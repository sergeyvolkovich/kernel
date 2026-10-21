# rust-l4: IOMMU — DMA- и IRQ-ремаппинг (Intel VT-d + AMD-Vi)

Полный стек изоляции устройств: парсинг ACPI (DMAR у Intel, IVRS у
AMD), домены изоляции, second-stage таблицы страниц (SSPT/v1),
инвалидации (QI у Intel, командный буфер у AMD), ремаппинг прерываний
(IRTE/IntTab), мульти-IOMMU и 2 МиБ-листья. Ядро поднимает подсистему
САМО до release_aps; пользователи работают через сискол-группу 0x80
(гейт — capability IommuAdmin).

Форматы таблиц и карты регистров — готовые no_std-крейты
[`intel-iommu`]/[`amd-iommu`] из git-зависимости
`sergeyvolkovich/iommu-rs`; MMIO, последовательности включения и
инвалидации, пулы кадров — наши драйверы (`backend/vtd.rs`,
`backend/amd.rs`, общий слой `backend/iommu.rs`).

Оглавление:

1. [Агрегатор и модель](#1-агрегатор-и-модель)
2. [Сисколы (группа 0x80)](#2-сисколы-группа-0x80)
3. [Intel VT-d](#3-intel-vt-d)
4. [AMD-Vi](#4-amd-vi)
5. [IRQ-ремаппинг: MSI и IOAPIC](#5-irq-ремаппинг-msi-и-ioapic)
6. [Мульти-IOMMU](#6-мульти-iommu)
7. [2 МиБ-страницы](#7-2-миб-страницы)
8. [Ограничения и курьёзы QEMU](#8-ограничения-и-курьёзы-qemu)

---

## 1. Агрегатор и модель

Оба драйвера исполняют одни контракты: HAL-трейты
`ANIOMMUInterface` (агностик) / `LIOMMUInterface` (платформенный) +
`IommuService` для сисколов. Сервис ставит **агрегатор**: индекс 0 —
Intel (если готов), следующий — AMD; обе части живут в системе
одновременно, ENUM-счётчик честный.

Модель изоляции — на каждый ATTACH: **домен изоляции** (DomainID у
AMD, context + SSPT-домен у Intel), device table указывает на таблицы
домена; права (R/W) задаются в листовых PTE — DTE-права AND-ятся с
листовыми. IOVA-диспетчеризация — вызывающего (L4-подобный ABI: пользователь
сам выбирает IOVA, ядро мапит IOVA→физика в таблицы домена).

Память таблиц — из ядрового пула LLfree (крупные буферы — классы
порядков, contiguous; zero-страницы и zero_huge 2 МиБ — общие хелперы
агрегатора).

## 2. Сисколы (группа 0x80)

ABI (v0.6, расширения — только новыми битами/номерами):

| № | Сискол | ABI | Прим. |
|---|--------|-----|-------|
| 0x80 | IOMMU_ENUM | `0xFFFF_FFFF` → число контроллеров; иначе `arg1=ctrl, arg2=0` → флаги, `arg2=1` → версия | флаги: bit0 `agaw48`, bit1 `queued_inval`, bit2 `pass_through`, bit3 `include_all`, bit4 `irq_remap` (v0.8), bit5 `large_pages` (v0.8), `mgaw<<8` |
| 0x81 | IOMMU_ATTACH | ctrl, bus, device, function | → DeviceId (идемпотентно); BDF вне coverage — `-ENODEV` |
| 0x82 | IOMMU_MAP | ctrl, DeviceId, iova, phys, `pages\|(prot<<32)` | prot: bit0 READ, bit1 WRITE; 2 МиБ-выровненные диапазоны кратные 512 стр → huge-лист; повтор — `-EEXIST` |
| 0x83 | IOMMU_UNMAP | ctrl, DeviceId, iova, pages | ТОЧНОЕ совпадение с MAP; частичное — `-EINVAL` |
| 0x84 | IOMMU_DETACH | ctrl, DeviceId | контекст гасится, таблицы домена — в пул |
| 0x85 | IOMMU_IRQ_MAP | ctrl, DeviceId, vector (0x10..0xFE), APIC-dest, flags | → handle = индекс IRTE; flags: bit0 level-triggered, bit1 logical DM |
| 0x86 | IOMMU_IRQ_UNMAP | ctrl, DeviceId, handle | погасить IRTE |

Пространство имён DeviceId — HAL-неймспейсит контроллер:
`(контроллер << 20) | локальный id` — операции знают свою единицу;
публичный ABI не менялся (ctrl передавался явно с v0.6).

Право: вся группа гейтована capability **IommuAdmin** (kind=5, v0.9):
выдаётся ядром доверенным задачам (kinit — init), дети не получают и
не передают. До v0.9 ЛЮБОЙ домен мог репрограммировать IOMMU.

## 3. Intel VT-d

Парсинг: RSDP → XSDT → DMAR → DRHD-единицы (каждая — свой инстанс
драйвера; INCLUDE_PCI_ALL — флаг coverage). Стек таблиц: root →
context → SSPT (second-stage page tables, 4 уровня, AGAW=48).

- **Включение**: root/context-таблицы + SSPT домена настраиваются ДО
  GCMD; каждый бит GCMD — ЗАПРОС на изменение: пишется `ENABLE|QIE`
  одной записью (баг-класс v0.6.1: запись ENABLE без QIE гасила
  очередь инвалидаций), обязательная проверка TES И QIES в GSTS.
- **Инвалидации** — Queued Invalidation (QI): INVALIDATE_IOTLB /
  INVALIDATE_CONTEXT / QiIec (global либо выборочный) +
  COMPLETION_WAIT (store-тег, поллинг, таймаут 100 мс) — каждая
  операция таблиц синхронизирована с железом до возврата сисколу.
- **IRQ-ремаппинг**: IRTA (256 IRTE = 4 КиБ, S=7, EIME=0 — ядро в
  xAPIC) → GCMD SIRTP (с ENABLE|QIE) → IEC-флеш (QiIec) → GCMD IRE;
  GSTS IRTPS/IRES обязательны. IRTE (remapped-формат):
  `P|vector|dest|SVT=11b VerifyFull + SQ=01b` — сверка bus+dev
  источника. Слоты: 1..15, 26..255 (0 — системный «нет handle»;
  0x10..0x25 — диапазон IOAPIC по спеке, резерв).

## 4. AMD-Vi

Парсинг: IVRS → IVHD-единицы: MMIO-база, сегмент id, покрытие из
device-записей (Select/Range/Alias; запись 01h «All» — весь сегмент;
Special/ACPI-HID пропускаются — не DMA-агенты).

- **Device Table** — 2 МиБ contiguous (LLfree order-9): 65536 DTE по
  32 байта, индекс = DeviceID = BDF. DTE: `V|TV|Mode=Level4|
  HPT-root|DomainID` + `IR|IW` (права DTE AND-ятся с листовыми PTE).
- **v1-таблицы** (4 уровня): каталог `PR|NextLevel<<9|PA`, лист
  `PR|IR|IW|PA`; NextLevel=0 — лист на любом уровне (крупные страницы
  v1 задаются уровнем).
- **Инвалидации — ТОЛЬКО командным буфером** (никаких «прямых»
  MMIO-записей): INVALIDATE_DEVTAB_ENTRY + INVALIDATE_IOMMU_PAGES
  (S=1, Address[51:12] = единицы → весь домен) + COMPLETION_WAIT
  (store-тег, поллинг, 100 мс).
- **Включение**: DTBA/CBBA/ELBA + головы/хвосты буферов, Control:
  сначала буферы, IOMMU_EN — ПОСЛЕДНИМ (спека); STATUS
  `CmdBufRun|EvtRun` — обязательная проверка (QEMU поднимает Run-бит
  одной записью).
- **Event log**: включён, дрейн при каждом sync — диагностика
  IO_PAGE_FAULT и illegal-command в консоль.

## 5. IRQ-ремаппинг: MSI и IOAPIC

Прерывания устройства проходят через таблицу ремаппинга контроллера:
источник (bus/dev/pin либо MSI-блок) сверяется, вектор/назначение
переписываются по IRTE. Ядро программирует IRTE и возвращает **handle**
— драйвер устройства кладёт его в MSI-адрес (Intel: SHV=0,
Address[15:0]=handle; AMD: индекс per-device IntTab).

**AMD-Vi**: per-device IRTE-таблица (v1, 128-битные записи,
IntTabLen=4 → 16 записей на страницу) из DTE: `IV=1 + IntTabPtr +
IntCtl=10b` (remap on); INVALIDATE_INTERRUPT_TABLE (05h) командным
буфером после записи/сброса IRTE; detach гасит таблицу в пул. Индексы
1..=15 (0 — резерв). У Intel — IRTA-таблица §3.

**IOAPIC-линии** (v0.11, `backend/ioapic.rs`): `enable_line` пишет
обычный RTE либо remapped-RTE:

- Intel: IRTE-слот `0x10 + pin`, remapped-RTE несёт handle+триггер —
  формат Linux `IR_IO_APIC_route_entry` (совместимо с QEMU);
- AMD-Vi: обычный RTE, ремап через IntTab IOAPIC-устройства,
  IRTE-индекс = вектор.

Честная граница (v0.8, сохранена): включение IR (IRTA/SIRTP/IEC/IRE у
Intel, IntCtl/DTE у AMD) валидировано эмулятором (`intremap=on`:
attach с IR-DTE и программирование IRTE проходят, event log чист);
ДОСТАВКА remapped-MSI требует драйвера устройства, поднимающего MSI —
в QEMU-прогоне MSI-трафика нет.

## 6. Мульти-IOMMU

Драйверы хранят ВСЕ единицы (Vec<инстанс>): Intel — каждый DRHD,
AMD — каждый IVHD с уникальной MMIO-базой (дедуп: QEMU кладёт типы
10h+11h ОДНОЙ единицы). IommuService маршрутизирует по сквозному
индексу: сперва все Intel (порядок DMAR), затем все AMD (порядок
IVRS). ATTACH требует BDF в coverage контроллера (scope DRHD /
device-записи IVHD), иначе `-ENODEV`.

## 7. 2 МиБ-страницы

- **Intel**: CAP.SSLPS bit0 → SS-PDE huge-лист (бит PS = 0x80, физика
  51:21). Раскладка map — детерминированный проход: 2 МиБ-выровненный
  кусок ≥ 512 стр → один PDE, остальное — 4К PTE; unmap/protect
  повторяют ту же геометрию (зеркала таблиц не храним); `sspt_free`
  различает huge-лист (не таблица — физика не наша).
- **AMD-Vi**: v1-лист уровня 2 (NextLevel=0 — размер задаётся
  уровнем); `pt_free` различает листы на любом уровне.

Багфикс v0.8 (важно): `amd: pt_free/sspt_free` освобождали
отображённую физику — лист уровня 2 был неотличим от каталога при
обходе (Intel — бит PS, AMD — NextLevel=0); без фикса detach отдал бы
чужую физику в пул (коррупция). UNMAP-политика — точное совпадение
(iova, count) с MAP; v0.7-хак с фантомным хвостом удалён, честный
`-EINVAL` на частичное снятие.

## 8. Ограничения и курьёзы QEMU

- IVMD-unity-диапазоны не обрабатываются; DomainID < 256 (QEMU: q1
  bit8 DTE — reserved).
- Таблицы — в физике < 4 GiB (покрытие physmap head.S; QEMU-масштаб).
- Частичный unmap с расщеплением huge — не реализован (точное
  совпадение, `-EINVAL`).
- Доставка remapped-MSI — драйвер устройства (MSI capability) вне
  ядра; IOMMU лишь даёт handle.
- Курьёзы эмулятора (не касаются корректности): MMIO-хвост event log
  QEMU не двигает (дрейн пуст на эмуляторе, работает на железе);
  `devtab_len` считается с багом (записей n+128 вместо (n+1)·128) —
  наш size-код 511 = 2 МиБ вне досягания.
- Демо-устройство: `00:1f.2` — ICH9 AHCI q35 (есть на шине, попадает
  и в Select-записи IVHD, и под INCLUDE_PCI_ALL Intel; прежнее
  00:01.0 root port в IVHD от QEMU отсутствует).
