# rust-l4: изменения по версиям (workspace)

## v0.7 — IOMMU: AMD-Vi (IVRS) + агрегатор Intel|AMD

### Сделано

**AMD-Vi — драйвер `backend/amd.rs` (крейт `amd-iommu` как форматы):**
- Парсинг IVRS/IVHD: MMIO-база IVHD, сегмент, покрытие из device-записей
  (Select/Range/Alias; запись 01h All = весь сегмент; Special/ACPI-HID
  пропускаются — не DMA-агенты).
- Device Table 2 МиБ (LLfree order-9, Class(1), contiguous): 65536 DTE по
  32 байта, индекс = DeviceID = BDF; DTE: V|TV|Mode=Level4|HPT-root|
  DomainID + IR|IW (права DTE AND-ятся с листовыми PTE — управление в PTE).
- v1-таблицы (4 уровня, NextLevel; каталог PR|NextLevel<<9|PA, лист
  PR|IR|IW|PA) — без больших страниц; домен изоляции на каждый attach
  (DomainID), IOVA-диспетчеризация вызывающего (L4-подобный ABI).
- Инвалидации — ТОЛЬКО командным буфером: INVALIDATE_DEVTAB_ENTRY +
  INVALIDATE_IOMMU_PAGES (S=1, Address[51:12]=единицы → весь домен) +
  COMPLETION_WAIT (store-тег + поллинг, таймаут 100 мс).
- Включение: DTBA/CBBA/ELBA + головы/хвосты, Control: буферы → IOMMU_EN
  (спека: enable последним), STATUS CmdBufRun|EvtRun — обязательная
  проверка после включения (QEMU поднимает Run-бит одной записью).
- Event log: включён, дрейн при каждом sync — IO_PAGE_FAULT и
  illegal-command диагностика. QEMU-курьёз: эмулятор не двигает MMIO-хвост
  event log — на QEMU дрейн пуст (на реальном железе работает).

**Агрегатор IOMMU (`backend/iommu.rs`):**
- Общие хелперы драйверов (Mmio/zero_page/free_page + zero_huge 2 МиБ)
  — vtd.rs переехал на них; сервис сисколов IOMMU_* теперь ставит
  агрегатор `IommuAgg`: индекс 0 — Intel (если готов), следующий — AMD;
  vtd::init_and_install → try_init (готовность — флаг, установка — общий).
- Оба драйвера исполняют одни контракты: ANIOMMUInterface/
  LIOMMUInterface (`hal::traits::iommu`) + IommuService (для агрегатора).

**Скрипты/QEMU:**
- run_qemu.sh: `QEMU_IOMMU=amd` → `-machine q35 -device amd-iommu`
  (раньше — только 1/intel); пути портируемы (WS от расположения
  скрипта), `-L` — на seabios-ромы user-space-префикса.
- build.sh: WS и префикс инструментов портируемы (TOOLS=…, qemu-usr —
  то, что реально ставит fetch_qemu.sh).
- scripts/boot_cfg.xml: добавлен cmdline `meltdown=allow` (обязателен
  под QEMU/TCG — без RDCL_NO; см. эталонный boot/boot_cfg.xml).

**Демо init:** ATTACH(00:1f.2) — встроенный ICH9 AHCI q35: устройство
реально есть на шине, попадает и в Select-записи IVHD (QEMU генерирует
их для каждого PCI-устройства шины 0), и под INCLUDE_PCI_ALL Intel;
прежнее 00:01.0 (root port) в IVHD от QEMU отсутствует.

### Исправленные баги
1. **amd-iommu (крейт): IVRS BLOCKS_OFFSET 44 → 48** — по спеке блоки
   начинаются после header 36 + IVInfo 4 + reserved 8 (Linux:
   IVRS_HEADER_LENGTH=48, QEMU пишет 4+8); со старым смещением итератор
   блоков натыкался на нули и останавливался — драйвер сообщал
   «IVRS without IVHD units». Фикс в репозитории iommu-rs (патч в
   серии); после его применения: `cargo update -p amd-iommu`.
2. **scripts/boot_cfg.xml без cmdline** — под QEMU/TCG (без RDCL_NO)
   kmain честно паниковал; эталонный boot/boot_cfg.xml флаг содержит.
3. **run_qemu.sh → boot/esp.img**, который build.sh не создаёт (выход —
   target/esp.img); префикс `qroot` не существует (fetch_qemu.sh
   распаковывает `qemu-usr`); жёсткие `/home/z/my-project/...` пути
   ломали свежие клоны — скрипты портируемы.

### Известные ограничения (задокументировано)
- IRQ-ремаппинг не реализован у обоих вендоров: Intel — запуск с
  `intremap=off`; DTE.IV=0 у AMD (IRQ идут напрямую).
- Мульти-IOMMU не поддержан (один IVHD/DRHD; v0.8+); IVMD-unity-диапазоны
  не обрабатываются; DomainID < 256 (QEMU: q1 bit8 DTE — reserved).
- Курьёзы QEMU: хвост event log не двигается, devtab_len в эмуляторе
  считается с багом (записей n+128 вместо (n+1)·128) — нас не
  касается: lookup DTE в QEMU без границ (наш size code 511 = 2 МиБ).

### Числа
- 139 тестов зелёные (kernel 125 + bootcfg 9 + boot_info 5), rustfmt
  применён; iommu-rs: 51 unit + 17 doctests зелёные после фикса.
- QEMU end-to-end зелёный в трёх конфигурациях: SMP=2 без IOMMU;
  intel-iommu (SMP=2); amd-iommu (SMP=2) — ENUM → ATTACH(00:1f.2) →
  MAP → повторный MAP (EEXIST) → UNMAP → DETACH + SMP-стресс
  (инкременты сходятся с ожидаемыми, lost updates = 0), exit 0.

## v0.6 — полноценный SMP + IOMMU (Intel VT-d)

### Сделано

**SMP (симметричная многопроцессорность):**
- Топология из MADT (`smp::bring_up`): RSDP -> XSDT/RSDT -> APIC-таблица,
  слоты CPU не уплотняются (cpu_id = индекс всех per-CPU массивов).
- SIPI-запуск AP: трамплин real->protected->long (position-fixed блоб на
  0x8000, почтовый ящик 0x8F00+), INIT-SIPI-SIPI + поллинг MAGIC_OK.
- per-CPU состояние: GDT/TSS/IDT/MSR/FPU + LAPIC на каждом AP
  (`ap_entry64`), GS-блоки, ядровые стеки 16K на AP.
- Модель синхронизации — big kernel lock (`klock.rs`): пользователь
  исполняется на всех CPU параллельно, входы в ядро сериализованы;
  планировщик — глобальная очередь готовности + per-CPU
  квант/флаг перепланировки (GS).
- resched-IPI (VEC 0x21, чистый asm-обработчик: gs:NEED_RESCHED + EOI),
  TLB shootdown IPI (VEC 0x22, битмап ACK), halt-IPI паники (VEC 0x23).
- Release-протокол: APы паркуются до окончания kinit
  (`X86Platform::run` -> `release_aps`).
- Демо в init: S3 SMP-стресс — поток на CPU, разделяемый счётчик,
  yield-миграции; гистограмма «на каких CPU исполнялся».

**IOMMU (Intel VT-d):**
- Парсинг DMAR (`find_table` -> `DmarTable` -> DRHD), драйвер
  `backend/vtd.rs`: root/context-таблицы, домены, SSPT (4 уровня,
  AGAW48), queued invalidations, включение DMA-ремаппинга.
- Сервис сисколов IOMMU_* (группа 0x80): ENUM/ATTACH/MAP/UNMAP/DETACH
  поверх `IommuService`; установка платформой в `run()`.
- Демо в init: S2 IOMMU smoke — ENUM -> ATTACH(00:01.0) ->
  MAP(2 стр RW) -> повторный MAP (EEXIST) -> UNMAP -> DETACH.

### Исправленные баги

1. **ICR shorthand перепутаны** (`lapic.rs`): код использовал
   `0b10 << 18` для «всем кроме себя», а по спеке (SDM Vol.3 10.6)
   `0b10` = *all including self*, `0b11` = *all excluding self*.
   Сам-IPI отправителю становился pending на IF=0-участках, AP не
   просыпался из парковки по resched-IPI. Константы поменяны местами.
2. **Связка VT-d <-> сисколы**: `init_and_install` помечал VTD0 готовым,
   но НЕ вызывал `install_iommu_service` — SERVICE=None, все IOMMU_*
   отвечали ENOSYS (init видел «no controllers»).
3. **GCMD.ENABLE гасил QIE** (`vtd.rs`): каждый бит GCMD — запрос на
   изменение; запись ENABLE без бита QIE означала «выключи QI» — QEMU
   останавливал обработку очереди инвалидаций (vtd_inv_qi_enable 0),
   первый ATTACH таймаутил (EIO). Теперь пишется `ENABLE|QIE`
   с проверкой TES **и** QIES.
4. ABI-выравнивание стека в ассемблерных точках входа
   (syscall/timer/fault/shootdown: якорь rbx + and rsp,-16);
   трамплин: `sub rsp, 8` перед входом в ядро.
5. Баг v0.5 в `syscall_c`: двойное продвижение rip (+2) при вытеснении —
   SMP-вытеснение проявляло как декод мусора (#PF на запись в RX).
6. `idle_loop` до установки glue (fatal-пути загрузки) — честное
   сообщение и сон вместо паники.

### Известные ограничения (задокументировано)

- QEMU 10.0 (MTTCG): доставка IPI остановленному vCPU ненадёжна —
  run-скрипт использует `-accel tcg,thread=single` (на KVM/железе
  проблемы нет).
- IRQ-ремаппинг VT-d не реализован (запуск с `intremap=off`);
  пер-процессорных очередей планировщика нет (одна глобальная под BKL);
  shrink фасадов не освобождает промежуточные таблицы (v0.6 без
  рефкаунтов страниц таблиц).

### Числа

- 139 тестов зелёные (kernel 125 + bootcfg 9 + boot_info 5), сборка
  workspace чистая; rustfmt применён.
- QEMU end-to-end зелёный в трёх конфигурациях:
  SMP=2 (без IOMMU), IOMMU+SMP=2, IOMMU+SMP=4 (3 воркера,
  0xc000 инкрементов == ожидаемым, lost updates = 0).
