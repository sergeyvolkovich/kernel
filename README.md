# rust-l4 — микроядро L4 на Rust (x86_64, UEFI)

Экспериментальное микроядро L4-архитектуры на Rust: домены защиты
(protection domains), потоки как единица планирования, capability-
пространства (cspace), синхронный IPC, песочница GTCB с rlimit-стилем
пределов, CPU-квоты с суб-тиковой точностью (TSC), SMP без Big Kernel
Lock (fine-grained + lock-free) и полный стек IOMMU (Intel VT-d и
AMD-Vi: DMA- и IRQ-ремаппинг, мульти-IOMMU, 2 МиБ-страницы).

v0.15: контракты HAL — отдельный крейт `kernel-hal` (не зависит ни
от одного крейта workspace — экспозиция архитектуры не проникает
между крейтами), деривация IoResource сужает ПОДИАПАЗОНЫ
(`CAP_MINT_RANGE` 0x27: бар устройства вместо всей физики, SCI-
линия вместо всего GSI-space — минимальные привилегии).

v0.14: в ядре НЕТ устройств — как в seL4. Перечисление ACPI (AML-
интерпретатор), PCI и драйверы — юзерспейс; ядро лишь медитирует
сырые ресурсы (физика/порты/линии) за IoResource-capability.
Юзерспейс-менеджер acpid читает DSDT/SSDT, перечисляет устройства,
подписывается на кнопку питания (SCI как L4-сигнал) и ВЫКЛЮЧАЕТ ПК
записью S5 в PM1a_CNT за capability.

Загрузка — UEFI (OVMF): самодостаточная заглушка `BOOTX64.EFI` со
встроенным образом ядра, конфигурация серверов в `boot_cfg.xml`.
Пользовательский мир — freestanding-серверы без libc: единственный API —
таблица сисколов (обёртки C-ABI — крейт `userlib`). Ядро сознательно не
содержит драйверов, файловых систем и libc: всё это — серверы
пользователя, общающиеся IPC (L4-философия).

```
OVMF -> BOOTX64.EFI (uefi_stub + встроенный kernel.bin)
     -> boot_cfg.xml (список серверов, cmdline ядра, boot_state)
     -> ExitBootServices -> head.S -> kmain -> startup::kinit
     -> elfload: сервер [0] (init) парсится, мапится, стартует
     -> планировщик: init — root-сервер (спавнит домены, владеет IommuAdmin)
```

## Содержание

- [Возможности](#возможности)
- [Архитектура в двух словах](#архитектура-в-двух-словах)
- [Состав репозитория](#состав-репозитория)
- [Требования](#требования)
- [Сборка](#сборка)
- [Запуск в QEMU](#запуск-в-qemu)
- [Демонстрация (что вы увидите)](#демонстрация-что-вы-увидите)
- [Тесты](#тесты)
- [Документация](#документация)
- [История версий](#история-версий)
- [Известные ограничения](#известные-ограничения)

## Возможности

| Подсистема | Что умеет |
|------------|-----------|
| **L4-ядро** | Домены (cspace + адресное пространство), потоки, приоритеты, конечный автомат состояний, exit-протокол (код/исключение/kill) |
| **Capability** | Моделирование прав хендлами в cspace: mint/send/revoke/delete, деривация, отзыв поддерева, generation-защита от висячих ссылок |
| **IPC** | Endpoint'ы (строгий rendezvous или буфер), `ipc_call`, fast-path по глобальному ThreadId, open receive, mailbox, однословные signal |
| **SHM / io_uring** | Разделяемые регионы с SQ/CQ-кольцами и doorbell-endpoint'ом |
| **Синхронизация SMP** | БЕЗ Big Kernel Lock: KSpin/KRwLock с IF-дисциплиной, per-gate RawGate, ранги захвата, lock-free MPMC-кольцо готовности (Вьюков), per-CPU кэш контекстов |
| **Планировщик** | SMP, RR-кванты, ленивый deschedule, resched-IPI, троттлинг доменов по CPU-квоте, вытеснение LAPIC TSC-deadline (суб-тик, фолбэк — периодический тик) |
| **Песочница GTCB** | rlimit-пределы в TCB: страницы/потоки/endpoint'ы/SHM/capability/приоритет/may_spawn/CPU-квота; семантика трещотки (только ужесточение); аудит `[kernel: sandbox]` |
| **Спавн доменов** | `TASK_SPAWN_IMAGE`: образ готовит юзерспейс-родитель (ядро — только указатели); PIE-образы (R_X86_64_RELATIVE, крейт `pie`), ET_EXEC-легаси как StaticFixed |
| **Сырые ресурсы + IRQ** | Устройств в ядре НЕТ (v0.14): перечисление ACPI/AML/PCI и драйверы — юзерспейс (acpid); ядро медитирует диапазоны за IoResource-cap: `MMIO_MAP` (физика), `IOP_IN/OUT` (порты, исполнение в ядре, IOPL=0), `IRQ_ATTACH` по Irq-cap (IOAPIC: линия — L4-signal без переключения контекста); `CAP_MINT_RANGE` (v0.15) — сужение поддиапазонов при деривации |
| **Изоляция крейтов (v0.15)** | HAL-контракты — отдельный крейт `kernel-hal` без зависимостей на workspace: ядро/бекенд видят контракты, контрактный слой не видит никого (граница проверяется cargo); `cargo build -p kernel-hal` — автономный гейт |
| **IOMMU** | Intel VT-d (DMAR/DRHD, QI-инвалидации) и AMD-Vi (IVRS/IVHD, командный буфер): DMA-ремаппинг, IRQ-ремаппинг (IRTE/IntTab), мульти-IOMMU, 2 МиБ-листья |
| **Загрузка** | UEFI-заглушка с динамическим размещением ядра, boot_cfg.xml, argv-протокол, SIPI-bring-up AP |
| **Юзерспейс** | `userlib` (C-ABI `_start` + `l4_*` для C и Rust), эталонные серверы: `init` (Rust) и `capp` (C) |

## Архитектура в двух словах

Слои строго разделены (политика не смешивается с механикой):

```
boot_cfg.xml   uefi_stub          пользователи (init, rogue, capp...)
     |   ESP    |  <- syscall ABI (rax/rdi/rsi/rdx/r10/r8/r9)
     v          v        ^
startup (kinit) --------->|     arch-НЕЗАВИСИМАЯ политика запуска
  | Platform / KernelGlue |     (пулы, GCTL, elfload, диспетчеризация)
  v                       |
kernel (pkg_generic_interface)   менеджеры: задачи, capability, память,
  |  GCTL, HAL-трейты            IPC, SHM, устройства, syscall-таблица
  v
backend (x86_64)                  исполнение контрактов: LAPIC, IOAPIC,
  |                               планировщик, VT-d/AMD-Vi, SMP/IPI, гейт
  v
arch + x86_64 (крейты)            механика ISA: per-CPU (GS), COM1, константы
```

- **`startup`** — единственная владелица ПОРЯДКА инициализации: два
  физических пула LLFree (ядро/пользователь), куча, slab, сборка `GCTL`,
  ELF-загрузка init, стартовое IPC, запуск диспетчеризации. Ни одного
  машинного адреса в коде.
- **`kernel` (GCTL)** — корневой фасад менеджеров; подсистемы связаны
  параметрами, не полями. HAL — набор трейтов (`MMAP`/`KMAP`/`ASID`/
  `Dma`/`Iommu`/`Irq`/`Cpu`): ядро не знает, на чём исполняется.
- **`backend`** — x86_64-исполнитель: high-half ядро (линк-база
  `0xFFFF_FFFF_8100_0000`), physmap 4 GiB, per-CPU блоки через GS,
  syscall-гейт (MSR), контекстное переключение (asm), LAPIC/IOAPIC,
  IOMMU-драйверы обоих вендоров.
- **Синхронизация** (v0.12+): общий лок запрещён — каждая подсистема под
  своим коротким локом, готовность планировщика lock-free, ранги захвата
  `GATE > CLAIM > TCB > SCHED` исключают ABBA; IF-дисциплина делает
  самодедлок IRQ-хендлера физически невозможным.
- **Планировщик** (v0.13): контекст потока — per-CPU слот (обычный сискол
  не трогает глобальное состояние вообще), парки — zero-copy передача
  между CPU через глобальную карту, вытеснение — one-shot LAPIC
  TSC-deadline на `min(квант, остаток бюджета домена, остаток периода)`.

Подробности: [docs/architecture.md](docs/architecture.md).

## Состав репозитория

```
crates/
  boot_info/    ABI страница BootInfo (заглушка -> ядро): память, модули, RSDP
  bootcfg/      mini-XML парсер boot_cfg.xml (+ host-тесты)
  kernel-hal/   HAL-КОНТРАКТЫ (v0.15): типы (PhysAddr, Bdf, DevicePath)
                + трейты ASID/KMAP/MMAP/DMA/IOMMU/IRQ/IOPORT — не зависит
                ни от одного крейта workspace (изоляция архитектуры)
  kernel/       ядро-крейт pkg_generic_interface: GCTL, менеджеры,
                сисколы, sync-примитивы + IrqRouter (hal = re-export
                kernel-hal); 136 host-тестов
  arch/         механика x86_64: per-CPU (GS), COM1 16550, константы ABI
  backend/      платформенный крейт: гейт, планировщик, SMP, LAPIC/IOAPIC,
                память, VT-d (vtd.rs), AMD-Vi (amd.rs), IOMMU-агрегатор;
                реализует контракты kernel-hal (единственное место
                экспозиции архитектуры)
  startup/      kinit: политика запуска (Platform/KernelGlue), elfload, пулы
  uefi_stub/    BOOTX64.EFI: boot_cfg, модули, ExitBootServices, прыжок в ядро
  init/         первый сервер (Rust, сырые сисколы): топология, IOMMU smoke,
                SMP-стресс, песочница (спавн rogue + вердикт), спавн acpid
                (IoResource-гранты + argv-транзит rsdp=; Irq-грант acpid —
                суженный 9..10 через CAP_MINT_RANGE, v0.15)
  rogue/        дочерний образ песочницы (static-PIE, ET_DYN + RELA)
  acpid/        ACPI-менеджер ЮЗЕРСПЕЙСА (v0.14, static-PIE): AML-
                интерпретатор (крейт acpi) вне ядра, namespace-walk,
                кнопка питания (SCI) и выключение ПК (S5, PM1a_CNT)
  pie/          юзерспейс-парсер PIE-образов: PT_LOAD W^X, R_X86_64_RELATIVE
  userlib/      C-ABI: _start + l4_* (статическая бибилиотека, заголовок l4.h;
                l4_cap_mint_range — v0.15)
scripts/        build.sh (полная цепочка), run_qemu.sh (OVMF+q35),
                fetch_qemu.sh (user-space префикс QEMU/OVMF/mtools), esp_mbr.py
boot/           эталонный boot_cfg.xml
examples/       capp.c — сервер на чистом C
docs/           документация (см. ниже)
CHANGES.md      история версий v0.6..v0.15 (подробно)
```

## Требования

- **Rust nightly** (`rust-toolchain.toml` закрепляет канал и компоненты),
  цели `x86_64-unknown-none` (ядро/юзерспейс) и `x86_64-unknown-uefi`
  (заглушка); `cargo install cargo-binutils` (rust-objcopy для strip).
- **QEMU + OVMF + mtools** в user-space-префиксе: `bash
  scripts/fetch_qemu.sh` скачивает deb-пакеты и распаковывает их в
  `$TOOLS/qemu-usr` (root не нужен). Префикс задаётся переменной
  `TOOLS` (по умолчанию `/home/z/my-project/tools`).
- **gcc** — для C-сервера `capp` (шаг build.sh; заменяется через `CC=`).
- **readelf** (binutils) — контроль ET_DYN у PIE-образа rogue.
- Зависимости IOMMU-форматов — из git: `sergeyvolkovich/iommu-rs`
  (крейты `intel-iommu`/`amd-iommu`, no_std; MMIO/последовательности
  включения — наш бекенд).

## Сборка

```bash
bash scripts/fetch_qemu.sh          # один раз: QEMU/OVMF/mtools в $TOOLS
bash scripts/build.sh               # ядро -> userlib -> rogue -> init -> заглушка -> ESP
```

`build.sh` собирает всю цепочку: ядро (release обязателен — debug ~14 МиБ
не влезает в геометрию загрузки), стрипает образ в `uefi_stub/kernel.bin`,
собирает `userlib`, `rogue` (static-PIE: `--pie` + `relocation-model=pic`,
с контролем `readelf -h`: ET_DYN обязателен), `init` (вшивает образ rogue
байтами), `uefi_stub` и C-сервер `capp`, затем склеивает FAT/MBR-образ
`target/esp.img` (mtools). Переменные окружения:

| Переменная | Значение | По умолчанию |
|------------|----------|--------------|
| `TOOLS` | префикс qemu-usr (QEMU/OVMF/mtools) | `/home/z/my-project/tools` |
| `BOOT_CFG` | конфигурация серверов | `scripts/boot_cfg.xml` |
| `ROGUE_PIE` | `1` — static-PIE rogue; пусто — легаси ET_EXEC (отладка загрузчика) | `1` |
| `CC` | компилятор C-сервера | `gcc` |

C-демо вместо Rust-ини: `BOOT_CFG=scripts/boot_cfg_c.xml bash scripts/build.sh`.

## Запуск в QEMU

```bash
QEMU_IOMMU=0    bash scripts/run_qemu.sh    # без IOMMU (baseline)
QEMU_IOMMU=1    bash scripts/run_qemu.sh    # Intel VT-d, intremap=on
QEMU_IOMMU=amd  bash scripts/run_qemu.sh    # AMD-Vi,  intremap=on
```

| Переменная | Смысл | По умолчанию |
|------------|-------|--------------|
| `QEMU_SMP` | число vCPU | `2` |
| `RAM` | память, МиБ | `512` |
| `QEMU_IOMMU` | `0` / `1` (Intel) / `amd` | `0` |
| `QEMU_INTREMAP` | IRQ-ремаппинг эмулятора | `1` |
| `QEMU_CPU` | модель CPU | `Cascadelake-Server` |
| `QEMU_TIMEOUT` | таймаут прогона, с | `120` |

Детали стенда: q35, OVMF (pflash), serial -> stdout, `-display none`.
TCG принудительно однопоточный (`-accel tcg,thread=single`): в сборке
QEMU 10.x (MTTCG) доставка IPI остановленному vCPU ненадёжна; на
KVM/железе ограничения нет. **`EXIT=124` — норма**: после успешного
демо ядро холдит машину (`[kernel] all user threads gone — halting`),
таймаут снимает процесс.

Под QEMU/TCG cmdline ядра обязан содержать `meltdown=allow` (эмулятор
не сообщает `ARCH_CAPABILITIES.RDCL_NO`; на реальном железе без KPTI
ядро честно откажется грузиться — не ставьте флаг). TSC-deadline режим
таймера (v0.13) в QEMU/TCG не эмулируется — там живёт периодический
фолбэк; точность квот проверяется на KVM/железе, заряд циклами работает
в обоих режимах.

## Демонстрация (что вы увидите)

Прогон init (сервер [0]) в хронологии консоли:

1. **Загрузка**: OVMF, заглушка, kinit: пулы LLFree, SMP bring-up
   (тополология из MADT, SIPI), `timer mode: tsc-deadline` либо
   `periodic fallback` — по CPUID.
2. **S1. Топология** init: `cpu_count` из SELF_INFO.
3. **S2. IOMMU smoke**: ENUM (флаги `irq_remap`, `large_pages`) →
   ATTACH(`00:1f.2` — ICH9 AHCI q35) → MAP → повторный MAP (`-EEXIST`) →
   huge MAP (один 2 МиБ-лист) → UNMAP → IRQ_MAP/IRQ_UNMAP → DETACH.
4. **S3. SMP-стресс**: поток на CPU, разделяемый счётчик, yield-миграции;
   инкременты сходятся с ожидаемыми (lost updates = 0), гистограмма CPU.
5. **S4. Песочница + PIE**: init спавнит rogue на ДВУХ базах
   (`0x40000000`/`0x50000000`) — накат R_X86_64_RELATIVE с контрольным
   readback, сверка PIE_PTR; ping-pong 3/3; квота CPU трипается
   посередине (`cpu quota: domain ... throttled (charged N cycles,
   limit 3 ticks per period)`); 9 атак rogue (флуд памятью/потоками/
   эндпоинтами/SHM, эскалация prio, kill родителя, спавн, захват IOMMU,
   разрушение SHM родителя, проталкивание капов) — каждая блокирована,
   аудит `[kernel: sandbox]`; exit 0x5A, вердикты `sandbox HELD` +
   `cpu quota HELD`.
6. **S5. Внешняя линия**: IoResource(Irq)-cap → IRQ_ATTACH(GSI 4):
   реальное прерывание COM1 прибывает L4-сигналом (`signal word = 4`),
   ACK/DETACH — вердикт полного контура IOAPIC→LAPIC→endpoint.
7. **S6. acpid — ACPI в юзерспейсе, выключение ПК**: init спавнит acpid
   (argv `rsdp=0x…` + три IoResource-гранта через CAP_MINT);
   таблицы через MMIO_MAP (refcount-кэш), DSDT/SSDT в namespace,
   перечисление устройств (_HID/_STA/_CRS) ЦЕЛИКОМ в юзерспейсе
   (11 устройств: LNKA..D, FWCF, GPE0, PHPR, PRES, MOU_), FADT:
   PM1a_EVT/CNT, SCI; `\_S5_` → SLP_TYP; кнопка питания подписана
   (IRQ_ATTACH(SCI=9) + PWRBTN_EN); запись S5|SLP_EN в PM1a_CNT за
   IoPort-cap — **VM выключается из юзерспейса: QEMU завершается с
   кодом 0** (без таймаута).

## Тесты

```bash
cargo test                       # host-портящиеся крейты (default-members):
                                 # kernel (131), bootcfg, boot_info, pie
```

Ядро-крейт гоняет тесты на std (host-хуки аллокатора); непортящиеся
крейты (backend/startup/uefi_stub/init/...) проверяются сборкой образа
(`build.sh`) и QEMU-прогонами (`run_qemu.sh` в трёх конфигурациях IOMMU).

## Документация

| Документ | Содержание |
|----------|------------|
| [docs/architecture.md](docs/architecture.md) | Слои, загрузка, память, SMP, планировщик, синхронизация, IPC, прерывания |
| [docs/gtcb-sandbox.md](docs/gtcb-sandbox.md) | Песочница GTCB: пределы, трещотка, права, спавн (включая PIE), смерть домена |
| [docs/cpu-quotas.md](docs/cpu-quotas.md) | CPU-квоты: заряд циклами TSC, период, троттлинг, TSC-deadline, ABI |
| [docs/iommu.md](docs/iommu.md) | VT-d + AMD-Vi: включение, таблицы, IRQ-ремаппинг, мульти-IOMMU, huge-страницы |
| [docs/apps-and-servers.md](docs/apps-and-servers.md) | Юзерспейс: стартовый протокол L4, полная syscall-таблица, userlib, серверы C/Rust |
| [CHANGES.md](CHANGES.md) | Подробная история версий |

## История версий

| Версия | Веха |
|--------|------|
| v0.3–v0.4 | L4-ядро крейта: домены/потоки, capability, IPC, плотная таблица сисколов |
| v0.5 | Загрузочная цепочка UEFI (заглушка + head.S + kinit + elfload) |
| v0.6 | Полноценный SMP (MADT/SIPI/IPI, per-CPU) + Intel VT-d (DMAR, QI, SSPT) |
| v0.7 | AMD-Vi (IVRS/IVHD, Device Table, командный буфер) + агрегатор Intel&#124;AMD |
| v0.8 | IRQ-ремаппинг (IRTE/IntTab), мульти-IOMMU, 2 МиБ-листья; userlib (C-ABI) |
| v0.9 | Песочница GTCB (пределы+трещотка), спавн по готовому образу, харднинг прав |
| v0.10 | CPU-квоты GTCB: троттлинг доменов, ленивые счётчики потоков |
| v0.11 | PIE-спавн (крейт pie, rogue static-PIE) + IOAPIC-драйвер (линии как L4-сигналы) |
| v0.12 | Демонтаж Big Kernel Lock: fine-grained локи, lock-free планировщик, IF-дисциплина |
| v0.13 | Точность квот (заряд циклами TSC, TSC-deadline), per-CPU кэш контекстов, демонтаж легаси task-level enqueue |
| v0.14 | Устройств в ядре НЕТ: AML/перечисление → юзерспейс (acpid), IoResource-capability (MMIO/порты/GSI), выключение ПК из юзерспейса (S5) |
| v0.15 | kernel-hal: HAL-контракты — отдельный крейт без зависимостей на workspace (изоляция архитектуры силами cargo); CAP_MINT_RANGE 0x27 — сужение поддиапазонов IoResource при деривации; шестой аргумент сисколл-ABI (a6) |

## Известные ограничения

- **Один init-сервер** грузится загрузочной цепочкой; остальные домены
  спавнит он (`TASK_SPAWN_IMAGE`). exec-сискола нет — это философия
  проекта (spawn-сервер в юзерспейсе).
- **FPU между потоками**: контекст сохраняется на каждом переключении
  (eager fxsave/fxrstor), но SSE-обработчики в ядре не используются;
  AVX не поддерживается.
- **IOMMU**: таблицы размещаются в физике < 4 GiB (physmap head.S — 4
  GiB; QEMU-масштаб); IVMD-unity-диапазоны не обрабатываются; частичный
  unmap с расщеплением huge-листа не реализован (UNMAP — точное
  совпадение с MAP); доставка remapped-MSI требует драйвера устройства,
  поднимающего MSI.
- **Периодический fallback** таймера в QEMU/TCG (TSC-deadline не
  эмулируется); MTTCG-сборки QEMU 10.x требуют `-accel tcg,thread=single`
  (IPI в остановленный vCPU).
- **Квант пробуждённых**: пробуждённый IPC-поток домена за пределом
  квоты отрабатывает до одного вытеснения (документированное окно
  перерасхода; спиннеры паркуются немедленно).
- **Устройства (v0.14/v0.15)**: в ядре НЕТ перечисления — только сырые
  ресурсы за IoResource-cap. acpid перечисляет ACPI/AML; PCI-драйверы
  (pcid через IOP CF8/CFC — roadmap, прямое применение суженных
  грантов CAP_MINT_RANGE); песочницы IoResource не получают вовсе
  (сужение поддиапазонов v0.15 — для доверенных менеджеров/драйверов).
- **Кнопка питания**: SCI подписан (IRQ_ATTACH + PWRBTN_EN; Irq-грант
  acpid сужен до GSI 9 — v0.15), но демо не «нажимает» её — после
  окна ожидания acpid выключает ПК сам (S5); интерактивное
  выключение через QEMU monitor — roadmap.
