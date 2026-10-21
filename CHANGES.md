# rust-l4: изменения по версиям (workspace)

# v0.15 — kernel-hal: контракты в отдельном крейте + сужение поддиапазонов IoResource (CAP_MINT_RANGE)

> Завершение запроса «экспозиция архитектуры не проникает между
> крейтами»: HAL-контракты покидают generic-ядро и становятся
> НЕЗАВИСИМЫМ крейтом kernel-hal — граница видна cargo при каждой
> сборке. Вторая половина: деривация IoResource умеет СУЖАТЬ
> поддиапазон (CAP_MINT_RANGE 0x27) — минимальные привилегии для
> драйверов: бар устройства, а не вся физика; SCI-линия, а не весь
> GSI-space. Ссылка: дизайн-документ kernel_v015_design.pdf (обложка
> Template 01, 10 стр.).

### Сделано

**kernel-hal — контрактный крейт (структурная изоляция):**
- Новый крейт `crates/kernel-hal` (пакет `kernel-hal`, lib
  `kernel_hal`): hal/types.rs (298 стр: PhysAddr, Bdf, DevicePath,
  IommuProt, DeviceInfo) + hal/traits/{asid,cpu,dma,iommu,ioport,irq,
  kmap,mmap} (1752 стр контрактов) — перенесены из
  pkg_generic_interface git-mv (история сохранена). Зависимости:
  bitflags/thiserror + ТИПЫ ОШИБОК контракта MMAP (llfree::Error,
  SlabError, AlignedBoxError — часть сигнатуры трейта) — ни одного
  крейта workspace: контрактный слой физически не видит ни ядро,
  ни бекенд (обратного ребра в Cargo.toml нет).
- IrqRouter (hal/irq.rs: GSI→endpoint) ОСТАЛСЯ в kernel — это
  механизм уровня ядра (сигнатуры содержат CapabilityManager/
  IpcManager/TcbManager); перенос сломал бы независимость крейта.
- Миграция БЕЗ переписывания 20 файлов ядра: kernel::hal реэкспортирует
  `kernel_hal::{types, traits}` (pub use) + локальный `pub mod irq` —
  пути crate::hal::types::*/crate::hal::traits::* в потребителях
  не менялись. backend и startup импортируют контракты НАПРЯМУЮ
  (`use kernel_hal::traits::…`): граница «контракт отдельно от нутра
  ядра» видна и в их исходниках, а не только в графе сборки.
- Автономный гейт: `cargo build -p kernel-hal` — контрактный слой
  обязан собираться без ядра (быстрая проверка «архитектура не
  протекла»). IommuError через границу крейта — non_exhaustive:
  syscall/iommu.rs получил wildcard-ветку (новый вариант больше не
  может сломать ABI сисколлов).
- Тесты ASID-контракта переехали вместе с файлами: kernel-hal 2
  (asid_pair/high_bit), ядро 129 + 7 новых (narrowing) = 136.

**Сужение поддиапазонов IoResource (решётка деривации):**
- `IoResourceKind::narrow(base, len)`: производная обязана лежать
  строго ВНУТРИ родительского диапазона той же разновидности.
  Инварианты (нарушение — None, отказ чистый): вложение (checked_add,
  без wrap-around), len > 0, совпадение вида (Mmio 64/64, IoPort —
  u16-границы, Irq — u32), транзитивность (сужать только внутрь
  суженного).
- `MintSpec.range: Option<(base, len)>` (UNCHANGED — прежняя
  семантика «клонировать целиком»); `CapabilityGate::derive` — теперь
  Result: `CapabilityError::RangeNotSubset` (новый вариант, enum
  получил PartialEq для тестов). Отказ БЕЗ создания CTE/узла дерева.
  Отзыв — прежний каскад дерева деривации: revoke родителя гасит
  суженное поддерево в чужих cspace.
- **CAP_MINT_RANGE (0x27)**: ABI arg1=src, arg2..3=TaskId(lo,hi),
  arg4=perms, arg5=new_base, arg6=new_len. ШЕСТОЙ аргумент ABI
  подключён впервые: SYSCALL_ARG_COUNT 6→7 — asm-стаб передавал
  r9/a6 всегда, гейт отбрасывал; теперь a6 в слоте 6, все прежние
  сисколлы читают arg(6)=0 — ABI-совместимость сохранена. badge не
  сужается (гейты 0x40 его не читают) — производная наследует
  родительский. Права получателя — как у CAP_MINT (свой домен ИЛИ
  TaskTCB + max_caps против флода).
- CAP_MINT (0x21) НЕ ИЗМЕНЁН (badge-путь, полный диапазон):
  перегрузка badge половинками диапазона отвергнута как
  неразличимая. userlib: l4_cap_mint_range + l4.h; l4_syscall6 уже
  несла a6.
- Демо минимальных привилегий в QEMU (S6): init выдаёт acpid Irq
  0..256 → **суженный 9..10** (SCI кнопки питания, FADT) через
  CAP_MINT_RANGE — «Irq grant NARROWED... GSI 9 only» в логе; полный
  контур сужения: CAP_MINT_RANGE → IRQ_ATTACH(SCI 9) → PWRBTN_EN →
  S5-выключение из юзерспейса. Mmio/IoPort-гранты acpid — как
  прежде (ему нужны все таблицы/порты).
- Host-тесты (7): успех+идентичность, отказы (наружу/пересечение/
  len=0/переполнение — без побочных эффектов), транзитивная цепочка,
  не-IoResource источник (диапазон запрошен у TaskTCB), границы
  IoPort (u16)/Irq (u32), revoke-каскад суженного дерева, фасадный
  путь.

### Верификация

- cargo fmt; cargo build -p kernel-hal (автономно); host-тесты:
  kernel 136 (129 + 7 narrowing) + kernel-hal 2 + bootcfg 9 +
  boot_info 8 + pie 5 — все зелёные.
- Полная сборка образа build.sh [1..6/6] (kernel, userlib, rogue,
  acpid ET_DYN, init, uefi_stub, capp, ESP) — зелёная.
- QEMU q35+OVMF SMP=2 (TCG single-thread): S1–S6 прежние зелёные,
  «Irq grant NARROWED via CAP_MINT_RANGE: GSI 9 only (v0.15)»,
  acpid: 53 узла namespace, 11 устройств, SCI line attached по
  суженной cap, S5 из юзерспейса — VM выключается сама.

### Roadmap (v0.16+)

- pcid: PCI-перечислитель в юзерспейсе через CF8/CFC за IoPort-cap
  (суженные гранты — прямое применение CAP_MINT_RANGE).
- Интерактивная кнопка питания (QEMU monitor `system_powerdown`).
- Проверка квот IPC-пробуждённых (enqueue-гейты).
- Частичный unmap huge-страниц; расширение дерева деривации — revocation
  волной по CPU.

# v0.14 — Устройств в ядре НЕТ: AML/перечисление вынесены в юзерспейс, сырые ресурсы за IoResource-capability, выключение ПК из юзерспейса (S5)

> Модель seL4: ядро не знает НИ ОДНОГО устройства. Перечисление (ACPI/
> AML/PCI) и драйверы — юзерспейс; ядро лишь медитирует СЫРЫЕ диапазоны
> (физика/порты/линии GSI) за capability. Кнопка питания и выключение
> ПК — юзерспейс-сервер acpid (AML-интерпретатор теперь ЗДЕСЬ: паника
> AML убивает менеджер, а не ядро).

### Сделано

**AML-интерпретатор удалён из ядра:**
- Крейт `acpi` (6.1.1, с `aml::Interpreter` — самая тяжёлая и риско-
  ванная часть ACPI) снят с зависимостей ядра: AML в образе ядра больше
  не существует. Ядро парсит только статические таблицы ДЛЯ СЕБЯ
  (MADT — SMP/IOAPIC в backend/smp.rs; DMAR/IVRS — iommu-rs) — как и
  прежде, вручную, slice-based, без acpi-крейта.
- Удалены (−4400 строк): `hal/device/acpi.rs` (AML-обходчик namespace,
  _HID/_STA/_CRS — 964 строки; на буте НИКОГДА не регистрировался —
  мёртвый груз с v0.4), `hal/device/pci.rs` (PCI-перечислитель, 969),
  `hal/device/claim.rs` (эксклюзивные локи устройств, 847),
  `hal/device/mod.rs` (DeviceManager: реестр + rescan + экспорт caps),
  `hal/device/traits.rs` (BusEnumerator/DiscoveredDevice),
  `syscall/device.rs` (DEVICE_INFO/ENUM/CLAIM/RELEASE/CLAIM_STATUS/
  MAP_REGION). DeviceReference-capability удалена; реестра устройств,
  rescan-семантики и hot-removal-уведомлений в ядре больше нет
  («горячее удаление» — политика юзерспейс-менеджера).

**IoResource — сырые аппаратные ресурсы за capability:**
- Новый вариант `ContainerACCCapability::IoResource { kind }`:
  `Mmio { base, len }` (физический диапазон), `IoPort { base, len }`
  (порты x86), `Irq { base, count }` (внешние линии GSI). Цель
  «бессмертна» (право на ДИАПАЗОН, не на объект ядра); выдаёт kinit
  корневому серверу, производные — CAP_MINT (полный диапазон;
  сужение поддиапазонов — roadmap). CAP_LIST/CAP_INFO: kinds 6/7/8,
  идентификация — [base, len|count].
- Стартовый грант kinit (модель seL4 root task): init получает ТРИ
  корневых IoResource — физика 0..4 GiB (таблицы прошивки, MMIO-баре),
  порты 0..64 KiB (PM-регистры, PCI config CF8/CFC), линии 0..256
  (весь GSI-space IOAPIC). Плюс ФАКТ прошивки в boot_state: `rsdp=0x…`
  (ядро передаёт ссылку на таблицы, интерпретация ACPI — юзерспейс).

**Новая ABI-группа 0x40 — сырые ресурсы (старые DEVICE_* удалены):**
- `MMIO_MAP` (0x41): Mmio-cap + байтовый офсет + страницы → виртуальный
  адрес БАЙТО-ТОЧНЫЙ (кадры внешние, снятие MEM_FREE). Замена
  DEVICE_MAP_REGION без реестра/claim: владение cap = право.
- `IOP_IN/IOP_OUT` (0x42/0x43): IoPort-cap + офсет + ширина (1|2|4) —
  исполняет in/out ЯДРО (IOPL пользовательских контекстов = 0: прямого
  доступа к портам из юзерспейса не существует) через платформенный
  сервис `IoPortOps` (hal-контракт, x86_64 — backend/ioport.rs).
  PCI config — те же CF8/CFC за cap: будущий pcid обойдётся без ядра.
- `IRQ_ATTACH` (0x46, ABI v0.14): право на GSI подтверждает
  IoResource(Irq)-cap (было: DeviceReference + принадлежность линии
  устройству из реестра). Флаги level/active_low — подсказка;
  MADT-ISO канонизация бекенда сильнее. IRQ_DETACH/IRQ_ACK — без
  изменений. IrqRouter переехал в `hal/irq.rs`, GSI-keyed, без
  DevicePath; detach_device/rescan-оркестрация удалены.

**acpid — ACPI-менеджер в юзерспейсе (новый крейт, static-PIE):**
- `acpi::Handler` поверх сисколов: `map_physical_region` — MMIO_MAP
  (байто-точный), refcount-кэш живых мапингов (acpi-крейт держит
  ПЕРЕКРЫВАЮЩИЕСЯ снапшоты одной физики: заголовок таблицы + полная
  таблица); `read/write_uN` — op-region SystemMemory; `read_io_*`/
  `write_io_*` — SystemIO (PM-регистры); PCI config — CF8/CFC;
  время — SYS_TIME; мьютексы AML — тривиальные (процесс однопоточен).
- Полный перечислитель namespace (порт бывшего ядрового acpi.rs):
  traverse → _HID/_CID (EisaId-расжатие)/_UID/_ADR/_STA/_CRS.
- Фиксированные события + выключение: FADT (PM1a_EVT/PM1a_CNT,
  sci_interrupt), `\_S5_` → SLP_TYPa; подписка на кнопку питания
  (EP_CREATE + IRQ_ATTACH(SCI=9) + PWRBTN_EN), ожидание L4-сигнала с
  таймаут-фолбэком; ВЫКЛЮЧЕНИЕ ПК из юзерспейса: IOP_OUT в PM1a_CNT
  значения SLP_TYPa<<10 | SLP_EN — QEMU завершает VM (exit 0).
- Куча: ленивый bump по регионам 1 МиБ (MEM_ALLOC order 8 — после
  бут-фрагментации пула непрерывные 2048-страничные пробеги не
  гарантированы), до 8 МиБ.

**init: S5 через Irq-cap + S6-спавн acpid:**
- S5 (внешние линии): IoResource(Irq) из CAP_LIST (kind 8) вместо
  DeviceReference — полный контур IOAPIC→LAPIC→endpoint как прежде.
- S6: спавн acpid (PIE-план, argv ["acpid", "rsdp=0x…"], гранты
  IoResource через CAP_MINT); парковка init с дедлайном диагностики.
- userlib: `l4_mmio_map/l4_iop_in/l4_iop_out` + `l4_irq_attach` нового
  ABI (аргументы 0x40-группы обновлены; l4.h синхронизирован; capp не
  использует старые DEVICE_* — совместимость C-ABI сохранена).

**Фасад памяти: многократные отображения одной физики (v0.14):**
- Ключ paddr-индекса записей — ПАРА (физическая база, виртуальная база);
  снята проверка дубликата по физике. Одна и та же физика может стоять
  в нескольких регионах (как frame в seL4) — это паттерн acpi-крейта
  (map заголовка + map полной таблицы одного адреса, оба живы).
  Снятие — по ТОЧНОЙ паре ключей; аудит-поиск по физике — линейный.

**Верификация:**
- Host: 131 тест ядра (+2 новых: перекрывающиеся external-мапинги
  одной физики; большой alloc_region через дефолтный класс), 151+ в
  workspace; rustfmt чисто.
- QEMU (SMP=2, TCG single-thread): полный прогон S1–S4 + S5 (реальная
  линия COM1 через Irq-cap: signal word = 4) + S6: acpid поднимает
  таблицы (rsdp→XSDT→DSDT/SSDT), 53 узла namespace, 11 устройств
  перечислены В ЮЗЕРСПЕЙСЕ (LNKA..D, FWCF, GPE0, PHPR, PRES, MOU_),
  PM1a_EVT=0xb000/PM1a_CNT=0xb004, SCI=9, SLP_TYPa=0, кнопка питания
  подписана (PWRBTN_EN), fallback-выключение S5|SLP_EN — QEMU ВЫХОДИТ
  (exit code 0, без таймаута: выключение из юзерспейса работает).

### Ограничения v0.14 / roadmap

- CAP_MINT копирует IoResource ЦЕЛИКОМ (badge-маска не сужает
  диапазон) — выдача поддиапазонов драйверам через отдельные типы
  caps или badge-политику — следующий шаг (сейчас производные в
  юзерспейс-менеджеры идут как копии корневых прав; песочницы IoResource
  не получают вовсе).
- Пользователь кнопки питания: строка демо не «жмёт» кнопку (нет
  monitor-планирования в run_qemu) — SCI подписан, событие ждалось 8 с,
  затем fallback self-S5. Интерактивное выключение (`system_powerdown`
  через QEMU monitor) — кандидат следующего шага.
- PCI-перечисление в юзерспейсе (pcid через IOP_IN/OUT CF8/CFC) и
  драйверы устройств — roadmap; kernel-hal (вынос HAL-контрактов в
  отдельный крейт — структурная гарантия «архитектура не протекает
  между крейтами») — следующий механический шаг.
# v0.13 — Точность CPU-квот (TSC) + per-CPU кэш контекстов + демонтаж легаси task-level enqueue

### Сделано

**Легаси task-level enqueue демонтирован (шум stale):**
- Единица планирования — ТОЛЬКО поток (L4); `TcbManager::create`/
  `set_state` больше не уведомляют планировщик на уровне ЗАДАЧ
  («легаси-модель платформ без потоков»). Прежде каждый спавн домена
  пушел UUID задачи в lock-free кольцо готовности: запись-призрак
  отсеивалась на pick (счётчик stale / шум в отчётах) и попутно
  рассылала resched-IPI ВСЕМ CPU. Хуки `enqueue`/`deschedule` —
  контракт ПОТОКОВ (`create_thread`/`thread_set_state`), как и было.
- Бекенд: временная bring-up-диагностика v0.12 удалена целиком
  (DBG_ENQ/POP/STALE/MARKFAIL/ENTER + once-печать «sched dbg» в
  idle + `rotate_current` «метод для диагностики»).

**Per-CPU кэш контекстов (демонтаж «карта под локом на каждом шаге»):**
- Горячий путь — сискол-вход: контекст текущего потока пишется в
  per-CPU СЛОТ (без локов и аллокаций; боксы рециклируются per-CPU
  пулом на 4). Обычный сискол без блока/вытеснения больше не трогает
  глобальное состояние вовсе (v0.12: KSpin + вставка в BTreeMap на
  КАЖДЫЙ сискол).
- Парки (IPC-block, suspend, preempt-rotate, троттл): контекст
  экспортируется слот -> глобальная карта ДО фиксации перехода —
  из самих хуков `enqueue`/`deschedule` (стреляют на CPU-владельце
  под write-гардом менеджера ДО коммита) и из `throttle_current`.
  Инвариант: Ready/Blocked => контекст в карте; Running => в слоте
  (не более чем в одном месте — дублей нет).
- Pick: контекст ИЗЫМАЕТСЯ из карты (zero-copy передача между CPU;
  v0.12 клонировал 680 Б и держал копию в карте). Вошедший бокс
  помечается per-CPU «inflight» и рециклируется на СЛЕДУЮЩЕЙ
  диспетчеризации этого CPU — демонтаж `Box::leak` (утечка ~700 Б
  на каждое переключение в v0.12).
- Отказ публикации (поток убит в окне вытеснения) — `release_slot_if`:
  бокс в пул, утечки нет. Ядровые kill-пути без гейт-reap (каскад
  user_fault, kill-сисколы) подметает `sweep_dead_contexts` на
  границе периода (v0.12 оставлял такие записи в карте навсегда).
  SAFETY per-CPU кэша: свой элемент трогает только владелец;
  возвращающиеся прерывания кэш не трогают, невозвращающиеся пути
  взаимоисключительны по потоку управления.

**Точность квот: заряд циклами TSC + TSC-граница периода:**
- Учёт — в GTCB доменов В ЦИКЛАХ: отрезок = rdtsc(парк) −
  rdtsc(диспетчеризация) (метка — новое GS-поле OFF_DISPATCH_TSC;
  протокол per-CPU — только дописывание в конец). Субтик-точно,
  включая ядровые участки потока; `cpu_used` (тики, аудит/exit) —
  floor-производное. Анти-спин-пол v0.10 сохранён: min 1 ТИК за
  проход (болтливый IPC-DoS не дешевле честного кванта); длинные
  отрезки теперь точны в обе стороны (v0.10 грубил: 2.4 тика
  исполнения = 2 тика заряда).
- Ядро: `TcbManager::set_cpu_time_unit` (циклов на тик; бекенд задаёт
  калибровкой `lapic::tsc_per_tick` до старта SMP; дефолт 1 —
  юнит-тесты и платформы без TSC), `charge_cpu_cycles`,
  `cpu_budget_cycles_left`, `TaskUsage::cpu_used_cycles`; тест
  субтик-точности (квота 3 тика = 30 циклов при unit=10 — граница
  ровно на исчерпании).
- Период — ГЛОБАЛЬНАЯ TSC-граница `PERIOD_END` (wall-семантика v0.10:
  CPU_PERIOD_TICKS суммарных тиков всех CPU, /ncpu): граница ТОЧНАЯ,
  закрытие — CAS (один победитель: refill + дренаж троттл-листа +
  sweep мёртвых + resched-IPI); тиковый счётчик CPU_TICKS/CPU_PERIOD_WRAP
  удалён. Idle-будка взводит one-shot точно на границу периода.
- LAPIC TSC-deadline (CPUID.01H:ECX[24]; x86_64 MSR 0x6E0): каждая
  диспетчеризация взводит one-shot на min(RR-квант, остаток бюджета
  домена, остаток периода) — домен перебирает квоту В МОМЕНТ
  исчерпания, а не «до ближайшего тика»; перевзвод из ядра
  (!from_user) эпсилоном (ядровые секции короткие). Фолбэк без
  фичи — прежний периодический тик (квант в GS): заряд циклами и
  TSC-граница периода работают в ОБОИХ режимах. Диагностика:
  «kmain: timer mode: tsc-deadline | periodic fallback».
  Замечание: QEMU/TCG вырезает tsc-deadline (не эмулирует) — в
  эмуляторе живёт фолбэк, дедлайн-путь — KVM/железо.

### Верификация

- Host: 151/151 тестов ядра (включая новый субтик-тест квот).
- QEMU q35 SMP=2 (TCG): полный демо-прогон — PIE x2 (self-ptr
  verified, ping-pong 3/3), все атаки песочницы заблокированы,
  «sandbox HELD» + «cpu quota HELD»; аудит показывает ТОЧНЫЙ заряд:
  «throttled (charged 96007605 cycles, limit 3 ticks per period)»
  (≈3.84 тика против квоты 3). «sched dbg»-шум исчез (0 строк).
  Регресс с intel-iommu (intremap=on) — тот же вердикт, чистый halt.

# v0.12 — Демонтаж Big Kernel Lock: fine-grained + lock-free SMP

### Сделано

**BKL удалён (`backend/src/klock.rs` — удалён; новый `kernel/src/sync.rs`):**
- Прежде: один AtomicBool сериализовал ВСЕ входы в ядро (сисколы,
  тик, фолты, внешние IRQ, диспетчеризация) — контракт однопоточности
  крейта (RefCell-менеджеры). Теперь: каждая подсистема — собственный
  короткий лок, горячие пути — атомики/lock-free.
- `sync.rs` — примитивы с IF-дисциплиной: держатель лока всегда IF=0;
  спин-ожидание на глубине 0 — с IF=1 (доставка IPI: shootdown-ACK);
  вложенное ожидание (TCB/SCHED, чьи держатели не ждут cross-CPU) —
  IF=0; внешние IRQ физически не прерывают держателя → самодедлок
  хендлера невозможен. Хуки wait/wake/depth ставит бекенд в GS:DEPTH
  до старта SMP (host-тесты — no-op-хуки). Ранги захвата:
  GATE > CLAIM > TCB > SCHED; CAP/KMEM/SHM/IrqRouter/Registry — листья.
- `KSpin<T>`/`KRwLock<T>` (RAII, depth-хуки), `RawGate` — статическая
  таблица пер-гейт локов `GATE_LOCKS[256]` (ёмкость cspace 16x16,
  нет проблемы времени жизни), `MpmcQueue` — кольцо Вьюкова
  (без аллокаций/ABA/реаллокации, ёмкость 1024 ≥ квота 512 потоков).

**Менеджеры ядра — fine-grained (RefCell → атомарные локи):**
- `TcbManager` — KRwLock (write для мутаций/транзакций, read для
  снапшотов); транзакции IPC-парковки `recv_any_park`/
  `send_thread_offer` — [переход + публикация] одной write-секцией.
- `CapabilityManager` — gates/irqs под KSpin + пер-гейт RawGate для
  rendezvous; `MemoryManager` — ops-лок (сериализует `with_facade`,
  закрывает гонку параллельного `&mut UFacade` двух потоков одного
  домена; TLB-shootdown — единственный лок, под которым ядро ждёт
  cross-CPU, его waiter'ы всегда глубина 0 → IF=1-спин жив).
- `ShmManager`, `DeviceClaimRegistry` (парк под CLAIM-локом —
  lost-wakeup закрыт), `IrqRouter`, `SyscallRegistry`, `IpcManager`
  (счётчики — атомики); IOMMU-агрегатор — ops-лок.

**IPC rendezvous — пер-гейт критсекции (`kernel/src/ipc/mod.rs`):**
- send: [claim ждущего получателя] / [буфер] / [парк отправителя] —
  одна секция RawGate(gate); доставка — ВНЕ лока (map-элементы —
  KMEM; ранг GATE→KMEM запрещён — ABBA call-фаз устранён).
- recv: [буфер → refill из send_q] / [claim отправителя] — секция;
  завершение фазы call (`complete_sender`) — вне лока (GATE→GATE
  запрещён — ABBA пары встречных ipc_call).

**Планировщик — lock-free готовность (`backend/src/sched.rs`):**
- Очередь готовности — MPMC-кольцо: enqueue из хуков TCB (под
  write-гардом — MPMC локов не берёт, инверсии рангов нет), pick —
  без чужих локов; + resched-IPI будит idle-CPU.
- Ленивый deschedule: запись остаётся в кольце, pick отсеивает по
  ФАКТИЧЕСКОМУ состоянию TCB (Dead-каскад «kill в момент rotate» —
  отсеется, воскрешения нет); финальная защита — `mark_running`
  (Ready→Running под write-гардом: провал = мимо, без входа).
- need_resched/quantum/slice_used — GS per-CPU (как прежде);
  CPU-период — атомики (как v0.10).

**Гонки, которые закрывал BKL — закрыты явно (bring-up фиксы):**
- *Rotate/троттл мимо автомата состояний*: preempt-шаг прежде пушал
  поток в кольцо/троттл-лист БЕЗ перехода Running→Ready — ленивая
  валидация pick отсеивала ВСЕ вытесненные как «stale» (демо
  зависало на первом же yield воркера). Теперь: `KernelGlue::
  requeue_thread` (Ready + enqueue-хук) и `KernelGlue::
  throttle_thread` → `TcbManager::thread_park_throttled` (Ready БЕЗ
  очереди — в троттл-лист до границы периода).
- *Публикация блокировки до сохранения контекста*: диспетчер
  паркуется в очередь, гейт сохранял фрейм ПОСЛЕ — cross-CPU
  пробуждение входило в поток со старым контекстом (первый блок —
  рестарт с start_info!). Теперь: контекст-вход — `syscall_c`
  сохраняет фрейм ДО диспетчера безусловно (повторное сохранение на
  блок-пути удалено — оно затирало бы контекст СЛЕДУЮЩЕГО
  блокирования после быстрого повторного парка на другом CPU).
  preempt-шаг сохраняет контекст ДО публикации готовности.
- *Check-then-act на выходе гейта*: «заблокирован?» решалось
  повторным чтением TCB — за окно поток успевал разбухнуть и бежать
  на другом CPU → sysret = ДВОЙНОЙ запуск. Теперь: per-CPU защёлка
  `syscall::{record,take}_block_latch` — хендлеры блокировки (IPC
  send/recv/call/recv_any, DEVICE_CLAIM) ставят её, гейт решает по
  данным СВОЕГО CPU; уже-разбуженный фрейм честно бросается
  (идентичный контекст входа принят другим CPU).

**Верификация (QEMU q35, OVMF, TCG SMP=2, EXIT=124 = холд после демо):**
- baseline / Intel VT-d (intremap=on) / AMD-Vi (intremap=on) — все
  демо v0.7–v0.11 зелёные в каждой конфигурации: SMP-стресс 0x4000
  инкрементов без потерь (миграция по yield), IOMMU smoke (map+huge+
  irq+unmap+detach) у обоих вендоров, песочница HELD (9+ нарушений
  блокированы), CPU-квота HELD (cpu_used=3/events=1), PIE-спавн на
  двух базах, IOAPIC COM1 → L4-signal, init exit 0.
- Счётчики кольца готовности (diag once в idle): enq==pop==157,
  stale=6 (легаси task-level записи + протухшие между enqueue и
  pick), markfail=0, enter=151 — во всех трёх прогонах.
- Host-тесты: 150 (было 149: +thread_park_throttled_ready_without_
  enqueue); rustfmt чисто.

### Открытые пункты (v0.13+)

- Убрать легаси task-level `set_state(Ready)` → enqueue UUID задач в
  кольцо (шум stale-записей; потоки — единственный исполняемый вид).
- per-CPU contexts-кэш вместо одной BTreeMap под KSpin (горячий путь
  контекст-входа; контенция на каждом сисколе).
- Убрать диагностику bring-up (DBG_*-счётчики sched) после стабилизации.
- TSC-deadline суб-тиковая точность квот; enqueue-проверка квоты
  пробуждённых IPC (окно перерасхода ≤ живые_потоки × квант).

# v0.11 — PIE-спавн + IOAPIC (внешние линии как L4-сообщения)

### Сделано

- Крейт `pie`: юзерспейс-загрузчик образов — ELF64 без аллокаций
  (план PT_LOAD W^X; RELA только R_X86_64_RELATIVE, иначе fail-closed;
  ET_EXEC-легаси как StaticFixed). `rogue` линкуется static-pie
  (ET_DYN + релоки под выбранную базу).
- init спавнит ОДИН образ на ДВУХ базах (0x40000000/0x50000000):
  накат релокаций с контрольным readback, PIE_PTR-сверка статического
  указателя ребёнка в READY.
- IOAPIC-драйвер: MADT тип 1/2 + ISO-флаги; enable_line — обычный
  RTE либо IRQ-ремаппинг (Intel: remapped-RTE по IRTE-слоту 0x10+pin;
  AMD-Vi: IntTab IOAPIC-устройства, IRTE-индекс = вектор); вход по
  линии — asm-стаб кладёт GSI → EOI → IrqRouter → signal в endpoint,
  без переключения контекста; `IrqLineOps` + `install_irq_line_service`.
- Фикс release-бага дерева деривации: debug_assert не отвязывал узел
  из children → «призрак» → KERNEL FAULT при переиспользовании слота
  (репродукция: два spawn→reap→revoke_all подряд).
- Репо-хигиена: .gitignore (target/, kernel.bin, OVMF_VARS.fd);
  [patch]-секция iommu-rs удалена — фиксы влиты в апстрим
  sergeyvolkovich/iommu-rs, зависимость напрямую из git.

# v0.10 — CPU-квоты GTCB (троттлинг доменов) + ленивые счётчики потоков

### Сделано

**CPU-квоты в атрибутах GTCB (`kernel/task/types.rs`, `task/mod.rs`):**
- `TaskLimits::cpu_quota` — максимум тиков планировщика за период
  (rlimit-стиль, `usize::MAX` = без лимита; трещотка распространена и
  на неё — расширить чужую/свою квоту через TASK_SET_LIMITS нельзя).
- `TaskUsage::{cpu_used, cpu_throttled, cpu_throttle_events}` — учёт:
  заряд на КАЖДОМ конце отрезка исполнения потока — вытеснение
  (квант/yield/IPI-resched) И блокировка (IPC/claim); минимум 1 тик за
  проход (анти-спин: yield-цикл и «вычислить-и-заблокироваться» не
  дешевле честного кванта) плюс фактически потреблённые тики отрезка.
- Период — политика бекенда x86_64 (`CPU_PERIOD_TICKS` = 100
  ГЛОБАЛЬНЫХ тиков всех CPU, ~1 c при SCHED_HZ=100): счётчик двигают
  ВСЕ тики таймера (пользовательские, ядровые, idle) — иначе троттл-лист
  завис бы без будящего источника; граница закрывается один раз под BKL
  (preempt-шаг гейта или будка idle): glue `on_cpu_period` сбрасывает
  учёт всех доменов, бекенд возвращает троттл-лист в готовность
  (+ resched-IPI будит idle-CPU).

**Троттлинг (бекенд планировщика `backend/sched.rs`, гейт `gate.rs`):**
- Троттл-лист в планировщике: домен за пределом квоты — его поток при
  вытеснении паркуется в отдельный список ДО границы периода (не
  диспетчеризуется); `deschedule` (Dead/Suspended) вычищает и его —
  погашенный поток не зависает в троттле.
- Единый preempt-шаг `sched::preempt_step` (вытеснение по тику И по
  выходу из сискола): refill периода → заряд домену через glue
  (`on_timeslice_consumed`) → rotate ИЛИ троттл-парк. Прежний выход
  «единственный поток — вытеснение бессмысленно» УДАЛЁН: одиночный
  спиннер-DoS теперь честно парковался бы квотой.
- Гранулярность (документировано): пробуждённый IPC-поток домена за
  пределом квоты отрабатывает до одного вытеснения — перерасход
  ограничен (живые_потоки x квант на границу), спиннеры же паркуются
  немедленно при каждом вытеснении.

**ABI (все расширения — обратно совместимы):**
- TASK_SET_LIMITS: `arg5[63:16] = cpu_quota` (0 — «не трогать»,
  наследие v0.9 — старые вызовы не замораживают домен; все единицы —
  кандидат «без лимита»; 1.. — квота в тиках за период).
- TASK_LIMITS_INFO: новые слова 6 = cpu_quota, 7 = cpu_used (тики
  текущего периода), 8 = cpu_throttle_events | (cpu_throttled?1<<32:0).
- TASK_SPAWN_IMAGE: дескриптор, u32 @ 0x6C — cpu_quota ребёнка
  (0 = без лимита — паддинг дескрипторов v0.9; 0xFFFF_FFFF — явно;
  лимит применяется ДО первого потока, «окно без квоты» невозможно).
- ExitPayload::Exit: +слова w4 = cpu_used, w5 = cpu_throttle_events —
  вердикт песочницы у родителя БЕЗ гонок с reaper'ом (TASK_LIMITS_INFO
  мёртвого домена — NotFound).

**Ленивые счётчики потоков (open item v0.9, «спавн»):**
- `TaskObj::live_threads` (GTCB) + `ThreadInner::total_live`:
  инкремент в `create_thread`, декремент в Dead-переходе потока
  (каскад смерти домена сходится туда же). Проверка `max_threads` при
  спавне/флуде — O(1) вместо O(n)-обхода реестра; `thread_count` /
  `total_thread_count` / `destroy` — тоже O(1).

**Фикс сборочной цепочки:**
- `build.sh`: путь образа rogue теперь АБСОЛЮТНЫЙ — build-скрипт init'а
  исполняется с CWD=crates/init, относительный `target/...` оттуда не
  виден; standalone-пересборка init молча получала пустой child.bin
  (баг v0.9: «no embedded child image»). В build.rs init —
  `cargo::rerun-if-env-changed=ROGUE_ELF` (cargo более не кэширует
  переключение образа).

### Демо (init S4, без изменений rogue/userlib)

Дескриптор спавна rogue теперь несёт cpu_quota=3 тика за период: rogue —
болтливая IPC-задача (GO/READY/PING x3/ATTACK/REPORT ≈ 5-6 парков),
квота трипается в середине пинг-понга — ядро печатает аудит
`[kernel: sandbox] cpu quota: domain ... throttled`, exit-уведомление
несёт cpu_used=3 / throttle_events=1, init выносит вердикт
`sandbox HELD` + `cpu quota HELD` (пинг-понг 3/3, exit 0x5A — квота
дисциплинирует, но не душит протокол).

### Тесты и верификация

Хост: 155 (было 152): учёт квот (заряд/кламп/троттл-флаг/события/
refill/история), трещотка cpu_quota, ABI-упаковка arg5 + слова 6..8,
квота из дескриптора спавна (u32 @ 0x6C, до первого потока), ленивые
счётчики против фактического состояния реестра (создание/смерть/
каскад). rustfmt чисто; QEMU x3 (baseline / Intel VT-d / AMD-Vi, оба с
intremap=on): троттл-аудит в каждом прогоне, вердикты HELD, EXIT=124
(холд после успеха), IOMMU-smoke v0.8 зелёный.

### Открытые пункты (v0.11+)

Суб-тиковая точность заряда (LAPIC TSC-deadline), отложенный троттлинг
пробуждённых IPC (enqueue-проверка квоты вместо окна перерасхода),
спавн PIE (динамический релок в copyin), политика отзывов IommuAdmin,
IOAPIC-драйвер remapped-линий, частичный unmap с расщеплением huge.

# v0.9 — Песочница: атрибуты GTCB, спавн по готовому образу, харднинг прав

### Сделано

**Атрибуты песочницы в GTCB (`kernel/task/types.rs`, `task/mod.rs`):**
- `TaskLimits` (rlimit-стиль, `usize::MAX` = без лимита): `max_pages`
  (MEM_ALLOC + входящие окна map/transfer/SHM), `max_threads`,
  `max_endpoints` (живые Gate-capability), `max_shm`, `max_caps`
  (cspace), `max_prio` (потолок THREAD_SET_PRIO), `may_spawn` (право
  творца). Хранятся в TCB задачи (`TaskObj`), дефолт — UNLIMITED
  (доверенные службы).
- Учёт: `TaskUsage {pages, shm}` — зарядка/возврат в точках расхода
  (зарядка ДО операции, атомарный откат при отказе подсистемы).
  «Число endpoint'ов» не хранится счётчиком: считается по живым
  Gate-capability (CAP_DELETE/REVOKE гасят гейт — учёт честен).
- СЕМАНТИКА ТРЕЩОТКИ: `set_limits` только УЖЕСТОЧАЕТ (min по числам,
  И по may_spawn) — задача, владеющая TaskTCB на САМУЮ СЕБЯ, не может
  расширить свою песочницу. Ошибки: PageQuota/ThreadQuota/ShmQuota →
  новый errno `QuotaExceeded` (-122, EDQUOT); SpawnDenied → EPERM.
- Сисколы: TASK_SET_LIMITS (0x1D, право TaskTCB на цель, упаковка
  слов — см. nums.rs) и TASK_LIMITS_INFO (0x1E, аудит: пределы+usage).

**Спавн по ГОТОВОМУ образу — TASK_SPAWN_IMAGE (0x1F):**
- Сискол ожидает УЖЕ залинкованный образ и принимает ТОЛЬКО
  указатели: родитель (юзерспейс) сам разбирает ELF64, выделяет свои
  регионы MEM_ALLOC, копирует сегменты/стек/argv и собирает дескриптор
  спавна (формат — `syscall/nums.rs`: entry/stack_top/thread_id/
  n_segments/argv/limits/priority + сегменты 32 байта: src у родителя,
  dst-линк-адрес, страницы, флаги). Ядро читает дескриптор через
  copyin-канал `UserCopy` (физика региона через MemRouter + direct-map
  платформы) и мапит ГОТОВЫЕ кадры родителя в новое пространство
  (map_external_at) — без единой пересылки данных.
- Атомарность песочницы: лимиты применяются ДО первого потока —
  «окно без лимитов» у ребёнка невозможно; стартовое IPC
  ([argc, argv_ptr, argv_bytes]) паркуется в очередь потока, как
  kinit делает для init. Отказ любого шага — полный откат домена
  (Dead-каскад → destroy_space → TCB destroy).
- Возврат — хендл TaskTCB(ребёнка) у родителя (лимиты/потоки/kill).
- TASK_CREATE (0x10) дополнен тем же грантом (право родителя) и
  фабрикой пространств; TASK_CREATE + THREAD_CREATE + MEM_MAP_AT
  (0x55, map_fixed по праву TaskTCB) остаются низкоуровневым путём.

**Рантайм-адресные пространства (`kernel/mem/mod.rs` + startup):**
- `SpaceFactory` (create_space/destroy_space) — тип-стёртый сервис,
  реализует PlatformSpaces (GCTL + Platform): геометрия окна — от
  платформы (`configure_runtime_spaces`), MMAP-бекенд — `make_mmap()`.
- `MemoryManager::create_task_space/destroy_task_space` — фасады под
  владением менеджера (slab-кэш под spin::Mutex: рантайм-аллокация
  через &self, kinit-пути — get_mut без лока); смерть домена дропает
  фасад: owned-кадры возвращаются пулу, external-окна (стейджинг
  родителя) остаются источнику — L4 pager-модель.
- Glue::reap_thread — полный контракт смерти домена: revoke_all(cspace)
  → SHM-регионы → TCB destroy → destroy_space; диагностика
  «[kernel] task reaped: cspace revoked, space dropped».

**Харднинг системы безопасности (закрытые дыры v0.8):**
- IOMMU-группа 0x80 гейтована новой capability `IommuAdmin`
  (kind=5): выдаётся ядром доверенным задачам (kinit — init), дети её
  не получают и не передают. Ранее ЛЮБОЙ домен мог репрограммировать
  IOMMU (ENUM/ATTACH/MAP/UNMAP/DETACH/IRQ_MAP/IRQ_UNMAP без проверок).
- MEM_TRANSFER (0x53): flexpage-окно в чужой домен — только по
  TaskTCB-праву на ПОЛУЧАТЕЛЯ (знание TaskId правом не было).
- CAP_MINT/CAP_SEND: передача в ЧУЖОЙ cspace — только по TaskTCB на
  получателя + предел max_caps получателя (флуд чужого cspace — DoS).
- THREAD_TERMINATE/THREAD_DESTROY/THREAD_SET_PRIO: требовали только
  знания ThreadId — теперь право домена (TaskTCB ИЛИ свой домен) +
  потолок max_prio цели (эскалация 255 — захват CPU).
- SHM (SETUP_RING/BIND_DOORBELL/MAP/DESTROY/RING_DOORBELL): все
  операции — только владельцу региона (угаданный ShmId ранее позволял
  разрушить чужие кадры и утянуть чужую память отображением).
- TASK_CREATE + TASK_SPAWN_IMAGE: право творца гасится атрибутом
  may_spawn (песочница не плодит домены-«побеги» с чистыми лимитами).
- Багфикс IPC_RECV (0x33): прямая встреча (неблокирующий путь)
  выбрасывала сообщение после чтения слова 0 — слова 1.. были
  недоступны IPC_MSG_WORD (класс бага v0.5.2, у recv_any починен,
  у recv — нет). Все пути теперь заполняют mailbox.
- Аудит: каждая блокировка песочницы печатает «[kernel: sandbox] …»
  в консоль отладки (квоты/права/угаданные хендлы) — оператор видит
  картину атаки вживую.

**Демо (init v0.9 S4 + крейт `rogue`):**
- init встраивает образ rogue байтами (`include_bytes!`; build.sh:
  ROGUE_ELF → build.rs → OUT_DIR/child.bin), парсит ELF64, готовит
  регионы, дескриптор с песочницей (max_pages 61 = образ+стек+argv+40,
  threads 4, endpoints 3, shm 2, caps 8, prio 100, may_spawn=0) и
  спавнит домен ОДНИМ сисколом — ядро получает только указатели.
- Протокол: порт init → CAP_MINT копии ребёнку; TaskTCB(ребёнка) →
  CAP_MINT (своя кухня — квоты держат даже хозяина TCB); GO → READY →
  PING x3 (эхо+контрольная сумма) → ATTACK → REPORT → TASK_EXIT(0x5A);
  exit-уведомление — на порт init (TASK_SET_EXIT_EP ребёнка), затем
  init возвращает стейджинг пулу (MEM_FREE x6) и печатает вердикт.
- rogue открывает свои порты (2 из 3: третья — в квоте), после
  команды атакует: флуд потоков (3 потока, 4-й -122), эскалация
  приоритета (-122), kill родителя по угаданному хендлу (-9), спавн
  своего домена (EPERM, may_spawn=0), захват IOMMU (EPERM, нет
  IommuAdmin), SHM-флуд (2 из 2, третья -122) и разрушение региона
  РОДИТЕЛЯ (EPERM, owner-гейт), проталкивание capability в cspace
  родителя (EPERM), флуд памяти (35 страниц, затем -122). Итог:
  9 нарушений заблокировано, вердикт «sandbox HELD» во всех трёх
  конфигурациях QEMU (без IOMMU / Intel VT-d intremap=on / AMD-Vi
  intremap=on).

**userlib (C-ABI) + rogue (Rust-приложение):**
- userlib: crate-type += rlib (Rust-приложения линкуют те же _start и
  l4_*); новые обёртки l4_task_set_limits/l4_task_limits_info/
  l4_task_spawn_image/l4_mem_map_at + прототипы в include/l4.h.

### Верификация

- Host-тесты: 152 passed (138 ядро: +8 новых — квоты страниц/SHM с
  откатами, трещотка лимитов, spawn-image по указателю (дескриптор,
  песочница до потока, старт-IPC, откат битого размера), права
  transfer/terminate/SETPRIO/отправки капов, потолок приоритета).
- rustfmt: чисто; сборка образа exit 0; три прогона QEMU: sandbox
  HELD (по 9 аудит-линий ядра, ping-pong 3/3, exit 0x5A, стейджинг
  возвращён), IOMMU smoke Intel/AMD зелёный (v0.8 паритет).
- Логи: logs/v0.9/ (build + qemu-1-baseline + qemu-2-intel +
  qemu-3-amd).

### Открытые пункты (v0.10+)

- «Ленивая» квота потоков при SMP-гонке создаётся по счётчику в GTCB
  (сейчас — живой обход реестра, с big-kernel-lock это честно).
- Спавн PIE-образов (динамический релок) — по-прежнему только
  статические линк-адреса (как elfload ядра).
- CPU-квоты (timeslice) — планировщик бекенда пока квант не режет.
- Отзыв IommuAdmin производными (revoke-дерево) — стандартный путь
  есть, политику оборачивания init-ем — на v0.10.

## v0.8 — IOMMU: IRQ-ремаппинг + мульти-IOMMU + крупные страницы; userlib (C-ABI)

### Сделано

**IRQ-ремаппинг (`backend/vtd.rs` — Intel, `backend/amd.rs` — AMD-Vi):**
- Intel: IRTA (256 IRTE = 4 КиБ, S=7, EIME=0 — ядро в xAPIC) → GCMD
  SIRTP (одной записью с ENABLE|QIE — каждый бит GCMD ЗАПРОС, баг
  v0.6.1 не воспроизводим) → IEC-флеш через QI (QiIec global) → GCMD
  IRE; GSTS IRTPS/IRES обязательны. IRTE (remapped-формат): P|vector|
  dest|SVT=11b VerifyFull+SQ=01b (сверка bus+dev источника); слоты
  1..15, 26..255 (0 — сисьмный «нет handle»; 0x10..0x25 — диапазон
  IOAPIC по спеке, резерв); погашение — выборочный QiIec + sync.
- AMD-Vi: per-device IRTE-таблица (v1, 128-бит, IntTabLen=4 → 16
  записей на страницу) из DTE: IV=1 + IntTabPtr + IntCtl=10b (remap
  on); INVALIDATE_INTERRUPT_TABLE (05h) командным буфером после
  записи/сброса IRTE; detach гасит таблицу в пул. Индексы 1..=15
  (0 — резерв).
- Сисколы: IOMMU_IRQ_MAP (0x85: ctrl/dev/vector/dest/flags → handle
  — его драйвер устройства кладёт в MSI-адрес) и IOMMU_IRQ_UNMAP
  (0x86); flags: bit0 level-triggered, bit1 logical DM. ENUM-флаги:
  bit4 = irq_remap, bit5 = large_pages (ABI v0.6 не меняется —
  расширение только новыми битами/номерами).
- Честная граница: включение IR (IRTA/SIRTP/IEC/IRE, IntCtl/DTE)
  валидировано эмулятором (QEMU intremap=on: attach с IR-DTE и
  программирование IRTE проходят, event log чист); ДОСТАВКА
  remapped-MSI требует драйвера устройства, поднимающего MSI —
  за пределами v0.8 (в QEMU-прогоне MSI-трафика нет).

**Мульти-IOMMU (vtd.rs/amd.rs/iommu.rs):**
- Драйверы хранят ВСЕ единицы (Vec<инстанс>): vtd — каждый DRHD
  DMAR, amd — каждый IVHD с уникальной MMIO-базой (дедуп: QEMU
  кладёт 10h+11h ОДНОЙ единицы). IommuService маршрутизирует по
  сквозному индексу: сперва все Intel, затем все AMD (агрегатор
  pick() → (драйвер, локальный индекс)); ENUM счётчик — честный.
- HAL-путь (ANIOMMUInterface) неймспейсит DeviceId: (контроллер <<
  20) | локальный id — операции знают контроллер; сисколы ABI
  v0.6 не меняют (ctrl передавался явно с v0.6).

**Крупные страницы (2 МиБ):**
- Intel: CAP.SSLPS bit0 → SS-PDE huge-лист (бит PS = 0x80, физика
  51:21); раскладка map — детерминированный проход: 2 МиБ-выровненный
  кусок ≥ 512 стр → один PDE, остальное — 4К PTE; unmap/protect
  повторяют ту же геометрию (зеркало таблиц не храним). sspt_free
  различает huge-лист (не таблица — физика не наша).
- AMD-Vi: v1-лист уровня 2 (NextLevel=0 — размер задаётся уровнем,
  спека v1); pt_free различает листы (NextLevel=0) на любом уровне.
- UNMAP-политика v0.8: точное совпадение (iova, count) с MAP —
  частичное снятие с расщеплением huge — v0.9 (v0.7-хак с фантомным
  хвостом удалён; честный EINVAL).

**userlib — C-интероп пользователей (`crates/userlib`, v0.8):**
- Статическая C-библиотека (x86_64-unknown-none, staticlib): `_start`
  (стартовый IPC L4 → разбор argv-блока → прикладной `main(argc,
  argv)` → TASK_EXIT(код)) + `l4_*` обёртки ВСЕЙ таблицы сисколов
  (группы 0x00..0x86: система, задачи/потоки, capability, IPC,
  устройства/IRQ, память, SHM/io_uring, отладка, IOMMU) + хелперы
  консоли (l4_debug_write_bytes/l4_puts/l4_puthex) + страховка
  __stack_chk_fail. C-заголовок: crates/userlib/include/l4.h.
- Пример C-сервера: examples/capp.c (сборка scripts/build.sh:
  gcc -ffreestanding -fno-stack-protector -nostdlib + init.ld @
  0x40000000) — идентификация, argv-конфигурация, MEM_ALLOC+паттерн,
  полный IOMMU-проход v0.8 (map+huge+irq+unmap+detach) на C.
- Конфигурация серверов: scripts/boot_cfg_c.xml (capp — первый
  сервер, init — второй модуль); выбор через BOOT_CFG=... в
  scripts/build.sh (по умолчанию — init).

**Скрипты/QEMU:**
- run_qemu.sh: QEMU_INTREMAP=0|1 (по умолчанию 1) — intremap=on в
  -device intel-iommu/amd-iommu (v0.7 выключал: IR не было в драйверах).
- build.sh: шаги userlib+capp; CC override; BOOT_CFG-выбор.

### Исправленные баги
1. **vtd: unmap ломал huge-таблицы** (найден при разработке v0.8):
   v0.7-хак unmap (снятие больше отображения → фантомный хвост в
   карте) конфликтует с детерминированной раскладкой v0.8 — удалён;
   policy точного совпадения, EINVAL на частичное.
2. **amd: pt_free/sspt_free freeing отображённой физики** — лист
   уровня 2 неотличим от каталога при обходе: Intel — бит PS,
   AMD — NextLevel=0; без фикса detach освобождал бы чужую физику
   в пул (коррупция).

### Верификация (QEMU, OVMF/UEFI, TCG SMP=2, intremap=on)
- init (Rust): baseline / intel-iommu / amd-iommu — ENUM (флаги
  0x3037: bit4 irq_remap, bit5 large_pages), ATTACH(00:1f.2), MAP,
  remap→-17, UNMAP, MAP huge 512p (один SS-PDE/v1-лист), UNMAP huge,
  IRQ_MAP→handle=1, IRQ_UNMAP, DETACH, SMP-стресс OK, boot chain OK.
- capp (C, boot_cfg_c.xml): baseline / amd-iommu — argv-протокол,
  MEM_ALLOC+паттерн 0xCAFEBABEDEADBEEF, полный IOMMU-проход на C,
  TASK_EXIT(0), boot chain OK.
- Host-тесты: 140 passed (v0.7: 139; +1 irq_map_unmap_cycle).

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
