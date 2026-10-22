# pkg_generic_interface v0.4 — переработка системы сисколов

Обновление v0.3 -> v0.4 по итогам АУДИТА пробелов: реестр сисколов
переработан с интрузивного RB-дерева на ПЛОСКУЮ таблицу (вектор
прерываний), нумерация стала плотной (группы по 16), добавлены 17
недостающих сисколов — прежде всего IRQ-привязки драйверов (L4
irq_attach), MMIO-отображение BAR, обзор cspace и идентификация себя.

Сборка и тесты: `cargo +nightly test` (121 тест, зелёные).

## Переработка реестра сисколов (просьба автора: «rbtree — не по-микроядерному»)

### Было (v0.3)
`SyscallRegistry` = RefCell<slab-кэш + интрузивное RB-дерево по номеру>:
O(log n) поиск на горячем пути, аллокации slab при каждой регистрации,
Drop-протокол слотов, unsafe-адаптеры intrusive-collections. Для
фиксированного набора ~60 сисколов — менеджерская общность без пользы.

### Стало (v0.4)
ПЛОСКАЯ таблица `[Option<&'static dyn SyscallHandler>; 256]` в .bss —
прямой аналог вектора прерываний (IDT):
* диспетчеризация = один bounds-check + одно чтение слота, O(1),
  ноль аллокаций на любом пути;
* `new()` без `Result` (отказ невозможен в принципе);
* `register` (строгий: занятый слот — EEXIST), `reregister` (подмена
  платформой дефолтного хендлера своим), `unregister`;
* `install_default_table()` — ДЕФОЛТНАЯ таблица крейта: все встроенные
  хендлеры по своим номерам, идемпотентна; GCTL вызывает её при сборке —
  платформа получает готовый стол и может перезаписывать слоты;
* из syscall-слоя ИСЧЕЗЛИ зависимости: intrusive-collections,
  slab-кэш capability::mem, Drop-протокол.

### Плотная нумерация 0x00..0xFF (было 0x1000..0x1704)
Группы по 16, старший полубайт = группа:
```
0x00 системные    (DEVICE_INFO, SELF_INFO, SYS_TIME; TASK_SPAWN — легаси-пример)
0x10 задачи/потоки (TASK_CREATE/SET_EXIT_EP/EXIT/KILL/EXIT_EXCEPTION,
                    THREAD_CREATE/DESTROY/TERMINATE/SET_PRIO/
                    SUSPEND/RESUME/YIELD/EX_REGS)
0x20 capability   (CAP_MINT/SEND/REVOKE/DELETE/LIST/INFO)
0x30 IPC          (EP_CREATE, IPC_SEND/RECV/CALL/SEND_THREAD/RECV_ANY,
                    IPC_MSG_WORD/LEN/CLEAR, NOTIFY_SIGNAL)
0x40 устройства   (DEVICE_CLAIM/RELEASE/CLAIM_STATUS/ENUM/MAP_REGION,
                    IRQ_ATTACH/DETACH/ACK)
0x50 память       (MEM_ALLOC/FREE/TRANSFER/INFO)
0x60 SHM io_uring (SHM_CREATE/SETUP_RING/BIND_DOORBELL/MAP/DESTROY,
                    RING_DOORBELL, SHM_INFO)
0x70 отладка      (DEBUG_WRITE/DUMP_TASKS/TRACE/DUMP_THREADS)
0x80..0xFE — свободно для платформы; 0xFF — зарезервировано.
```
TASK_SPAWN (сискол без capability-проверки) в дефолтную таблицу НЕ входит:
безопасная замена — TASK_CREATE с правом творца.

## Новые подсистемы

### 1. IRQ-роутер: прерывания как сообщения (`hal/device/irq.rs`, новый)
L4 irq_attach в гибридной модели крейта: привязка линии прерывания
устройства к notification-endpoint'у. Протокол edge-семантики с
pending-битом (уведомления L4): событие -> pending=true + signal(gsi) в
endpoint; повторные события до ACK склеиваются одним битом (не теряются
и не переполняют буфер); ACK (EOI) взводит линию снова. Валидация:
GSI обязан принадлежать ресурсам ЖИВОГО устройства (произвольный номер
не привязать), право подтверждено DeviceReference-capability.
Каскады: смерть задачи-владельца (detach_all_of), hot-removal устройства
(detach_device — GCTL::rescan_devices оркестрирует). Хранение — плоский
Vec в RefCell (привязок мало, регистрация редкая — та же философия
простоты, что у реестра сисколов). Платформа вызывает `irq_event(gsi)`
из верхнего полуобработчика прерываний.

### 2. TimeSource-контракт (`syscall/system.rs`, новый)
Монотонные часы (аналог KIP clock): платформенный трейт + одноразовая
установка (паттерн DebugSink/GateManager). SYS_TIME без источника —
честный ENOSYS; платформа может подменить весь слот (reregister).
Таймауты IPC и сон — слой выше: таймер-сервер юзерспейса (классический
микроядерный путь — ядро не хранит таймеры процессов).

### 3. `SchedulerInterface::yield_now` (`task/scheduler.rs`)
Дефолт-метод (no-op): кооперативный бекенд трактует yield как пустой
звук — и это корректно; бекенды с очередями готовности переопределяют.
Сискол THREAD_YIELD зовёт его для ТЕКУЩЕГО потока.

## Новые сисколы (17)

| Номер | Сискол | Что закрывает |
|---|---|---|
| 0x03 | SELF_INFO | задача после старта не знала свой TaskId/ThreadId/CPU |
| 0x04 | SYS_TIME | часы ядра (KIP clock) |
| 0x10 | TASK_CREATE | право творца: TaskTCB на СЕБЯ (spawn-сервер/devmon) |
| 0x13 | TASK_KILL | право TaskTCB на цель; Killed{source} + локи + IRQ + каскад |
| 0x14 | TASK_EXIT_EXCEPTION | паника рантайма: Exception{regs+fault} доставка + гашение |
| 0x19 | THREAD_SUSPEND | L4 suspend (право: свой домен или TaskTCB) |
| 0x1A | THREAD_RESUME | L4 resume |
| 0x1B | THREAD_YIELD | L4 yield (хук планировщика) |
| 0x1C | THREAD_EX_REGS | L4 ex_regs: смена entry/stack потока (pager, отладка) |
| 0x25 | CAP_LIST | обход cspace (devmon находит выданные ядром хендлы) |
| 0x26 | CAP_INFO | снимок capability: kind/perms/badge/alive/идентификация |
| 0x44 | DEVICE_ENUM | обзор живых устройств (compact-слова: kind/path/flags) |
| 0x45 | DEVICE_MAP_REGION | MMIO BAR -> map_external (требует claim!) |
| 0x46 | IRQ_ATTACH | привязка GSI -> endpoint (валидация: GSI из ресурсов устройства) |
| 0x47 | IRQ_DETACH | снятие привязки (владелец) |
| 0x48 | IRQ_ACK | EOI: pending снят, линия снова взведена |
| 0x54 | MEM_INFO | регион по адресу: (vbase, pbase, pages) |

Полный L4-цикл драйвера теперь замкнут: DEVICE_ENUM -> CAP_LIST/CAP_INFO
-> DEVICE_CLAIM -> DEVICE_MAP_REGION (регистры) -> IRQ_ATTACH (прерывания)
-> IPC_RECV на endpoint'е -> IRQ_ACK -> ... -> DEVICE_RELEASE.

## Прочие изменения

* `SyscallCtx`/`SyscallFacade`/GCTL: новое поле `irq` (IrqRouter),
  проводка with_irq; GCTL::new ставит дефолтную таблицу сисколов.
* `rescan_devices`: снятие IRQ-привязок пропавших устройств.
* `TcbManager::thread_ex_regs`: смена entry/stack потока (менеджер).
* `SyscallError: From<SchedulerError>` (yield-хук).
* `DeviceInfoHandler` — юнит-хендлер (реестр устройств из ctx; было поле
  `&'static DeviceManager` — несовместимо с дефолтной таблицей).
* Маппинг `IrqError -> SyscallError` (errno-словарь).
* TASK_EXIT/KILL/EXIT_EXCEPTION: полный маршрут выхода теперь включает
  снятие IRQ-привязок (локи снимались и раньше).

## Тесты (121, было 104)

Реестр: плоская таблица (границы 0/255/256/u64::MAX, reregister-подмена,
дефолтная таблица идемпотентна, TASK_SPAWN вне стола). IRQ: полный цикл
attach/event/склейка/ack/detach, одна привязка на линию, каскады
(устройство/задача), слово в очереди endpoint'а. Сисколы: TASK_CREATE
(право на себя vs чужого), TASK_KILL (Killed-доставка + каскад),
TASK_EXIT_EXCEPTION (слова Exception), THREAD_SUSPEND/RESUME/YIELD/EX_REGS
(включая чужой поток без права), CAP_LIST/CAP_INFO (слова), DEVICE_ENUM
(kind/path/flags), DEVICE_MAP_REGION (claim-гейт + FakeRouter),
IRQ-хендлеры через реестр, SELF_INFO/SYS_TIME (источник + подмена),
MEM_INFO (регион/окно/ENOENT/EINVAL).

---

# pkg_generic_interface v0.3 — расширение L4-Fiasco

Обновление v0.2 -> v0.3: потоки L4, гибридный IPC, эксклюзивные локи
устройств с hot-removal-уведомлениями, очереди блокировки в планировщике,
память (эластичные регионы + flexpage), разделяемая память io_uring,
exit-протокол (3 вида данных), отладочные сисколы, декодирование PCIe
capability в обходчике PCI.

Сборка и тесты: `cargo +nightly test` (104 теста, зелёные).

## Новые подсистемы

### 1. Потоки — единицы планирования (`task/thread.rs`, новый)
L4-модель: ЗАДАЧА = домен защиты (cspace + адресное пространство, `TaskObj`),
ПОТОК = сущность, которую диспетчирует планировщик (`ThreadObj`). ThreadId
разделяет пространство имён с TaskId (глобальные номера L4). У потока — свой
автомат состояний (Ready/Running/Blocked/Suspended/Dead), приоритет, точка
старта (entry/stack), IPC-состояние (причина ожидания, почтовый ящик,
парковочная очередь direct-IPC). Смерть задачи — каскад гасит её потоки.
`TcbManager` вырос: create_thread/destroy/thread_set_state/with_thread и др.

### 2. Очереди блокировки в планировщике (`task/scheduler.rs`)
`SchedulerInterface` расширен контрактом `BlockQueueId`: блок-очереди ЖИВУТ
в бекенде планировщика (отдельный крейт — здесь только контракт):
`block_queue_create/destroy`, `block_push`, `block_remove`,
`block_pop_front` (FIFO), `block_len`. Дефолт-реализации — отказ
`Backend("block queues are not supported")`: старые бекенды компилируются.
Пользуются: IPC-endpoint'ы (send/recv-очереди) и DeviceLock (очередь
претендентов). Двухфазный контракт: Blocked (хук deschedule) -> block_push;
пробуждение: block_pop_front -> доставка -> Ready (хук enqueue).

### 3. IPC в стиле L4 — гибрид (`ipc/mod.rs`, новый)
* **Endpoint-объекты** (seL4-слой поверх capability): `GateObj` с реальным
  `EndpointState` (буфер сообщений ёмкости `capacity` + две блок-очереди).
  `capacity = 0` — строгий rendezvous (L4 sync IPC), `> 0` —
  notification-канал (doorbell, exit, события устройств).
* **Fast-path по глобальному ThreadID** (L4 v2): `send_thread` — прямая
  отправка потоку в open-receive (доставка в почтовый ящик + пробуждение),
  иначе парковка в очереди ПОТОКА (до 8 сообщений). `recv_any` — открытый
  приём.
* **Сообщения**: 8 inline-слов + 4 map/grant-элемента (flexpage: кадры
  окна отправителя отображаются/передаются получателю через `MemRouter`) +
  длинный payload (снимки регистров, строки argv).
* **ipc_call** (L4): send + ожидание ответа на reply-endpoint БЕЗ возврата
  в пользователя между фазами.
* Блокировка потока в сисколе: arch-глюй после хендлера проверяет
  состояние потока и переключает контекст; возврат материализуется из
  `ThreadObj::syscall_ret` при пробуждении.

### 4. Разделяемая память io_uring (`ipc/shm.rs`, новый)
`ShmManager`: регионы из физического пула (zero-copy — ядро не копирует
данные), `RingLayout` — io_uring-геометрия колец SQ/CQ в регионе
(заголовок head/tail/mask + массивы SQE/CQE; инициализация — юзерспейс),
doorbell-endpoint (signal производителем после submit: `RING_DOORBELL`).
Обе стороны отображают регион (`SHM_MAP`) и работают с кольцами напрямую.

### 5. Эксклюзивные claim устройств (`hal/device/claim.rs`, новый)
`DeviceClaimRegistry` (внутри `DeviceManager`): LockObj на устройство —
владелец-задача (ОДНА задача одновременно; idempotent для владельца),
очередь претендентов — блок-очередь планировщика, notify-endpoint
владельца.
**Hot-removal** (требование №1): rescan помечает запись `alive = false`;
`GCTL::rescan_devices()` для каждого удерживаемого лока:
1) IPC-сообщение DEVICE_LOST владельцу (тег + идентичность устройства);
2) форс-снятие лока;
3) претенденты будятся с кодом ENXIO (`syscall_ret` = отрицательный errno);
4) лок «отравняется» до повторного появления устройства
   (`claim` -> `SyscallError::DeviceGone` — ошибка от ядра).
Выход задачи — авто-release всех её локов. `enumerate()`/`rescan_bus()`
собирают hot-removal diff (`removed_since_last_scan()`); повторное
появление устройства снимает отравление.

### 6. Exit-протокол: ТРИ вида данных на exit endpoint (`ipc::ExitPayload`)
1. **Exit{code}** — код возврата (TASK_EXIT / task_exit);
2. **Exception{snapshot, fault}** — снимок регистров процесса
   (`RegisterSnapshot`, слова — платформенная раскладка) + указатели
   фолта (`FaultInfo`: адрес, IP, класс — page r/w/x, #GP, выравнивание,
   арифметика);
3. **Killed{by}** — кем убита (`KillSource`: сама / ядро / задача).
Стабильная сериализация в слова (w0 = тег, w1..2 = TaskId, дальше — вид).
Регистрация: TASK_SET_EXIT_EP. Доставка — ядерная (не блокирует ядро).

### 7. Протокол запуска L4 (argc/argv через IPC)
TASK_CREATE (домен) -> THREAD_CREATE (главный поток, entry/stack) ->
TASK_SET_EXIT_EP -> родитель шлёт стартовое сообщение ПРЯМОМУ ПОТОКУ
(fast-path): слова [argc, argv_ptr, argv_bytes, envp_ptr, envp_bytes] +
map-элемент с окном буфера argv. Главный поток начинает жизнь с
`IPC_RECV_ANY`. Полный цикл покрыт тестом `l4_full_cycle_spawn_argv_exit`.

## Сисколы (номера — `syscall/nums.rs`, 0x1000..0x1700)
* 0x1100: TASK_CREATE/SET_EXIT_EP/EXIT, THREAD_CREATE/DESTROY/TERMINATE/
  SET_PRIO;
* 0x1200: CAP_MINT/SEND/REVOKE/DELETE (передача прав capability);
* 0x1300: EP_CREATE, IPC_SEND/RECV/CALL/SEND_THREAD/RECV_ANY,
  IPC_MSG_WORD/LEN/CLEAR, NOTIFY_SIGNAL;
* 0x1400: DEVICE_CLAIM/RELEASE/CLAIM_STATUS;
* 0x1500: MEM_ALLOC/MEM_FREE (эластичные регионы, адрес — возврат),
  MEM_TRANSFER (flexpage map/grant);
* 0x1600: SHM_CREATE/SETUP_RING/BIND_DOORBELL/MAP/DESTROY/INFO,
  RING_DOORBELL;
* 0x1700: DEBUG_WRITE/DUMP_TASKS/TRACE/DUMP_THREADS (+ глобальный
  `DebugSink` платформы, трассировка в реестре сисколов).

## Память
* `UFacade::alloc_region` (возвращает адрес), `map_external` (внешние кадры
  SHM/устройств — запись `external`, не возвращаются пулу при снятии),
  `detach_region` (grant: снять без возврата кадров), `region_window`;
* `MemoryManager`: привязки задача→фасад (`bind/unbind/with_facade`) —
  сисколы и IPC-элементы идут через фасад задачи;
* `MemRouter` (trait, type-erased) + `MemRouterImpl` над менеджером:
  alloc/free/map_external/region_at/transfer.

## Обходчик PCI
* Декодирование PCIe capability (0x10): версия, тип порта, максимальная и
  согласованное скорость/ширина звена (`PciExpressInfo`) — в
  `PciDeviceData` и сериализацию `record_words`;
* hot-removal diff + возрождение записей (см. claims).

## Совместимость
`SyscallFacade::new(tasks, caps, registry)` сохранён (подсистемы —
builder-методы with_ipc/with_shm/with_devices/with_memory);
`dispatch`/`dispatch_number` получили параметр `thread` (L4: сискол всегда
на потоке); `SyscallCtx` строится `core()` + builder'ы. `create_gate`
сохранён (легаси, rendezvous без очередей); полный endpoint —
`create_endpoint`. Новые errno: TryAgain (EAGAIN), DeviceGone (ENXIO).

## Тесты
104 (было 81): потоки+каскад, IPC (endpoint/fast-path/rendezvous/buffer/
mailbox), exit-протокол (3 вида), claim (эксклюзивность/очередь/
hot-removal/уведомление), SHM (геометрия/полный поток io_uring),
память (alloc/free/transfer), debug, PCIe capability, интеграционный
L4-цикл.
