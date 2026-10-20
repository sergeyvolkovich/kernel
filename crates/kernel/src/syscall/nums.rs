// ==== Таблица номеров сисколов (плотная L4-подобная нумерация v0.4) ====
//
// Переработка v0.4: разреженные диапазоны 0x1000-0x1700 заменены ПЛОТНОЙ
// таблицей — реестр сисколов теперь плоский массив слотов (вектор
// прерываний), диспетчеризация — прямой индекс, ноль аллокаций и ноль
// деревьев на горячем пути. Номер обязан попадать в таблицу
// ([`crate::syscall::SYSCALL_TABLE_SIZE`]); остальное — ENOSYS.
//
// Карта групп (старший полубайт):
//   0x00 — системные + легаси-примеры v0.2
//   0x10 — задачи и потоки (L4: task_new / thread_control / ex_regs)
//   0x20 — передача прав capability (map/grant/send поверх cspace)
//   0x30 — IPC (endpoint'ы + fast-path + mailbox)
//   0x40 — устройства и IRQ (claim, MMIO, прерывания драйверов)
//   0x50 — память (аллокация/освобождение/flexpage-перенос)
//   0x60 — разделяемая память io_uring (регионы/кольца/doorbell)
//   0x70 — отладка
//   0x80 — IOMMU/DMA-ремаппинг (v0.6: контроллеры/attach/map/unmap)
//   0x90-0xFE — свободно для платформенных сисколов
//   0xFF — зарезервировано (расширение таблицы в будущем)
//
// Слоты — константы ПО УМОЛЧАНИЮ: платформа вправе перезаписать любой
// слот своей регистрацией (`SyscallRegistry::register`) — например,
// подменить SYS_TIME платформенным источником времени.

use crate::syscall::types::SyscallNumber;

// ==== 0x00: системные + легаси-примеры v0.2 ====

/// Легаси-пример v0.2: создание задачи БЕЗ capability-проверки.
/// В дефолтную таблицу НЕ входит (нет права — включайте осознанно);
/// безопасный путь — TASK_CREATE. ABI: arg1..2 = TaskId(lo, hi),
/// arg3 = приоритет.
pub const TASK_SPAWN: SyscallNumber = SyscallNumber(0x01);

/// Чтение метаданных устройства по capability (пример v0.2).
/// ABI: arg1 = хендл DeviceReference, arg2 = индекс слова
/// (сериализация `DeviceRecord::record_words`).
pub const DEVICE_INFO: SyscallNumber = SyscallNumber(0x02);

/// Идентификация себя: задача после старта не знает своих ID.
/// Слова по индексу: 0 = task_id.lo, 1 = task_id.hi, 2 = thread_id.lo,
/// 3 = thread_id.hi, 4 = cpu, 5 = cpu_count (v0.6). ABI: arg1 = индекс.
pub const SELF_INFO: SyscallNumber = SyscallNumber(0x03);

/// Монотонные часы ядра (аналог KIP clock в L4), наносекунды.
/// Источник — TimeSource-контракт, установленный платформой; без
/// источника — ENOSYS. Платформа вправе подменить слот своей
/// реализацией (регистрация поверх дефолтной).
pub const SYS_TIME: SyscallNumber = SyscallNumber(0x04);

// ==== 0x10: задачи и потоки ====

/// Создать задачу-домен (protection domain: cspace + адресное
/// пространство). ПРАВО: capability TaskTCB на САМОГО ВЫЗЫВАЮЩЕГО —
/// ядро выдаёт её доверенным задачам (spawn-сервер, devmon) как
/// сигнал права творца. ABI: arg1 = хендл TaskTCB(себя),
/// arg2..3 = TaskId(lo, hi) новой задачи, arg4 = приоритет.
pub const TASK_CREATE: SyscallNumber = SyscallNumber(0x10);

/// Зарегистрировать exit-endpoint задачи: ядро доставит туда
/// `ExitPayload` (код выхода / исключение / кем убита).
/// ABI: arg1 = хендл Gate-capability в cspace вызывающего.
pub const TASK_SET_EXIT_EP: SyscallNumber = SyscallNumber(0x11);

/// Само-выход задачи с кодом: каскад гасит потоки, локи устройств
/// отпускаются, IRQ-привязки снимаются, exit-состояние уходит на
/// exit endpoint. ABI: arg1 = код выхода.
pub const TASK_EXIT: SyscallNumber = SyscallNumber(0x12);

/// Убить задачу (право TaskTCB на ЦЕЛЬ): exit-доставка Killed{source}
/// -> локи -> IRQ-привязки -> каскад Dead. ABI: arg1 = хендл TaskTCB
/// цели.
pub const TASK_KILL: SyscallNumber = SyscallNumber(0x13);

/// Гашение вызывающей задачи по ИСКЛЮЧЕНИЮ (паника рантайма, фолт):
/// доставка ExitPayload::Exception (снимок регистров + fault-слова) на
/// exit endpoint, затем домен умирает. ABI: arg1 = fault_addr,
/// arg2 = ip, arg3 = FaultKind (слово), arg4..5 = первые 2 слова
/// снимка регистров (полный снапшот — платформенный payload по
/// контракту `RegisterSnapshot`).
pub const TASK_EXIT_EXCEPTION: SyscallNumber = SyscallNumber(0x14);

/// Создать поток в домене (L4 thread_control). Требует capability
/// TaskTCB целевой задачи. ABI: arg1 = хендл TaskTCB, arg2 = entry,
/// arg3 = stack_top, arg4..5 = ThreadId(lo, hi) — назначает вызывающий.
/// Приоритет — THREAD_SET_PRIO.
pub const THREAD_CREATE: SyscallNumber = SyscallNumber(0x15);

/// Разрушить TCB завершённого потока. ABI: arg1..2 = ThreadId(lo, hi).
pub const THREAD_DESTROY: SyscallNumber = SyscallNumber(0x16);

/// Перевести поток в Dead (terminate; без exit-доставки — это
/// принудительное гашение, см. TASK_EXIT для домена).
/// ABI: arg1..2 = ThreadId(lo, hi).
pub const THREAD_TERMINATE: SyscallNumber = SyscallNumber(0x17);

/// Приоритет задачи/потока (общее пространство имён).
/// ABI: arg1..2 = id(lo, hi), arg3 = приоритет.
pub const THREAD_SET_PRIO: SyscallNumber = SyscallNumber(0x18);

/// Приостановить поток (Suspended; вне очереди планировщика).
/// Себя — тоже (возврата в пользователя до RESUME не будет).
/// ABI: arg1..2 = ThreadId(lo, hi). Требует TaskTCB домена потока.
pub const THREAD_SUSPEND: SyscallNumber = SyscallNumber(0x19);

/// Возобновить поток (Suspended -> Ready, в очередь планировщика).
/// ABI: arg1..2 = ThreadId(lo, hi). Требует TaskTCB домена потока.
pub const THREAD_RESUME: SyscallNumber = SyscallNumber(0x1A);

/// Уступить CPU (L4 yield): немедленный перевыпуск планировщика.
/// Хук `SchedulerInterface::yield_now` (по умолчанию — no-op:
/// кооперативность — опция бекенда). Вызывается для ТЕКУЩЕГО потока.
pub const THREAD_YIELD: SyscallNumber = SyscallNumber(0x1B);

/// L4 thread_ex_regs: сменить точку входа/стек потока (перезапуск,
/// pager-протоколы, отладка). ABI: arg1..2 = ThreadId(lo, hi),
/// arg3 = new entry (-1 = не менять), arg4 = new stack_top (-1 = не
/// менять), arg5 = что вернуть: 0 = прежний entry, 1 = прежний stack.
/// Требует TaskTCB домена потока.
pub const THREAD_EX_REGS: SyscallNumber = SyscallNumber(0x1C);

/// Назначить пределы песочницы задаче (атрибуты GTCB, v0.9).
/// ПРАВО: capability TaskTCB на ЦЕЛЬ. Семантика — трещотка: новые
/// значения только УЖЕСТОЧАЮТ текущие (`TaskLimits::tighten`).
/// ABI: arg1 = хендл TaskTCB цели, arg2 = max_pages,
/// arg3 = max_threads | (max_endpoints << 32),
/// arg4 = max_shm | (max_caps << 32),
/// arg5 = max_prio (u8) | (may_spawn ? 0x100 : 0).
pub const TASK_SET_LIMITS: SyscallNumber = SyscallNumber(0x1D);

/// Снимок атрибутов безопасности задачи (v0.9). ПРАВО: TaskTCB на цель.
/// Слова по индексу: 0 = max_pages, 1 = usage pages, 2 = usage shm,
/// 3 = max_threads | (max_endpoints << 32), 4 = max_shm |
/// (max_caps << 32), 5 = max_prio | (may_spawn ? 0x100 : 0).
/// ABI: arg1 = хендл TaskTCB цели, arg2 = индекс слова.
pub const TASK_LIMITS_INFO: SyscallNumber = SyscallNumber(0x1E);

/// Спавн домена из ГОТОВОГО образа (v0.9): сискол ожидает УЖЕ
/// залинкованный по фиксированным адресам образ, КОПИРОВАННЫЙ
/// юзерспейсом-родителем в собственные регионы (MEM_ALLOC + запись
/// байтов) — ядро принимает ТОЛЬКО указатели на память родителя
/// (дескриптор спавна, сегменты, стек, argv-блок) и мапит готовые
/// кадры в новое пространство без единой пересылки данных.
///
/// Дескриптор (в памяти родителя, little-endian, выравнивание 8):
/// ```text
///   +0x00 u64 entry        точка входа ребёнка (линк-адрес)
///   +0x08 u64 stack_top     вершина стека (THREAD_CREATE-слова)
///   +0x10 u64 thread_id_lo  ThreadId главного потока (мл. слово)
///   +0x18 u64 thread_id_hi  ThreadId главного потока (ст. слово)
///   +0x20 u32 n_segments    число сегментов (1..=16)
///   +0x24 u32 argv_pages    страницы argv-блока (0 = без argv)
///   +0x28 u64 argv_src      адрес argv-блока у РОДИТЕЛЯ
///   +0x30 u64 argv_dst      адрес argv-блока у РЕБЁНКА
///   +0x38 u64 argv_bytes    длина блока (байт)
///   +0x40 u64 argc          argc стартового IPC
///   +0x48 u64 limits[0]     max_pages (TaskLimits)
///   +0x50 u64 limits[1]     max_threads | (max_endpoints << 32)
///   +0x58 u64 limits[2]     max_shm | (max_caps << 32)
///   +0x60 u64 limits[3]     max_prio | (may_spawn ? 0x100 : 0)
///   +0x68 u8  priority      приоритет домена/потока
///   +0x70 сегменты, 32 байта каждый:
///        u64 src   адрес сегмента у РОДИТЕЛЯ (MEM_ALLOC-регион)
///        u64 dst   линк-адрес сегмента у РЕБЁНКА (4K-выровнен)
///        u64 pages страниц
///        u64 flags MMAPMemoryFlags bits (RO/RW/RX)
/// ```
/// ПРАВО: TaskTCB на САМОГО вызывающего (право творца) + may_spawn;
/// лимиты применяются ДО первого потока — ребёнок рождается в
/// песочнице атомарно. Возврат — хендл TaskTCB(ребёнка) у родителя.
/// ABI: arg1 = хендл TaskTCB(себя), arg2..3 = TaskId(lo, hi) нового
/// домена, arg4 = адрес дескриптора у родителя, arg5 = размер
/// дескриптора (байт: 0x70 + 32*n).
pub const TASK_SPAWN_IMAGE: SyscallNumber = SyscallNumber(0x1F);

// ==== 0x20: передача прав capability ====

/// Породить производную capability (сужение perms/badge).
/// ABI: arg1 = хендл источника, arg2..3 = TaskId получателя(lo, hi),
/// arg4 = perms bits, arg5 = badge bits.
pub const CAP_MINT: SyscallNumber = SyscallNumber(0x21);

/// Передать capability (transfer, право Send у источника).
/// ABI: arg1 = хендл источника, arg2..3 = TaskId получателя(lo, hi).
pub const CAP_SEND: SyscallNumber = SyscallNumber(0x22);

/// Отозвать capability со всем поддеревом производных.
/// ABI: arg1 = хендл. Возврат: число погашенных слотов.
pub const CAP_REVOKE: SyscallNumber = SyscallNumber(0x23);

/// Удалить один хендл (дерево перепривязывается).
/// ABI: arg1 = хендл.
pub const CAP_DELETE: SyscallNumber = SyscallNumber(0x24);

/// Обход cspace вызывающего (менеджеры задач/устройств находят
/// выданные ядром хендлы). Слова по индексу: 0 = число занятых
/// слотов; далее ПО ОДНОМУ слову на слот: (kind << 32) | handle_bits.
/// kind: 1 = DeviceReference, 2 = TaskTCB, 3 = Gate, 4 = Irq.
/// ABI: arg1 = индекс слова.
pub const CAP_LIST: SyscallNumber = SyscallNumber(0x25);

/// Снимок capability по хендлу. Слова по индексу: 0 = kind (как у
/// CAP_LIST), 1 = perms, 2 = badge (64 бита), 3 = alive(1/0),
/// 4..5 = идентификация: TaskTCB -> TaskId(lo, hi); Gate -> (obj_id, 0);
/// Irq -> (gsi, obj_id); DeviceReference -> (компактное слово пути
/// DEVICE_ENUM-кодировки, 0). ABI: arg1 = хендл, arg2 = индекс слова.
pub const CAP_INFO: SyscallNumber = SyscallNumber(0x26);

// ==== 0x30: IPC ====

/// Создать endpoint. ABI: arg1 = ёмкость буфера (0 = строгий
/// rendezvous L4, > 0 = notification-канал). Возврат: хендл.
pub const EP_CREATE: SyscallNumber = SyscallNumber(0x31);

/// Отправка в endpoint (блокирующая, L4). ABI: arg1 = хендл,
/// arg2..4 = до 3 inline-слов, arg5 = флаги (bit0 = try).
/// Блокировка: возврат материализуется при встрече (syscall_ret).
pub const IPC_SEND: SyscallNumber = SyscallNumber(0x32);

/// Приём из endpoint (блокирующая). ABI: arg1 = хендл, arg2 = флаги
/// (bit0 = try). Возврат: слово 0 сообщения (остальные — IPC_MSG_WORD).
pub const IPC_RECV: SyscallNumber = SyscallNumber(0x33);

/// L4 ipc_call: отправка + ожидание ответа на reply-endpoint без
/// возврата в пользователя между фазами. ABI: arg1 = хендл endpoint'а
/// назначения, arg2 = хендл reply-endpoint'а, arg3..4 = до 2 слов,
/// arg5 = флаги (bit0 = try).
pub const IPC_CALL: SyscallNumber = SyscallNumber(0x34);

/// Fast-path L4: прямая отправка потоку по глобальному ThreadID.
/// Получатель в open-receive — мгновенная доставка; иначе сообщение
/// паркуется в очереди потока (до IPC_THREAD_PARK_MAX). Отправитель
/// не блокируется. ABI: arg1..2 = ThreadId(lo, hi), arg3..4 = слова,
/// arg5 = число слов (0..=2).
pub const IPC_SEND_THREAD: SyscallNumber = SyscallNumber(0x35);

/// Открытый приём (L4 open receive): от любого отправителя.
/// ABI: arg1 = флаги (bit0 = try). Возврат: слово 0.
pub const IPC_RECV_ANY: SyscallNumber = SyscallNumber(0x36);

/// Слово сообщения из почтового ящика потока (inline + payload,
/// сквозная индексация). ABI: arg1 = индекс.
pub const IPC_MSG_WORD: SyscallNumber = SyscallNumber(0x37);

/// Размер сообщения в ящике и статус: `(status_bits << 32) | слов`.
/// Status: bit0 = ITEM_ERRORS (flexpage-элементы пропущены),
/// bit1 = FAST_PATH.
pub const IPC_MSG_LEN: SyscallNumber = SyscallNumber(0x38);

/// Очистить почтовый ящик (следующий recv — с чистого листа).
pub const IPC_MSG_CLEAR: SyscallNumber = SyscallNumber(0x39);

/// Однословный signal в endpoint (doorbell/уведомления): ядро не
/// блокируется, буфер обязан иметь ёмкость. ABI: arg1 = хендл,
/// arg2 = слово.
pub const NOTIFY_SIGNAL: SyscallNumber = SyscallNumber(0x3A);

// ==== 0x40: устройства и IRQ ====

/// Эксклюзивный захват устройства (одна задача одновременно).
/// Требует DeviceReference capability. ABI: arg1 = хендл устройства,
/// arg2 = флаги (bit0 = try), arg3 = хендл notify-endpoint (0 — без
/// уведомлений о потере). Возврат: 0; блокировка — при занятости.
pub const DEVICE_CLAIM: SyscallNumber = SyscallNumber(0x41);

/// Отпустить лок (владелец). ABI: arg1 = хендл устройства.
pub const DEVICE_RELEASE: SyscallNumber = SyscallNumber(0x42);

/// Статус лока слова́ми (по индексу, как DEVICE_INFO):
/// 0 = занятость (1 = owner есть), 1..2 = owner(lo, hi),
/// 3 = waiters, 4 = gone. ABI: arg1 = хендл, arg2 = индекс.
pub const DEVICE_CLAIM_STATUS: SyscallNumber = SyscallNumber(0x43);

/// Обзор реестра живых устройств (devmon: связывает устройства с
/// capability после rescan). Слова по индексу: 0 = число живых;
/// далее по 4 слова на устройство: (kind, path_w0, path_w1, flags).
/// kind: 1 = Pci, 2 = Acpi, 3 = StreamId, 4 = Dt.
/// Pci: path_w0 = bdf-биты; StreamId: (iommu, id); Acpi/Dt:
/// (длина пути, FNV-1a хэш) — полный путь только в DeviceReference
/// (см. CAP_INFO). flags: bit0 = msi. ABI: arg1 = индекс слова.
pub const DEVICE_ENUM: SyscallNumber = SyscallNumber(0x44);

/// Отобразить ресурс устройства (MMIO BAR) в пространство вызывающего
/// (zero-copy, кадры не из пула). Требует DeviceReference + claim
/// устройства вызывающим. ABI: arg1 = хендл устройства,
/// arg2 = индекс ресурса (порядок `DeviceRecord::resources`).
/// Возврат: виртуальный адрес.
pub const DEVICE_MAP_REGION: SyscallNumber = SyscallNumber(0x45);

/// Привязать IRQ устройства к notify-endpoint'у (L4 irq_attach):
/// прерывание становится signal-сообщением в endpoint (word = gsi),
/// драйвер ждёт обычным IPC_RECV. Требует DeviceReference; gsi обязан
/// принадлежать ресурсам ЖИВОГО устройства. ABI: arg1 = хендл
/// устройства, arg2 = gsi, arg3 = хендл Gate. Возврат: 0.
pub const IRQ_ATTACH: SyscallNumber = SyscallNumber(0x46);

/// Снять привязку IRQ (владелец). ABI: arg1 = gsi. ABI: arg1 = gsi.
pub const IRQ_DETACH: SyscallNumber = SyscallNumber(0x47);

/// Подтвердить обработку прерывания (EOI-семантика L4): до ACK
/// повторные события копятся одним pending-битом, после — линия
/// снова «взведена». ABI: arg1 = gsi.
pub const IRQ_ACK: SyscallNumber = SyscallNumber(0x48);

// ==== 0x50: память ====

/// Эластичное расширение памяти: выделить регион (страницы + отображение)
/// в пространстве задачи. ABI: arg1 = страниц, arg2 = MMAPMemoryFlags
/// bits. Возврат: виртуальный адрес.
pub const MEM_ALLOC: SyscallNumber = SyscallNumber(0x51);

/// Снять регион по адресу (кадры возвращаются пулу, кроме внешних).
/// ABI: arg1 = адрес.
pub const MEM_FREE: SyscallNumber = SyscallNumber(0x52);

/// Flexpage-перенос (IPC map/grant-элемент как прямой сискол):
/// окно источника в пространство другой задачи. ABI: arg1 = src_vaddr,
/// arg2 = страниц, arg3 = флаги (bit0 = grant), arg4..5 = TaskId
/// получателя(lo, hi). Возврат: адрес у получателя.
pub const MEM_TRANSFER: SyscallNumber = SyscallNumber(0x53);

/// Регион по адресу (аудит рантайма, pager'ы). Слова по индексу:
/// 0 = база виртуальная, 1 = база физики, 2 = страниц, 3 = 0
/// (зарезервировано: external-флаг). ABI: arg1 = адрес, arg2 = индекс.
pub const MEM_INFO: SyscallNumber = SyscallNumber(0x54);

/// Отобразить СВОИ страницы по ФИКСИРОВАННОМУ адресу в пространстве
/// ДРУГОЙ задачи (spawn-протокол: родитель грузит ELF/стек/argv
/// ребёнка; v0.9). ПРАВО: capability TaskTCB на цель — без него
/// отобразить память в чужой домен нельзя. Страницы зарядаются
/// пределу ЦЕЛИ (песочница), у источника окно остаётся (кадры —
/// собственность источника до MEM_FREE, L4 pager-модель).
/// ABI: arg1 = хендл TaskTCB цели, arg2 = src_vaddr (адрес в
/// пространстве вызывающего), arg3 = страниц, arg4 = dst_vaddr
/// (адрес в пространстве цели), arg5 = MMAPMemoryFlags bits.
/// Возврат: dst_vaddr.
pub const MEM_MAP_AT: SyscallNumber = SyscallNumber(0x55);

// ==== 0x60: разделяемая память io_uring ====

/// Создать SHM-регион (кадры из физического пула, zero-copy).
/// ABI: arg1 = страниц. Возврат: ShmId.
pub const SHM_CREATE: SyscallNumber = SyscallNumber(0x61);

/// Настроить SQ/CQ-кольца (io_uring-геометрия). ABI: arg1 = ShmId,
/// arg2 = sq_entries, arg3 = cq_entries, arg4 = слов на слот.
/// Возврат: смещение SQ (слова); полная геометрия — SHM_INFO.
pub const SHM_SETUP_RING: SyscallNumber = SyscallNumber(0x62);

/// Привязать doorbell-endpoint (signal при submit). ABI: arg1 = ShmId,
/// arg2 = хендл Gate.
pub const SHM_BIND_DOORBELL: SyscallNumber = SyscallNumber(0x63);

/// Отобразить регион в пространство задачи (zero-copy: обе стороны
/// работают с кольцами напрямую). ABI: arg1 = ShmId, arg2 = флаги
/// прав. Возврат: виртуальный адрес.
pub const SHM_MAP: SyscallNumber = SyscallNumber(0x64);

/// Разрушить регион (кадры в пул; отображения снимает платформа).
/// ABI: arg1 = ShmId.
pub const SHM_DESTROY: SyscallNumber = SyscallNumber(0x65);

/// Doorbell: сигнал производителю->потребителю после submit SQE.
/// ABI: arg1 = ShmId, arg2 = слово (например, новый sq_tail).
pub const RING_DOORBELL: SyscallNumber = SyscallNumber(0x66);

/// Информация о регионе по индексу слова (как DEVICE_INFO):
/// 0 = страниц, 1 = база физики, 2 = sq_off, 3 = sq_entries,
/// 4 = cq_off, 5 = cq_entries, 6 = entry_words, 7 = total_words,
/// 8 = doorbell (ObjId bits, 0 — нет), 9..10 = owner(lo, hi).
/// ABI: arg1 = ShmId, arg2 = индекс.
pub const SHM_INFO: SyscallNumber = SyscallNumber(0x67);

// ==== 0x70: отладка ====

/// Вывод в консоль отладки (до 40 байт за вызов: arg1..5 = слова).
pub const DEBUG_WRITE: SyscallNumber = SyscallNumber(0x71);

/// Дамп задач по индексу слова: 0 = число задач; далее по 4 слова на
/// задачу (id lo, id hi, state, priority). ABI: arg1 = индекс.
pub const DEBUG_DUMP_TASKS: SyscallNumber = SyscallNumber(0x72);

/// Трассировка сисколов вкл/выкл (в debug-консоль).
/// ABI: arg1 = 0/1. Возврат: прежнее состояние.
pub const DEBUG_TRACE: SyscallNumber = SyscallNumber(0x73);

/// Дамп потоков задачи по индексу слова: 0 = число потоков; далее по
/// 6 слов на поток (id lo, hi, owner lo, hi, state, priority).
/// ABI: arg1..2 = TaskId(lo, hi), arg3 = индекс.
pub const DEBUG_DUMP_THREADS: SyscallNumber = SyscallNumber(0x74);

// ==== 0x80: IOMMU / DMA-ремаппинг (v0.6) ====
// Сервис — IommuService (установка платформой; без него — ENOSYS).

/// Обзор IOMMU-подсистемы. ABI: arg1 = индекс контроллера,
/// 0xFFFF_FFFF — число контроллеров; arg2 = 0 -> флаги (bit0 agaw48,
/// bit1 queued_inval, bit2 pass_through, bit3 include_all; mgaw << 8),
/// arg2 = 1 -> версию ((major<<8)|minor).
pub const IOMMU_ENUM: SyscallNumber = SyscallNumber(0x80);

/// Привязать устройство (BDF) к контроллеру: домен изоляции + DeviceId.
/// ABI: arg1 = контроллер, arg2 = bus, arg3 = device, arg4 = function.
pub const IOMMU_ATTACH: SyscallNumber = SyscallNumber(0x81);

/// Отобразить физические страницы в IOVA-пространство устройства.
/// ABI: arg1 = контроллер, arg2 = DeviceId, arg3 = iova (4K-выровнен),
/// arg4 = phys (4K-выровнен), arg5 = pages | (prot << 32)
/// (prot: bit0 READ, bit1 WRITE, bit2 CACHE).
pub const IOMMU_MAP: SyscallNumber = SyscallNumber(0x82);

/// Снять IOVA-отображение. ABI: arg1 = контроллер, arg2 = DeviceId,
/// arg3 = iova, arg4 = pages.
pub const IOMMU_UNMAP: SyscallNumber = SyscallNumber(0x83);

/// Отвязать устройство (контекст гасится, таблицы домена — в пул).
/// ABI: arg1 = контроллер, arg2 = DeviceId.
pub const IOMMU_DETACH: SyscallNumber = SyscallNumber(0x84);

/// Запрограммировать IRTE (IRQ-ремаппинг, v0.8): remapped-запись
/// прерывания устройства (vector/dest) в таблице контроллера.
/// ABI: arg1 = контроллер, arg2 = DeviceId, arg3 = vector (0x10..0xFE),
/// arg4 = APIC-destination (u8; физический APIC ID), arg5 = флаги
/// (bit0 = level-triggered, bit1 = logical destination mode).
/// Возврат: handle (индекс IRTE) — драйвер устройства кладёт его в
/// MSI-адрес (Intel: SHV=0 handle=индекс; AMD: индекс в per-device
/// таблице). 0 — «нет handle» и не выдаётся.
pub const IOMMU_IRQ_MAP: SyscallNumber = SyscallNumber(0x85);

/// Погасить IRTE по handle (прерывание снова не ремапится).
/// ABI: arg1 = контроллер, arg2 = DeviceId, arg3 = handle из IRQ_MAP.
pub const IOMMU_IRQ_UNMAP: SyscallNumber = SyscallNumber(0x86);
