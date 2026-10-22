/* ==== l4.h: C-интерфейс rust-l4 (userlib, v0.8) ====
 *
 * Userspace-интероп с ядром rust-l4: обёртки сисколов (l4_*) + стартовый
 * протокол. Библиотека libuserlib.a (крейт crates/userlib) экспортирует
 * _start и все функции ниже; линкуется в прикладной образ БЕЗ libc:
 *
 *   gcc -O2 -Wall -ffreestanding -fno-stack-protector -fno-pie \
 *       -I crates/userlib/include -c app.c -o app.o
 *   gcc -nostdlib -static -no-pie -Wl,-T,crates/init/init.ld \
 *       -Wl,--build-id=none app.o libuserlib.a -o app
 *
 * Протокол запуска (L4): ядро грузит статический ELF по фиксированным
 * линк-адресам (0x40000000; см. init.ld), обнуляет BSS, ставит стек и
 * паркует стартовое IPC в очередь потока; _start (в библиотеке) принимает
 * его, разбирает argv-блок и вызывает прикладной main(argc, argv):
 *
 *   int main(int argc, char **argv);   // argv[0] = имя модуля;
 *                                      // хвост = <arg> из boot_cfg.xml
 *                                      // + boot_state «имя=значение».
 *
 * Возврат из main — TASK_EXIT(код & 0xFF). Смерть домена: ядро гасит
 * потоки и печатает «all user threads gone — halting».
 *
 * Соглашения: все функции возвращают int64_t; значения >= 0 — успех,
 * отрицательные — errno-подобные коды (см. main.rs ядра: ENOSYS=-38,
 * ENOMEM=-12, EEXIST=-17, EINVAL=-22, ENODEV=-19, ENOTSUP=-95...).
 * Аргументы u64 — 64-битные без знака.
 */

#ifndef L4_H
#define L4_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ─────────────── 0x00: система ─────────────── */

/* SELF_INFO(0x03): идентификация себя. Слова по индексу:
 * 0 = task_id.lo, 1 = task_id.hi, 2 = thread_id.lo, 3 = thread_id.hi,
 * 4 = cpu (номер CPU потока), 5 = cpu_count, 6 = TLS-слово потока
 * (v0.17; l4_tls_word() — обёртка). */
int64_t l4_self_info(uint64_t index);

/* SYS_TIME(0x04): монотонные часы ядра, наносекунды. */
int64_t l4_sys_time(void);

/* ─────────────── 0x10: задачи и потоки ─────────────── */

/* TASK_SPAWN(0x01): легаси-создание задачи БЕЗ capability-проверки. */
int64_t l4_task_spawn(uint64_t id_lo, uint64_t id_hi, uint64_t prio);

/* TASK_CREATE(0x10): задача-домен (cspace + адресное пространство);
 * требует capability TaskTCB на САМОГО ВЫЗЫВАЮЩЕГО (грант kinit,
 * находится через l4_cap_list: kind = 2). */
int64_t l4_task_create(uint64_t tcb, uint64_t id_lo, uint64_t id_hi,
                       uint64_t prio);

/* TASK_SET_EXIT_EP(0x11): exit-endpoint задачи (доставка ExitPayload). */
int64_t l4_task_set_exit_ep(uint64_t gate);

/* TASK_EXIT(0x12): само-выход задачи с кодом. НЕ возвращается. */
__attribute__((noreturn)) void l4_task_exit(uint64_t code);

/* TASK_KILL(0x13): убить задачу (право TaskTCB на цель). */
int64_t l4_task_set_limits(uint64_t tcb, uint64_t max_pages,
                            uint64_t threads_eps, uint64_t shm_caps,
                            uint64_t prio_spawn);
int64_t l4_task_limits_info(uint64_t tcb, uint64_t index);
int64_t l4_task_spawn_image(uint64_t tcb_self, uint64_t id_lo,
                            uint64_t id_hi, uint64_t desc_ptr,
                            uint64_t desc_bytes);
int64_t l4_task_kill(uint64_t tcb);

/* THREAD_CREATE(0x15): поток в домене (L4 thread_control).
 * tid назначает вызывающий; entry получает нулевые регистры. */
int64_t l4_thread_create(uint64_t tcb, uint64_t entry,
                         uint64_t stack_top, uint64_t tid);

/* THREAD_CREATE(0x15) с начальным TLS-словом (v0.17): поток рождается
 * с готовым указателем потока (на x86_64 — FS base; доступ из C —
 * __thread-модели на %fs, или читай слово: l4_tls_word()). Без гонки
 * «создал -> выставил»: свежий поток может уйти на другой CPU раньше
 * последующего l4_thread_set_tls. */
int64_t l4_thread_create_tls(uint64_t tcb, uint64_t entry,
                             uint64_t stack_top, uint64_t tid, uint64_t tls);

/* THREAD_SET_TLS(0x91, v0.17): назначить потоку TLS-слово (непрозрачное
 * для ядра; грузится в регистр указателя потока при каждой
 * диспетчеризации). Право: свой домен или TaskTCB домена потока.
 * Возврат: ПРЕЖНЕЕ слово. */
int64_t l4_thread_set_tls(uint64_t tid_lo, uint64_t tid_hi, uint64_t value);

/* TLS-слово ТЕКУЩЕГО потока (SELF_INFO, индекс 6; v0.17).
 * Рекомендуемая конвенция TCB-блока: слово по смещению 0 от базового
 * указателя = сам указатель (self-relative, как glibc_tcbhead->tcb);
 * тогда l4_tls_word() == *(uint64_t *)l4_tls_word(). */
int64_t l4_tls_word(void);

/* THREAD_DESTROY(0x16): разрушить TCB завершённого потока. */
int64_t l4_thread_destroy(uint64_t tid_lo, uint64_t tid_hi);

/* THREAD_TERMINATE(0x17): поток в Dead (принудительное гашение). */
int64_t l4_thread_terminate(uint64_t tid_lo, uint64_t tid_hi);

/* THREAD_SET_PRIO(0x18): приоритет задачи/потока. */
int64_t l4_thread_set_prio(uint64_t id_lo, uint64_t id_hi, uint64_t prio);

/* THREAD_SUSPEND(0x19): приостановить поток (себя — тоже). */
int64_t l4_thread_suspend(uint64_t tid_lo, uint64_t tid_hi);

/* THREAD_RESUME(0x1A): возобновить поток. */
int64_t l4_thread_resume(uint64_t tid_lo, uint64_t tid_hi);

/* THREAD_YIELD(0x1B): уступить CPU (L4 yield). */
int64_t l4_thread_yield(void);

/* THREAD_EX_REGS(0x1C): сменить entry/стек потока (-1 = не менять);
 * what: 0 = вернуть прежний entry, 1 = прежний stack. */
int64_t l4_thread_ex_regs(uint64_t tid_lo, uint64_t tid_hi,
                          uint64_t entry, uint64_t stack_top, uint64_t what);

/* ─────────────── 0x20: capability ─────────────── */

/* CAP_MINT(0x21): производная capability (сужение perms/badge). */
int64_t l4_cap_mint(uint64_t src, uint64_t dst_lo, uint64_t dst_hi,
                    uint64_t perms, uint64_t badge);

/* CAP_MINT_RANGE(0x27, v0.15): производная IoResource-возможности со
 * сужением ПОДДИАПАЗОНА: base..base+len обязан лежать строго внутри
 * родительского диапазона той же разновидности (иначе RangeNotSubset).
 * Первый пользователь шестого аргумента ABI (a6). */
int64_t l4_cap_mint_range(uint64_t src, uint64_t dst_lo, uint64_t dst_hi,
                          uint64_t perms, uint64_t new_base, uint64_t new_len);

/* CAP_SEND(0x22): передать capability (право Send у источника). */
int64_t l4_cap_send(uint64_t src, uint64_t dst_lo, uint64_t dst_hi);

/* CAP_REVOKE(0x23): отозвать со всем поддеревом (возврат — погашено). */
int64_t l4_cap_revoke(uint64_t src);

/* CAP_DELETE(0x24): удалить один хендл. */
int64_t l4_cap_delete(uint64_t src);

/* CAP_LIST(0x25): обход cspace. Слово 0 = число слотов; далее по ДВА
 * слова на слот: [1+2i] = handle_bits, [2+2i] = kind
 * (1 = DeviceReference, 2 = TaskTCB, 3 = Gate, 4 = Irq). */
int64_t l4_cap_list(uint64_t index);

/* CAP_INFO(0x26): снимок capability (kind/perms/badge/alive/...). */
int64_t l4_cap_info(uint64_t handle, uint64_t index);

/* ─────────────── 0x30: IPC ─────────────── */

/* EP_CREATE(0x31): создать endpoint (0 = строгий rendezvous L4,
 * > 0 = ёмкость notification-канала). Возврат: хендл. */
int64_t l4_ep_create(uint64_t capacity);

/* IPC_SEND(0x32): блокирующая отправка (до 3 inline-слов);
 * flags: bit0 = try. Возврат материализуется при встрече. */
int64_t l4_ipc_send(uint64_t ep, uint64_t w0, uint64_t w1, uint64_t w2,
                    uint64_t flags);

/* IPC_RECV(0x33): блокирующий приём из endpoint. Возврат: слово 0
 * сообщения (остальные — l4_ipc_msg_word). */
int64_t l4_ipc_recv(uint64_t ep, uint64_t flags);

/* IPC_CALL(0x34): L4 ipc_call: отправка + ожидание ответа. */
int64_t l4_ipc_call(uint64_t ep, uint64_t reply_ep, uint64_t w0,
                    uint64_t w1, uint64_t flags);

/* IPC_SEND_THREAD(0x35): fast-path отправка потоку по ThreadID. */
int64_t l4_ipc_send_thread(uint64_t tid_lo, uint64_t tid_hi, uint64_t w0,
                           uint64_t w1, uint64_t words);

/* IPC_RECV_ANY(0x36): открытый приём (L4 open receive). Возврат:
 * слово 0 сообщения. */
int64_t l4_ipc_recv_any(uint64_t flags);

/* IPC_MSG_WORD(0x37): слово сообщения из почтового ящика (сквозная
 * индексация inline + payload). */
int64_t l4_ipc_msg_word(uint64_t index);

/* IPC_MSG_LEN(0x38): (status_bits << 32) | слов; status: bit0 =
 * ITEM_ERRORS, bit1 = FAST_PATH. */
int64_t l4_ipc_msg_len(void);

/* IPC_MSG_CLEAR(0x39): очистить почтовый ящик. */
int64_t l4_ipc_msg_clear(void);

/* NOTIFY_SIGNAL(0x3A): однословный signal (doorbell); буфер endpoint'а
 * обязан иметь ёмкость. */
int64_t l4_notify_signal(uint64_t ep, uint64_t word);

/* ───────── Футеки (v0.17): юзерспейс-мьютексы/condvar/барьеры ───────── */

/* FUTEX_WAIT(0x3B): уснуть на 32-битном слове (uaddr выровнен на 4),
 * если текущее значение == expected. Ключ — ФИЗИЧЕСКИЙ адрес слова:
 * футеки одного кадра общие для всех задач, куда он отображён
 * (SHM/transfer/map_at); приватная память изолирована по построению.
 * Возвраты: 0 — разбужден (l4_futex_wake); -11 EAGAIN — значение
 * изменилось (без сна или в окне парка — потерянных пробуждений нет).
 * Таймаута нет (v1): таймер-сервер юзерспейса будит l4_futex_wake. */
int64_t l4_futex_wait(uint64_t uaddr, uint32_t expected);

/* FUTEX_WAKE(0x3C): разбудить до count ждущих на слове с тем же
 * физическим адресом. Возврат — число разбужденных. Дисциплина
 * «изменил слово -> разбуди» — на приложении (ядро значение не
 * читает, как в Linux). */
int64_t l4_futex_wake(uint64_t uaddr, uint32_t count);

/* ───── 0x40: сырые ресурсы (IoResource) и IRQ (v0.14) ───── */
/* «Устройств в ядре нет» (v0.14): доступ к физике/портам/линиям
 * гейтован IoResource-capability; перечисление (ACPI/AML/PCI) и
 * драйверы — юзерспейс (acpid). */

/* MMIO_MAP(0x41): отобразить физический диапазон (Mmio-cap); кадры
 * внешние (снятие — l4_mem_free(base_vaddr)). Возврат: байто-точный
 * виртуальный адрес. */
int64_t l4_mmio_map(uint64_t mmio_cap, uint64_t off, uint64_t pages, uint64_t flags);

/* IOP_IN(0x42): чтение из I/O-порта (in исполняет ядро за IoPort-cap;
 * width = 1|2|4). Возврат: значение. */
int64_t l4_iop_in(uint64_t io_cap, uint64_t off, uint64_t width);

/* IOP_OUT(0x43): запись в I/O-порт (width = 1|2|4). */
int64_t l4_iop_out(uint64_t io_cap, uint64_t off, uint64_t width, uint64_t value);

/* IRQ_ATTACH(0x46): привязать внешнюю линию (GSI) за Irq-cap к
 * notify-endpoint'у (прерывание = signal, word = gsi). flags: bit0 =
 * level, bit1 = active_low (подсказка; MADT-ISO каноничнее). */
int64_t l4_irq_attach(uint64_t irq_cap, uint64_t gsi, uint64_t gate, uint64_t flags);

/* IRQ_DETACH(0x47): снять привязку IRQ (владелец). */
int64_t l4_irq_detach(uint64_t gsi);

/* IRQ_ACK(0x48): подтвердить обработку (EOI-семантика L4). */
int64_t l4_irq_ack(uint64_t gsi);

/* ─────────────── 0x50: память ─────────────── */

/* MEM_ALLOC(0x51): выделить регион (страницы + отображение).
 * flags: MMAPMemoryFlags bits (READ|WRITE = 0b011). Возврат: vaddr. */
int64_t l4_mem_alloc(uint64_t pages, uint64_t flags);

/* MEM_FREE(0x52): снять регион по адресу (кадры — пулу). */
int64_t l4_mem_free(uint64_t addr);

/* MEM_TRANSFER(0x53): flexpage-перенос окна в другую задачу
 * (flags: bit0 = grant). Возврат: адрес у получателя. */
int64_t l4_mem_transfer(uint64_t src_vaddr, uint64_t pages, uint64_t flags,
                        uint64_t dst_lo, uint64_t dst_hi);

/* MEM_INFO(0x54): регион по адресу (0 = vbase, 1 = pbase, 2 = страниц). */
int64_t l4_mem_map_at(uint64_t tcb_dst, uint64_t src,
                              uint64_t pages, uint64_t dst, uint64_t flags);
int64_t l4_mem_info(uint64_t addr, uint64_t index);

/* MEM_PROTECT(0x56, v0.17): сменить права СВОИХ отображённых страниц
 * (mprotect-аналог; W^X действует: RWX отклоняется). Окно
 * [addr, addr+pages*4K) — в одном регионе; разделяемые кадры у ДРУГИХ
 * задач сохраняют их права (per-mapping семантика). flags — как у
 * l4_mem_alloc (READ|WRITE = 0b011, READ|EXEC = 0b101). */
int64_t l4_mem_protect(uint64_t addr, uint64_t pages, uint64_t flags);

/* ─────────────── 0x60: SHM / io_uring ─────────────── */

/* SHM_CREATE(0x61): создать SHM-регион. Возврат: ShmId. */
int64_t l4_shm_create(uint64_t pages);

/* SHM_SETUP_RING(0x62): настроить SQ/CQ-кольца (io_uring-геометрия).
 * Возврат: смещение SQ (в словах); полная геометрия — l4_shm_info. */
int64_t l4_shm_setup_ring(uint64_t shm, uint64_t sq_entries,
                          uint64_t cq_entries, uint64_t words_per_slot);

/* SHM_BIND_DOORBELL(0x63): привязать doorbell-endpoint (signal при
 * submit). */
int64_t l4_shm_bind_doorbell(uint64_t shm, uint64_t gate);

/* SHM_MAP(0x64): отобразить регион (zero-copy кольца с обеих сторон).
 * Возврат: виртуальный адрес. */
int64_t l4_shm_map(uint64_t shm, uint64_t flags);

/* SHM_DESTROY(0x65): разрушить регион (кадры в пул). */
int64_t l4_shm_destroy(uint64_t shm);

/* RING_DOORBELL(0x66): сигнал производителю->потребителю после
 * submit SQE (word = новый sq_tail). */
int64_t l4_ring_doorbell(uint64_t shm, uint64_t word);

/* SHM_INFO(0x67): информация о регионе по индексу слова. */
int64_t l4_shm_info(uint64_t shm, uint64_t index);

/* ─────────────── 0x70: отладка ─────────────── */

/* DEBUG_WRITE(0x71): вывод в консоль отладки (до 40 байт = 5 слов
 * little-endian за вызов). */
int64_t l4_debug_write(uint64_t w0, uint64_t w1, uint64_t w2, uint64_t w3,
                      uint64_t w4);

/* DEBUG_DUMP_TASKS(0x72): дамп задач по индексу слова. */
int64_t l4_debug_dump_tasks(uint64_t index);

/* DEBUG_TRACE(0x73): трассировка сисколов вкл/выкл (возврат — прежнее). */
int64_t l4_debug_trace(uint64_t on);

/* DEBUG_DUMP_THREADS(0x74): дамп потоков задачи. */
int64_t l4_debug_dump_threads(uint64_t task_lo, uint64_t task_hi,
                              uint64_t index);

/* ─────────────── 0x80: IOMMU / DMA-ремаппинг ─────────────── */

/* IOMMU_ENUM(0x80): ctrl = 0xFFFFFFFF — число контроллеров; иначе
 * слова по word: 0 = флаги | (mgaw << 8)  [bit0 agaw48, bit1
 * queued_inval, bit2 pass_through, bit3 include_all, bit4 irq_remap,
 * bit5 large_pages], 1 = версия ((major<<8)|minor). */
int64_t l4_iommu_enum(uint64_t ctrl, uint64_t word);

/* IOMMU_ATTACH(0x81): BDF -> DeviceId (домен изоляции). Идемпотентно. */
int64_t l4_iommu_attach(uint64_t ctrl, uint64_t bus, uint64_t device,
                        uint64_t function);

/* IOMMU_MAP(0x82): физические страницы -> IOVA. packed = pages |
 * (prot << 32); prot: bit0 READ, bit1 WRITE. 2 МиБ-выровненный
 * диапазон кратных 512 страниц ложится huge-листом (v0.8). */
int64_t l4_iommu_map(uint64_t ctrl, uint64_t device, uint64_t iova,
                     uint64_t phys, uint64_t packed);

/* IOMMU_UNMAP(0x83): снять IOVA-диапазон (точное совпадение с MAP). */
int64_t l4_iommu_unmap(uint64_t ctrl, uint64_t device, uint64_t iova,
                       uint64_t pages);

/* IOMMU_DETACH(0x84): отвязать устройство (таблицы домена — в пул). */
int64_t l4_iommu_detach(uint64_t ctrl, uint64_t device);

/* IOMMU_IRQ_MAP(0x85): запрограммировать IRTE (IRQ-ремаппинг, v0.8).
 * vector: 0x10..0xFE; dest: физический APIC ID; flags: bit0 =
 * level-triggered, bit1 = logical DM. Возврат: handle (индекс IRTE,
 * >0) — его несёт MSI-адрес устройства. Без включённого IR на
 * контроллере — -EOPNOTSUPP (RemappingDisabled). */
int64_t l4_iommu_irq_map(uint64_t ctrl, uint64_t device, uint64_t vector,
                         uint64_t dest, uint64_t flags);

/* IOMMU_IRQ_UNMAP(0x86): погасить IRTE по handle. */
int64_t l4_iommu_irq_unmap(uint64_t ctrl, uint64_t device, uint64_t handle);

/* ─────────────── Консольные хелперы ─────────────── */

/* Порция DEBUG_WRITE из байтов (обрезается до 40). */
void l4_debug_write_bytes(const uint8_t *bytes, uint64_t len);

/* Печать ASCIIZ-строки + CRLF. */
void l4_puts(const char *s);

/* Печать префикса + 0x%016x + CRLF. */
void l4_puthex(const char *prefix, uint64_t v);

#ifdef __cplusplus
}
#endif

#endif /* L4_H */
