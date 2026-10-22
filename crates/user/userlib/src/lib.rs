// ==== userlib: C-ABI интероп-библиотека пользователя (v0.8) ====
//
// Мост между ABI ядра rust-l4 и приложениями/серверами на C (и любом
// языке с C-линковкой). Библиотека собирается staticlib'ом под
// x86_64-unknown-none и линкуется В прикладной образ (-nostdlib):
//
//   * `_start` — точка входа (символ init.ld / ELF entry). Протокол
//     запуска L4: ядро паркует стартовое IPC (argc, argv_ptr,
//     argv_bytes) в очередь потока; _start принимает его, разбирает
//     argv-блок ([u64 argc][u64 ptr[argc]]..[NULL][pad][asciiz]) и
//     вызывает прикладной `main(argc, argv)`; возврат из main —
//     TASK_EXIT(code). BSS/стек/argv-блок готовит ядро (elfload).
//
//   * `l4_*` — обёртки сисколов (номера — syscall/nums.rs ядра, ABI:
//     rax = номер; rdi/rsi/rdx/r10/r8/r9 = аргументы; возврат rax).
//     Полная таблица групп 0x00..0x80: система, задачи/потоки,
//     capability, IPC, устройства/IRQ, память, SHM/io_uring, отладка,
//     IOMMU (ENUM/ATTACH/MAP/UNMAP/DETACH/IRQ_MAP/IRQ_UNMAP).
//
//   * Хелперы консоли: l4_debug_write (≤40 байт за вызов), l4_puts,
//     l4_puthex — те же порции DEBUG_WRITE, что у init.
//
// C-заголовок — include/l4.h (для C-приложений); examples/capp.c —
// референс C-сервера (сборка: scripts/build.sh, грузится boot_cfg.xml).

#![no_std]
#![allow(clippy::missing_safety_doc)]

use core::arch::asm;

// ───────────────────────── Syscall ABI (x86_64) ─────────────────────────

/// Сырой syscall: rax = номер; rdi, rsi, rdx, r10, r8, r9 = аргументы.
#[inline(always)]
pub unsafe fn l4_syscall6(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1, in("rsi") a2, in("rdx") a3,
            in("r10") a4, in("r8") a5, in("r9") a6,
            lateout("rcx") _, lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

// ───────────────────────── Точка входа ─────────────────────────

/// Прикладной main: определяется ПРОГРАММОЙ (C: int main(void) или
/// int main(int argc, char **argv)).
unsafe extern "C" {
    fn main(argc: i32, argv: *const *const i8) -> i32;
}

/// Точка входа (ELF entry; _start в init.ld): стартовый IPC -> main.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // Стартовое сообщение ядра: слово 0 = argc, 1 = argv_ptr, 2 = bytes.
    let ret = l4_ipc_recv_any(0);
    if ret < 0 {
        // Нет стартового IPC — протокол нарушен; честный выход.
        l4_task_exit(1);
    }
    let argv_ptr = l4_ipc_msg_word(1) as u64 as usize as *const u64;
    if argv_ptr as usize == 0 {
        l4_task_exit(2);
    }
    // SAFETY: argv-блок замаплен ядром (2 страницы под стеком):
    // [u64 argc][u64 ptr[argc]]..[u64 NULL][pad][asciiz-строки].
    let block_argc = unsafe { argv_ptr.read_volatile() } as i32;
    // SAFETY: указатели идут сразу за argc; блок построен ядром.
    let argv = unsafe { argv_ptr.add(1) } as *const *const i8;
    let code = unsafe { main(block_argc, argv) };
    l4_task_exit(code as u64 & 0xFF)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // Паника рантайма — смерть домена (как у init; диагностику ядро
    // напечатает по exit-доставке).
    l4_task_exit(13)
}

// ───────────────────────── 0x00: система ─────────────────────────

/// SELF_INFO(0x03): слова 0/1 = task_id lo/hi, 2/3 = thread_id lo/hi,
/// 4 = cpu, 5 = cpu_count. ABI: arg1 = индекс слова.
#[unsafe(no_mangle)]
pub extern "C" fn l4_self_info(index: u64) -> i64 {
    unsafe { l4_syscall6(0x03, index, 0, 0, 0, 0, 0) }
}

/// SYS_TIME(0x04): монотонные часы ядра, наносекунды.
#[unsafe(no_mangle)]
pub extern "C" fn l4_sys_time() -> i64 {
    unsafe { l4_syscall6(0x04, 0, 0, 0, 0, 0, 0) }
}

// ───────────────────────── 0x10: задачи и потоки ─────────────────────────

/// TASK_SPAWN(0x01): легаси-создание задачи (без capability-проверки).
#[unsafe(no_mangle)]
pub extern "C" fn l4_task_spawn(id_lo: u64, id_hi: u64, prio: u64) -> i64 {
    unsafe { l4_syscall6(0x01, id_lo, id_hi, prio, 0, 0, 0) }
}

/// TASK_CREATE(0x10): задача-домен по хендлу TaskTCB(себя).
#[unsafe(no_mangle)]
pub extern "C" fn l4_task_create(tcb: u64, id_lo: u64, id_hi: u64, prio: u64) -> i64 {
    unsafe { l4_syscall6(0x10, tcb, id_lo, id_hi, prio, 0, 0) }
}

/// TASK_SET_EXIT_EP(0x11): зарегистрировать exit-endpoint задачи.
#[unsafe(no_mangle)]
pub extern "C" fn l4_task_set_exit_ep(gate: u64) -> i64 {
    unsafe { l4_syscall6(0x11, gate, 0, 0, 0, 0, 0) }
}

/// TASK_EXIT(0x12): само-выход задачи с кодом. Не возвращается.
#[unsafe(no_mangle)]
pub extern "C" fn l4_task_exit(code: u64) -> ! {
    unsafe { l4_syscall6(0x12, code, 0, 0, 0, 0, 0) };
    // При живом ядре не возвращается; страховка от бага — крутиться
    // без привилегированных инструкций (hlt в ring3 = #GP).
    loop {
        core::hint::spin_loop();
    }
}

/// TASK_SET_LIMITS(0x1D, v0.9): назначить пределы песочницы задаче
/// (трещотка: только ужесточение). Право: TaskTCB на цель.
#[unsafe(no_mangle)]
pub extern "C" fn l4_task_set_limits(
    tcb: u64,
    max_pages: u64,
    threads_eps: u64,
    shm_caps: u64,
    prio_spawn: u64,
) -> i64 {
    unsafe { l4_syscall6(0x1D, tcb, max_pages, threads_eps, shm_caps, prio_spawn, 0) }
}

/// TASK_LIMITS_INFO(0x1E, v0.9): слово атрибутов безопасности задачи.
/// Право: TaskTCB на цель. Слова: 0 = max_pages, 1 = usage pages,
/// 2 = usage shm, 3 = threads|endpoints<<32, 4 = shm|caps<<32,
/// 5 = prio | may_spawn<<8.
#[unsafe(no_mangle)]
pub extern "C" fn l4_task_limits_info(tcb: u64, index: u64) -> i64 {
    unsafe { l4_syscall6(0x1E, tcb, index, 0, 0, 0, 0) }
}

/// TASK_SPAWN_IMAGE(0x1F, v0.9): спавн домена из ГОТОВОГО образа.
/// Родитель заранее (1) разобрал залинкованный ELF, (2) выделил себе
/// регионы MEM_ALLOC, (3) скопировал сегменты/стек/argv и (4) собрал
/// дескриптор. Ядро принимает ТОЛЬКО указатели и мапит готовые кадры.
/// ABI: (tcb_self, id_lo, id_hi, desc_ptr, desc_bytes). Возврат — хендл
/// TaskTCB(ребёнка). Формат дескриптора — syscall/nums.rs ядра.
#[unsafe(no_mangle)]
pub extern "C" fn l4_task_spawn_image(
    tcb_self: u64,
    id_lo: u64,
    id_hi: u64,
    desc_ptr: u64,
    desc_bytes: u64,
) -> i64 {
    unsafe { l4_syscall6(0x1F, tcb_self, id_lo, id_hi, desc_ptr, desc_bytes, 0) }
}

/// TASK_KILL(0x13): убить задачу по хендлу TaskTCB.
#[unsafe(no_mangle)]
pub extern "C" fn l4_task_kill(tcb: u64) -> i64 {
    unsafe { l4_syscall6(0x13, tcb, 0, 0, 0, 0, 0) }
}

/// THREAD_CREATE(0x15): поток в домене (L4 thread_control).
#[unsafe(no_mangle)]
pub extern "C" fn l4_thread_create(tcb: u64, entry: u64, stack_top: u64, tid: u64) -> i64 {
    unsafe { l4_syscall6(0x15, tcb, entry, stack_top, tid, 0, 0) }
}

/// THREAD_CREATE(0x15) с начальным TLS-словом (v0.17, arg6): поток
/// рождается с готовым указателем потока — рантайм без гонки
/// «создал -> выставил до первого такта» (свежий поток может уйти на
/// другой CPU раньше, чем создатель дойдёт до l4_thread_set_tls).
/// Слово непрозрачно для ядра; на x86_64 бекенд кладёт его в FS base
/// (читай из юзерспейса как %fs:0-относительные данные).
#[unsafe(no_mangle)]
pub extern "C" fn l4_thread_create_tls(
    tcb: u64,
    entry: u64,
    stack_top: u64,
    tid: u64,
    tls: u64,
) -> i64 {
    unsafe { l4_syscall6(0x15, tcb, entry, stack_top, tid, 0, tls) }
}

/// THREAD_SET_TLS(0x91, v0.17): назначить потоку TLS-слово (непрозрачное
/// для ядра; грузится в регистр указателя потока при каждой
/// диспетчеризации). Право: свой домен или TaskTCB домена потока.
/// Возврат: ПРЕЖНЕЕ слово (read-modify-write без SELF_INFO).
#[unsafe(no_mangle)]
pub extern "C" fn l4_thread_set_tls(tid_lo: u64, tid_hi: u64, value: u64) -> i64 {
    unsafe { l4_syscall6(0x91, tid_lo, tid_hi, value, 0, 0, 0) }
}

/// TLS-слово ТЕКУЩЕГО потока (SELF_INFO, слово 6 — единственный
/// «геттер» без нового сискола; v0.17).
#[unsafe(no_mangle)]
pub extern "C" fn l4_tls_word() -> i64 {
    unsafe { l4_syscall6(0x03, 6, 0, 0, 0, 0, 0) }
}

/// THREAD_DESTROY(0x16): разрушить TCB завершённого потока.
#[unsafe(no_mangle)]
pub extern "C" fn l4_thread_destroy(tid_lo: u64, tid_hi: u64) -> i64 {
    unsafe { l4_syscall6(0x16, tid_lo, tid_hi, 0, 0, 0, 0) }
}

/// THREAD_TERMINATE(0x17): поток в Dead (принудительное гашение).
#[unsafe(no_mangle)]
pub extern "C" fn l4_thread_terminate(tid_lo: u64, tid_hi: u64) -> i64 {
    unsafe { l4_syscall6(0x17, tid_lo, tid_hi, 0, 0, 0, 0) }
}

/// THREAD_SET_PRIO(0x18): приоритет задачи/потока.
#[unsafe(no_mangle)]
pub extern "C" fn l4_thread_set_prio(id_lo: u64, id_hi: u64, prio: u64) -> i64 {
    unsafe { l4_syscall6(0x18, id_lo, id_hi, prio, 0, 0, 0) }
}

/// THREAD_SUSPEND(0x19): приостановить поток (себя — тоже).
#[unsafe(no_mangle)]
pub extern "C" fn l4_thread_suspend(tid_lo: u64, tid_hi: u64) -> i64 {
    unsafe { l4_syscall6(0x19, tid_lo, tid_hi, 0, 0, 0, 0) }
}

/// THREAD_RESUME(0x1A): возобновить поток.
#[unsafe(no_mangle)]
pub extern "C" fn l4_thread_resume(tid_lo: u64, tid_hi: u64) -> i64 {
    unsafe { l4_syscall6(0x1A, tid_lo, tid_hi, 0, 0, 0, 0) }
}

/// THREAD_YIELD(0x1B): уступить CPU (L4 yield).
#[unsafe(no_mangle)]
pub extern "C" fn l4_thread_yield() -> i64 {
    unsafe { l4_syscall6(0x1B, 0, 0, 0, 0, 0, 0) }
}

/// THREAD_EX_REGS(0x1C): сменить entry/стек потока (L4 ex_regs).
#[unsafe(no_mangle)]
pub extern "C" fn l4_thread_ex_regs(
    tid_lo: u64,
    tid_hi: u64,
    entry: u64,
    stack_top: u64,
    what: u64,
) -> i64 {
    unsafe { l4_syscall6(0x1C, tid_lo, tid_hi, entry, stack_top, what, 0) }
}

/// THREAD_SET_SLICE_NOTIFY(0x90, v0.16): зарегистрировать ОПЦИОНАЛЬНЫЙ
/// advisory-канал «конец временного промежутка близко» для ТЕКУЩЕГО
/// потока: `gate = 0` — снять регистрацию. Уведомление — kernel-сообщение
/// в гейт: слово 0 = 1 (SLICE_WARN), слово 1 = остаток слайса (TSC).
///
/// Семантика best-effort и НЕ принуждающая: задача вправе игнорировать
/// уведомления (или не регистрироваться) — вытеснение от реакции не
/// зависит. Полный буфер гейта — событие молча теряется до следующего
/// слайса. Требует TSC-deadline режима таймера (QEMU/KVM; в периодическом
/// фолбэке регистрация принимается, доставка не идёт).
#[unsafe(no_mangle)]
pub extern "C" fn l4_thread_slice_notify(gate: u64) -> i64 {
    unsafe { l4_syscall6(0x90, gate, 0, 0, 0, 0, 0) }
}

// ───────────────────────── 0x20: capability ─────────────────────────

/// CAP_MINT(0x21): производная capability (сужение perms/badge).
#[unsafe(no_mangle)]
pub extern "C" fn l4_cap_mint(src: u64, dst_lo: u64, dst_hi: u64, perms: u64, badge: u64) -> i64 {
    unsafe { l4_syscall6(0x21, src, dst_lo, dst_hi, perms, badge, 0) }
}

/// CAP_MINT_RANGE(0x27): производная IoResource-возможности со сужением
/// ПОДДИАПАЗОНА (v0.15): `base..base+len` обязан лежать строго внутри
/// родительского диапазона той же разновидности (иначе RangeNotSubset).
/// Использует ШЕСТОЙ аргумент ABI (a6): SYSCALL_ARG_COUNT=7 с v0.15.
#[unsafe(no_mangle)]
pub extern "C" fn l4_cap_mint_range(
    src: u64,
    dst_lo: u64,
    dst_hi: u64,
    perms: u64,
    new_base: u64,
    new_len: u64,
) -> i64 {
    unsafe { l4_syscall6(0x27, src, dst_lo, dst_hi, perms, new_base, new_len) }
}

/// CAP_SEND(0x22): передать capability.
#[unsafe(no_mangle)]
pub extern "C" fn l4_cap_send(src: u64, dst_lo: u64, dst_hi: u64) -> i64 {
    unsafe { l4_syscall6(0x22, src, dst_lo, dst_hi, 0, 0, 0) }
}

/// CAP_REVOKE(0x23): отозвать capability с поддеревом.
#[unsafe(no_mangle)]
pub extern "C" fn l4_cap_revoke(src: u64) -> i64 {
    unsafe { l4_syscall6(0x23, src, 0, 0, 0, 0, 0) }
}

/// CAP_DELETE(0x24): удалить хендл.
#[unsafe(no_mangle)]
pub extern "C" fn l4_cap_delete(src: u64) -> i64 {
    unsafe { l4_syscall6(0x24, src, 0, 0, 0, 0, 0) }
}

/// CAP_LIST(0x25): обход cspace по индексу слова.
#[unsafe(no_mangle)]
pub extern "C" fn l4_cap_list(index: u64) -> i64 {
    unsafe { l4_syscall6(0x25, index, 0, 0, 0, 0, 0) }
}

/// CAP_INFO(0x26): снимок capability по хендлу.
#[unsafe(no_mangle)]
pub extern "C" fn l4_cap_info(handle: u64, index: u64) -> i64 {
    unsafe { l4_syscall6(0x26, handle, index, 0, 0, 0, 0) }
}

// ───────────────────────── 0x30: IPC ─────────────────────────

/// EP_CREATE(0x31): создать endpoint (0 = строгий rendezvous).
#[unsafe(no_mangle)]
pub extern "C" fn l4_ep_create(capacity: u64) -> i64 {
    unsafe { l4_syscall6(0x31, capacity, 0, 0, 0, 0, 0) }
}

/// IPC_SEND(0x32): отправка в endpoint (блокирующая, L4).
#[unsafe(no_mangle)]
pub extern "C" fn l4_ipc_send(ep: u64, w0: u64, w1: u64, w2: u64, flags: u64) -> i64 {
    unsafe { l4_syscall6(0x32, ep, w0, w1, w2, flags, 0) }
}

/// IPC_RECV(0x33): приём из endpoint (блокирующая).
#[unsafe(no_mangle)]
pub extern "C" fn l4_ipc_recv(ep: u64, flags: u64) -> i64 {
    unsafe { l4_syscall6(0x33, ep, flags, 0, 0, 0, 0) }
}

/// IPC_CALL(0x34): L4 ipc_call (отправка + ожидание ответа).
#[unsafe(no_mangle)]
pub extern "C" fn l4_ipc_call(ep: u64, reply_ep: u64, w0: u64, w1: u64, flags: u64) -> i64 {
    unsafe { l4_syscall6(0x34, ep, reply_ep, w0, w1, flags, 0) }
}

/// IPC_SEND_THREAD(0x35): fast-path отправка потоку по ThreadID.
#[unsafe(no_mangle)]
pub extern "C" fn l4_ipc_send_thread(
    tid_lo: u64,
    tid_hi: u64,
    w0: u64,
    w1: u64,
    words: u64,
) -> i64 {
    unsafe { l4_syscall6(0x35, tid_lo, tid_hi, w0, w1, words, 0) }
}

/// IPC_RECV_ANY(0x36): открытый приём (L4 open receive).
#[unsafe(no_mangle)]
pub extern "C" fn l4_ipc_recv_any(flags: u64) -> i64 {
    unsafe { l4_syscall6(0x36, flags, 0, 0, 0, 0, 0) }
}

/// IPC_MSG_WORD(0x37): слово сообщения из почтового ящика.
#[unsafe(no_mangle)]
pub extern "C" fn l4_ipc_msg_word(index: u64) -> i64 {
    unsafe { l4_syscall6(0x37, index, 0, 0, 0, 0, 0) }
}

/// IPC_MSG_LEN(0x38): размер сообщения + статус.
#[unsafe(no_mangle)]
pub extern "C" fn l4_ipc_msg_len() -> i64 {
    unsafe { l4_syscall6(0x38, 0, 0, 0, 0, 0, 0) }
}

/// IPC_MSG_CLEAR(0x39): очистить почтовый ящик.
#[unsafe(no_mangle)]
pub extern "C" fn l4_ipc_msg_clear() -> i64 {
    unsafe { l4_syscall6(0x39, 0, 0, 0, 0, 0, 0) }
}

/// NOTIFY_SIGNAL(0x3A): однословный signal в endpoint (doorbell).
#[unsafe(no_mangle)]
pub extern "C" fn l4_notify_signal(ep: u64, word: u64) -> i64 {
    unsafe { l4_syscall6(0x3A, ep, word, 0, 0, 0, 0) }
}

/// FUTEX_WAIT(0x3B, v0.17): уснуть на 32-битном слове, если его текущее
/// значение == expected. Ключ — ФИЗИЧЕСКИЙ адрес слова: футеки одного
/// кадра общие для всех задач, куда он отображён (SHM/transfer/map_at);
/// приватная память изолирована. Возвраты: 0 — разбужден
/// (FUTEX_WAKE); -11 (EAGAIN) — значение изменилось (до сна или в
/// окне парка — потерянных пробуждений нет); отрицательный errno —
/// ошибка. Таймаута нет (v1) — таймер-сервер юзерспейса будит
/// FUTEX_WAKE'ом.
#[unsafe(no_mangle)]
pub extern "C" fn l4_futex_wait(uaddr: u64, expected: u32) -> i64 {
    unsafe { l4_syscall6(0x3B, uaddr, expected as u64, 0, 0, 0, 0) }
}

/// FUTEX_WAKE(0x3C, v0.17): разбудить до `count` ждущих на слове с тем
/// же физическим адресом. Возврат — число разбужденных (0 — ждущих
/// нет). Дисциплина «изменил слово -> разбуди» — на приложении (ядро
/// значение не читает, как в Linux).
#[unsafe(no_mangle)]
pub extern "C" fn l4_futex_wake(uaddr: u64, count: u32) -> i64 {
    unsafe { l4_syscall6(0x3C, uaddr, count as u64, 0, 0, 0, 0) }
}

// ───────────── 0x40: сырые ресурсы (IoResource) и IRQ (v0.14) ─────────────
// «Устройств в ядре нет»: доступ к физике/портам/линиям гейтован
// IoResource-capability; перечисление устройств (ACPI/AML/PCI) и
// драйверы — юзерспейс (acpid).

/// MMIO_MAP(0x41): отобразить физический диапазон (Mmio-cap) в
/// пространство вызывающего (кадры внешние, снятие MEM_FREE).
/// Возврат: виртуальный адрес, байто-точный к base+off.
#[unsafe(no_mangle)]
pub extern "C" fn l4_mmio_map(mmio_cap: u64, off: u64, pages: u64, flags: u64) -> i64 {
    unsafe { l4_syscall6(0x41, mmio_cap, off, pages, flags, 0, 0) }
}

/// IOP_IN(0x42): чтение из I/O-порта (исполнение в ядре за IoPort-cap).
#[unsafe(no_mangle)]
pub extern "C" fn l4_iop_in(io_cap: u64, off: u64, width: u64) -> i64 {
    unsafe { l4_syscall6(0x42, io_cap, off, width, 0, 0, 0) }
}

/// IOP_OUT(0x43): запись в I/O-порт (исполнение в ядре за IoPort-cap).
#[unsafe(no_mangle)]
pub extern "C" fn l4_iop_out(io_cap: u64, off: u64, width: u64, value: u64) -> i64 {
    unsafe { l4_syscall6(0x43, io_cap, off, width, value, 0, 0) }
}

/// IRQ_ATTACH(0x46): привязать внешнюю линию (GSI) за Irq-cap к
/// notify-endpoint'у (прерывание = signal-сообщение, word = gsi).
/// flags: bit0 = level, bit1 = active_low (подсказка; MADT-ISO каноничнее).
#[unsafe(no_mangle)]
pub extern "C" fn l4_irq_attach(irq_cap: u64, gsi: u64, gate: u64, flags: u64) -> i64 {
    unsafe { l4_syscall6(0x46, irq_cap, gsi, gate, flags, 0, 0) }
}

/// IRQ_DETACH(0x47): снять привязку IRQ (владелец).
#[unsafe(no_mangle)]
pub extern "C" fn l4_irq_detach(gsi: u64) -> i64 {
    unsafe { l4_syscall6(0x47, gsi, 0, 0, 0, 0, 0) }
}

/// IRQ_ACK(0x48): подтвердить обработку прерывания (EOI-семантика).
#[unsafe(no_mangle)]
pub extern "C" fn l4_irq_ack(gsi: u64) -> i64 {
    unsafe { l4_syscall6(0x48, gsi, 0, 0, 0, 0, 0) }
}

// ───────────────────────── 0x50: память ─────────────────────────

/// MEM_ALLOC(0x51): выделить регион (страницы + отображение).
#[unsafe(no_mangle)]
pub extern "C" fn l4_mem_alloc(pages: u64, flags: u64) -> i64 {
    unsafe { l4_syscall6(0x51, pages, flags, 0, 0, 0, 0) }
}

/// MEM_FREE(0x52): снять регион по адресу.
#[unsafe(no_mangle)]
pub extern "C" fn l4_mem_free(addr: u64) -> i64 {
    unsafe { l4_syscall6(0x52, addr, 0, 0, 0, 0, 0) }
}

/// MEM_TRANSFER(0x53): flexpage-перенос в другую задачу.
#[unsafe(no_mangle)]
pub extern "C" fn l4_mem_transfer(
    src_vaddr: u64,
    pages: u64,
    flags: u64,
    dst_lo: u64,
    dst_hi: u64,
) -> i64 {
    unsafe { l4_syscall6(0x53, src_vaddr, pages, flags, dst_lo, dst_hi, 0) }
}

/// MEM_INFO(0x54): регион по адресу (аудит рантайма).
#[unsafe(no_mangle)]
pub extern "C" fn l4_mem_map_at(tcb_dst: u64, src: u64, pages: u64, dst: u64, flags: u64) -> i64 {
    unsafe { l4_syscall6(0x55, tcb_dst, src, pages, dst, flags, 0) }
}

/// MEM_INFO(0x54): слово региона задачи по адресу.
#[unsafe(no_mangle)]
pub extern "C" fn l4_mem_info(addr: u64, index: u64) -> i64 {
    unsafe { l4_syscall6(0x54, addr, index, 0, 0, 0, 0) }
}

/// MEM_PROTECT(0x56, v0.17): сменить права СВОИХ отображённых страниц
/// (mprotect-аналог; W^X действует: RWX отклоняется). Окно
/// [addr, addr+pages*4K) — в одном регионе; разделяемые кадры у ДРУГИХ
/// задач сохраняют их права. Флаги — как у MEM_ALLOC
/// (READ|WRITE = 0b011, READ|EXEC = 0b101 и т.д.).
#[unsafe(no_mangle)]
pub extern "C" fn l4_mem_protect(addr: u64, pages: u64, flags: u64) -> i64 {
    unsafe { l4_syscall6(0x56, addr, pages, flags, 0, 0, 0) }
}

// ───────────────────────── 0x60: SHM / io_uring ─────────────────────────

/// SHM_CREATE(0x61): создать SHM-регион.
#[unsafe(no_mangle)]
pub extern "C" fn l4_shm_create(pages: u64) -> i64 {
    unsafe { l4_syscall6(0x61, pages, 0, 0, 0, 0, 0) }
}

/// SHM_SETUP_RING(0x62): настроить SQ/CQ-кольца.
#[unsafe(no_mangle)]
pub extern "C" fn l4_shm_setup_ring(shm: u64, sq: u64, cq: u64, words_per_slot: u64) -> i64 {
    unsafe { l4_syscall6(0x62, shm, sq, cq, words_per_slot, 0, 0) }
}

/// SHM_BIND_DOORBELL(0x63): привязать doorbell-endpoint.
#[unsafe(no_mangle)]
pub extern "C" fn l4_shm_bind_doorbell(shm: u64, gate: u64) -> i64 {
    unsafe { l4_syscall6(0x63, shm, gate, 0, 0, 0, 0) }
}

/// SHM_MAP(0x64): отобразить регион в пространство задачи.
#[unsafe(no_mangle)]
pub extern "C" fn l4_shm_map(shm: u64, flags: u64) -> i64 {
    unsafe { l4_syscall6(0x64, shm, flags, 0, 0, 0, 0) }
}

/// SHM_DESTROY(0x65): разрушить регион.
#[unsafe(no_mangle)]
pub extern "C" fn l4_shm_destroy(shm: u64) -> i64 {
    unsafe { l4_syscall6(0x65, shm, 0, 0, 0, 0, 0) }
}

/// RING_DOORBELL(0x66): сигнал после submit SQE.
#[unsafe(no_mangle)]
pub extern "C" fn l4_ring_doorbell(shm: u64, word: u64) -> i64 {
    unsafe { l4_syscall6(0x66, shm, word, 0, 0, 0, 0) }
}

/// SHM_INFO(0x67): информация о регионе по индексу слова.
#[unsafe(no_mangle)]
pub extern "C" fn l4_shm_info(shm: u64, index: u64) -> i64 {
    unsafe { l4_syscall6(0x67, shm, index, 0, 0, 0, 0) }
}

// ───────────────────────── 0x70: отладка ─────────────────────────

/// DEBUG_WRITE(0x71): вывод в консоль отладки, до 40 байт за вызов.
/// Слова — little-endian в arg1..5.
#[unsafe(no_mangle)]
pub extern "C" fn l4_debug_write(w0: u64, w1: u64, w2: u64, w3: u64, w4: u64) -> i64 {
    unsafe { l4_syscall6(0x71, w0, w1, w2, w3, w4, 0) }
}

/// DEBUG_DUMP_TASKS(0x72): дамп задач по индексу слова.
#[unsafe(no_mangle)]
pub extern "C" fn l4_debug_dump_tasks(index: u64) -> i64 {
    unsafe { l4_syscall6(0x72, index, 0, 0, 0, 0, 0) }
}

/// DEBUG_TRACE(0x73): трассировка сисколов вкл/выкл.
#[unsafe(no_mangle)]
pub extern "C" fn l4_debug_trace(on: u64) -> i64 {
    unsafe { l4_syscall6(0x73, on, 0, 0, 0, 0, 0) }
}

/// DEBUG_DUMP_THREADS(0x74): дамп потоков задачи.
#[unsafe(no_mangle)]
pub extern "C" fn l4_debug_dump_threads(task_lo: u64, task_hi: u64, index: u64) -> i64 {
    unsafe { l4_syscall6(0x74, task_lo, task_hi, index, 0, 0, 0) }
}

// ───────────────────────── 0x80: IOMMU / DMA-ремаппинг ─────────────────────────

/// IOMMU_ENUM(0x80): обзор подсистемы. 0xFFFF_FFFF — число
/// контроллеров; иначе слова по arg2: 0 = флаги (bit0 agaw48,
/// bit1 queued_inval, bit2 pass_through, bit3 include_all, bit4
/// irq_remap, bit5 large_pages; mgaw << 8), 1 = версия.
#[unsafe(no_mangle)]
pub extern "C" fn l4_iommu_enum(ctrl: u64, word: u64) -> i64 {
    unsafe { l4_syscall6(0x80, ctrl, word, 0, 0, 0, 0) }
}

/// IOMMU_ATTACH(0x81): BDF -> DeviceId (домен изоляции).
#[unsafe(no_mangle)]
pub extern "C" fn l4_iommu_attach(ctrl: u64, bus: u64, device: u64, function: u64) -> i64 {
    unsafe { l4_syscall6(0x81, ctrl, bus, device, function, 0, 0) }
}

/// IOMMU_MAP(0x82): физические страницы -> IOVA устройства.
/// packed = pages | (prot << 32) (prot: bit0 READ, bit1 WRITE).
/// 2 МиБ-выровненный диапазон кратных 512 стр автоматически ложится
/// huge-листом (v0.8, флаг large_pages в ENUM).
#[unsafe(no_mangle)]
pub extern "C" fn l4_iommu_map(ctrl: u64, device: u64, iova: u64, phys: u64, packed: u64) -> i64 {
    unsafe { l4_syscall6(0x82, ctrl, device, iova, phys, packed, 0) }
}

/// IOMMU_UNMAP(0x83): снять IOVA-диапазон (точное совпадение с MAP).
#[unsafe(no_mangle)]
pub extern "C" fn l4_iommu_unmap(ctrl: u64, device: u64, iova: u64, pages: u64) -> i64 {
    unsafe { l4_syscall6(0x83, ctrl, device, iova, pages, 0, 0) }
}

/// IOMMU_DETACH(0x84): отвязать устройство.
#[unsafe(no_mangle)]
pub extern "C" fn l4_iommu_detach(ctrl: u64, device: u64) -> i64 {
    unsafe { l4_syscall6(0x84, ctrl, device, 0, 0, 0, 0) }
}

/// IOMMU_IRQ_MAP(0x85): запрограммировать IRTE (IRQ-ремаппинг).
/// Возврат — handle (индекс IRTE): MSI-адрес устройства несёт его
/// (Intel: SHV=0, handle = индекс; AMD: индекс per-device таблицы).
/// flags: bit0 = level-triggered, bit1 = logical destination mode.
#[unsafe(no_mangle)]
pub extern "C" fn l4_iommu_irq_map(
    ctrl: u64,
    device: u64,
    vector: u64,
    dest: u64,
    flags: u64,
) -> i64 {
    unsafe { l4_syscall6(0x85, ctrl, device, vector, dest, flags, 0) }
}

/// IOMMU_IRQ_UNMAP(0x86): погасить IRTE по handle.
#[unsafe(no_mangle)]
pub extern "C" fn l4_iommu_irq_unmap(ctrl: u64, device: u64, handle: u64) -> i64 {
    unsafe { l4_syscall6(0x86, ctrl, device, handle, 0, 0, 0) }
}

// ───────────────────────── Консольные хелперы ─────────────────────────

/// Порция DEBUG_WRITE из байтов (≤40;Little-endian слова).
#[unsafe(no_mangle)]
pub extern "C" fn l4_debug_write_bytes(bytes: *const u8, len: u64) {
    let len = (len as usize).min(40);
    let mut words = [0u64; 5];
    // SAFETY: контракт вызова — буфер ≥ len байт доступен для чтения.
    unsafe {
        for (i, &b) in core::slice::from_raw_parts(bytes, len).iter().enumerate() {
            words[i / 8] |= (b as u64) << ((i % 8) * 8);
        }
    }
    unsafe { l4_syscall6(0x71, words[0], words[1], words[2], words[3], words[4], 0) };
}

/// Печать строки (порциями по 40 байт) + \r\n.
#[unsafe(no_mangle)]
pub extern "C" fn l4_puts(s: *const i8) {
    // SAFETY: контракт вызова — ASCIIZ-строка.
    let mut p = s as *const u8;
    let mut buf = [0u8; 40];
    unsafe {
        loop {
            let mut n = 0usize;
            while n < 40 && p.add(n).read_volatile() != 0 {
                buf[n] = p.add(n).read_volatile();
                n += 1;
            }
            if n > 0 {
                l4_debug_write_bytes(buf.as_ptr(), n as u64);
            }
            if n < 40 {
                break; // ноль внутри порции — конец строки
            }
            p = p.add(40);
        }
        l4_debug_write_bytes(b"\r\n".as_ptr(), 2);
    }
}

/// Печать префикса (ASCIIZ) + hex-слова (0x + 16 цифр) + \r\n.
#[unsafe(no_mangle)]
pub extern "C" fn l4_puthex(prefix: *const i8, v: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    // SAFETY: контракт вызова — ASCIIZ-префикс.
    let mut p = prefix as *const u8;
    unsafe {
        let mut n = 0usize;
        while n < 32 && p.add(n).read_volatile() != 0 {
            n += 1;
        }
        if n > 0 {
            l4_debug_write_bytes(prefix as *const u8, n as u64);
        }
    }
    // «0x» + 16 цифр + "\r\n" = 20 байт — одна порция DEBUG_WRITE.
    let mut buf = [0u8; 20];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16 {
        let nib = (v >> ((15 - i) * 4)) & 0xF;
        buf[2 + i] = HEX[nib as usize];
    }
    buf[18] = b'\r';
    buf[19] = b'\n';
    unsafe { l4_debug_write_bytes(buf.as_ptr(), 20) };
}

/// Страховка -fstack-protector (сборка C с -fno-stack-protector не
/// ссылается; если ссылается — домен честно умирает с кодом 13).
#[unsafe(no_mangle)]
pub extern "C" fn __stack_chk_fail() -> ! {
    l4_task_exit(13)
}
