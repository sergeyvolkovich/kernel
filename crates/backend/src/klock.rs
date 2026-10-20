// ==== Big Kernel Lock (BKL) — сериализация входов в ядро (SMP v0.6) ====
//
// Ядро (крейт kernel) построено на однопроцессорных структурах: RefCell в
// TcbManager/IpcManager/GCTL, глобальные очереди без атомиков. Полноценный
// SMP v0.6 сериализует ВХОДЫ в ядро одним глобальным замком: пользователь
// исполняется параллельно на всех CPU, ядро — эксклюзивно.
//
// Дисциплина (инвариант BKL):
//
//   * держатель BKL исполняет код ядра от имени СВОЕГО потока; IF=0
//     (таймер не прерывает сискол — прежняя дисциплина v0.5 сохранена);
//   * захват — ТОЛЬКО из точек входа (syscall_c / timer_c / fault_c /
//     idle_loop) и ТОЛЬКО с IF=1-спином: во время ожидания прерывания
//     (IPI) ДОСТАВЛЯЮТСЯ — иначе shootdown-ACK не придёт на CPU,
//     крутящийся в этом же спине (классическая deadlock-петля
//     «CPU0 ждёт ACK, CPU1 ждёт BKL с погашенным IF»);
//   * освобождение — на границе выхода в пользователя: нормальный
//     sysret (syscall_c), вход по контексту (finalize_and_enter),
//     уход в idle (idle_loop);
//   * обработчики IPI (resched/shootdown/halt) BKL НЕ берут: они трогают
//     только собственный per-CPU блок и атомики.
//
// Глубина (gs:DEPTH) — маркер «этот CPU держит BKL» для отладочных
// проверок: 0 = не держит, 1 = держит. Вложенных захватов не существует
// по построению (см. выше); значение >1 — баг протокола.

use core::sync::atomic::{AtomicBool, Ordering};

/// Глобальный флаг BKL (false = свободен).
static LOCKED: AtomicBool = AtomicBool::new(false);

/// Захватить BKL.
///
/// Контракт вызова: вызвано с IF=0 (все точки входа уже погасили IF:
/// syscall-гейт через FMASK, прерывания — сам факт interrupt-gate),
/// текущий CPU НЕ держит BKL.
///
/// Во время спина IF включается (доставка IPI), после захвата гасится
/// обратно — прерванный код ядра видит прежнюю дисциплину IF=0.
pub fn acquire() {
    debug_assert_eq!(arch::percpu::depth(), 0, "BKL: recursive acquire");
    // Прерывания включаем ДО спина: pending IPI (shootdown-ACK/resched)
    // доставляются во время ожидания, а не копятся до sysret.
    unsafe { x86_64::instructions::interrupts::enable() };
    while LOCKED
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    // Захвачено: возвращаем дисциплину IF=0.
    x86_64::instructions::interrupts::disable();
    arch::percpu::set_depth(1);
}

/// Освободить BKL.
///
/// Контракт: текущий CPU держит BKL; после вызова ядро больше не
/// исполняется от имени потока (возврат в user / вход по контексту /
/// уход в idle). IF остаётся 0 — восстановит sysret/iretq из фрейма
/// пользователя (в user всегда IF=1).
pub fn release() {
    debug_assert_eq!(arch::percpu::depth(), 1, "BKL: release without acquire");
    arch::percpu::set_depth(0);
    LOCKED.store(false, Ordering::Release);
}

/// Текущий CPU держит BKL? (отладка/инварианты).
pub fn held() -> bool {
    arch::percpu::depth() != 0
}
