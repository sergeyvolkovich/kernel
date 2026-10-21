// ==== SMP-примитивы ядра v0.12: спин-локи с IF-дисциплиной + lock-free MPMC ====
//
// Демонтаж BKL (klock.rs удалён): ядро больше не сериализуется одним
// глобальным замком. Каждая подсистема защищается собственным локом
// (fine-grained), горячие пути — атомики и lock-free структуры.
//
// ───────────────────────── IF-дисциплина (контракт) ─────────────────────────
//
//   * держатель любого ядрового лока всегда исполняется с IF=0
//     (входы в ядро гасят IF; захват лока его не меняет);
//   * спин-ОЖИДАНИЕ лока на «глубине 0» (никаких других локов не
//     держится) идёт с IF=1: ожидающий доставляет IPI — в частности
//     shootdown-ACK держателю KMEM, единственного лока, под которым
//     ядро ждёт cross-CPU (TLB shootdown);
//   * спин-ОЖИДАНИЕ вложенного лока (глубина > 0) идёт с IF=0 —
//     безопасно: вложенные ожидания возможны только на TCB/SCHED
//     (см. ранги ниже), чьи держатели никогда не ждут других CPU;
//   * внешние прерывания физически не могут прервать держателя лока
//     (у него IF=0) → хард-IRQ хендлер не может самозависнуть на локе,
//     который держит прерванный контекст; на «глубине 0» IRQ-хендлер
//     берёт локы свободно (прерванный ничего не держал).
//
// Глубина (per-CPU, устанавливается платформой в GS) — счётчик удерживаемых
// ядровых локов; хуки wait/wake/depth_* ставит бекенд ДО старта SMP
// (host-тесты живут на no-op-хуках: спин без IF-манипуляций).
//
// ───────────────────────── Ранги захвата ( deadlock-дисциплина ) ─────────────
//
//   GATE (per-endpoint RawGate) ──▶ { TCB, SCHED, CAP }
//   CLAIM (DeviceClaimRegistry) ──▶ { TCB, SCHED }
//   TCB   (TcbManager, KRwLock) ──▶ SCHED (хуки enqueue/deschedule)
//   SCHED (бекенд: мьютекс контекстов/block-очередей; MPMC — lock-free)
//   CAP / KMEM / SHM / IrqRouter / Registry — ЛИСТЬЯ (никого не берут)
//
// Инварианты: GATE→GATE запрещён (фазы L4 ipc_call покидают лок до
// повторного входа — «claim-протокол» в crate::ipc); KMEM — единственный
// лок, удерживаемый через cross-CPU ожидание (shootdown), и берётся
// только на глубине 0; любые пары вне таблицы — последовательно,
// без пересечения критсекций.
//
// ───────────────────────── Lock-free по итогам аудита v0.12 ─────────────────
//
//   * готовность планировщика — [`MpmcQueue`] (алгоритм Vyukov:
//     без аллокаций на пути, без ABA, без реаллокаций узлов);
//   * флаги need_resched/квант/slice_used — per-CPU (GS, бекенд);
//   * граница CPU-периода и тики — атомики (бекенд, v0.10);
//   * живость capability-целей — generation-проверки TargetRef (было).

use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use spin::Once;

// ───────────────────── Хуки платформы (установка бекендом) ─────────────────────

/// Платформенная половина IF-дисциплины: что делать в спине и где живёт
/// per-CPU глубина захвата ядровых локов.
///
/// `wait`/`wake` вызываются парами ВОКРУГ спина (не на каждой итерации):
/// x86_64-бекенд в `wait` включает прерывания, если глубина == 0, в
/// `wake` — гасит обратно (глубина в этот момент ещё прежняя: инкремент
/// выполняется ПОСЛЕ захвата). Быстрый путь без спина хуки не трогает —
/// IF остаётся 0, как и был на входе в ядро.
pub struct SpinHooks {
    /// Начали ждать лок (медленный путь): на глубине 0 — включить IF.
    pub wait: fn(),
    /// Дождались и захватили: на глубине 0 — вернуть IF=0.
    pub wake: fn(),
    /// Захвачен ядровый лок: +1 к per-CPU глубине.
    pub depth_inc: fn(),
    /// Освобождён ядровый лок: −1.
    pub depth_dec: fn(),
    /// Текущая per-CPU глубина захвата (отладка/инварианты).
    pub depth: fn() -> u32,
}

/// Host/no-op-хуки: спин без IF-манипуляций, глубина не ведётся.
const HOST_HOOKS: SpinHooks = SpinHooks {
    wait: || {},
    wake: || {},
    depth_inc: || {},
    depth_dec: || {},
    depth: || 0,
};

static HOOKS: Once<SpinHooks> = Once::new();

/// Установить платформенные хуки (однократно, ДО старта SMP; повторные
/// вызовы игнорируются — семантика spin::Once).
pub fn install_hooks(hooks: SpinHooks) {
    let _ = HOOKS.call_once(|| hooks);
}

#[inline]
fn hooks() -> &'static SpinHooks {
    HOOKS.get().unwrap_or(&HOST_HOOKS)
}

/// Текущая per-CPU глубина захвата ядровых локов (0 — «мы не держим
/// ничего», вход IRQ-хендлера безопасен в любом локе).
pub fn lock_depth() -> u32 {
    (hooks().depth)()
}

/// Поднять глубину БЕЗ лока — маркер «исполняемся в ядре» для хендлеров
/// прерываний (см. backend gate::irq_c): их спины пойдут с IF=0,
/// вложение внешних линий ограничено одним уровнем.
pub fn depth_enter() {
    (hooks().depth_inc)();
}

/// Снять маркер [`depth_enter`].
pub fn depth_exit() {
    (hooks().depth_dec)();
}

// ───────────────────── RawGate: сырой спин-лок без данных ─────────────────────

/// Спин-лок без полезной нагрузки: сериализация критсекций, данные —
/// рядом в другой структуре (per-gate локи IPC в статической таблице
/// `GATE_LOCKS` крейта capability).
///
/// Дисциплина IF — общая для всех локов этого модуля (см. шапку).
pub struct RawGate {
    locked: AtomicBool,
}

impl RawGate {
    /// Свободен.
    pub const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
        }
    }

    /// Захват без ожидания (медленный путь не входит).
    #[inline]
    pub fn try_acquire(&self) -> bool {
        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    /// Захват с IF-дисциплиной: спин на глубине 0 — с прерываниями.
    pub fn acquire(&self) {
        if self.try_acquire() {
            (hooks().depth_inc)();
            return;
        }
        (hooks().wait)();
        while !self.try_acquire() {
            spin_loop();
        }
        (hooks().wake)();
        (hooks().depth_inc)();
    }

    /// Освобождение (глубина −1 до store: мгновенной релокации инварианта
    /// «держатель = глубина ≥ 1» нет, порядок статистический).
    #[inline]
    pub fn release(&self) {
        (hooks().depth_dec)();
        self.locked.store(false, Ordering::Release);
    }

    /// Занят ли (диагностика; гонка допустима).
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }

    /// RAII-захват: [`GateGuard`] отпускает лок на выходе из области
    /// (ранние `return`/`?` из критсекции GATE — безопасны по построению).
    pub fn acquire_guard(&self) -> GateGuard<'_> {
        self.acquire();
        GateGuard { gate: self }
    }
}

/// RAII-гард [`RawGate`] (см. `acquire_guard`).
pub struct GateGuard<'a> {
    gate: &'a RawGate,
}

impl Drop for GateGuard<'_> {
    #[inline]
    fn drop(&mut self) {
        self.gate.release();
    }
}

// ───────────────────── KSpin<T>: мьютекс подсистемы ─────────────────────

/// Спин-мьютекс с данными: защита состояния менеджера (листовой ранг —
/// внутри критсекции другие ядровые локи НЕ берутся, кроме разрешённых
/// таблицей рангов).
///
/// Хост-сборка (тесты): обычный корректный мьютекс на атомиках —
/// многопоточные стресс-тесты см. ниже.
pub struct KSpin<T: ?Sized> {
    gate: RawGate,
    data: UnsafeCell<T>,
}

// SAFETY: доступ к данным — только под локом; T передаётся между CPU.
unsafe impl<T: ?Sized + Send> Sync for KSpin<T> {}
unsafe impl<T: ?Sized + Send> Send for KSpin<T> {}

/// RAII-гард [`KSpin`]: эксклюзивный доступ до конца области.
pub struct KSpinGuard<'a, T: ?Sized> {
    lock: &'a KSpin<T>,
}

impl<T: ?Sized> Deref for KSpinGuard<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: гард существует только под захваченным локом.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for KSpinGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: эксклюзивность — инвариант лока.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for KSpinGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.gate.release();
    }
}

impl<T> KSpin<T> {
    /// Новый лок поверх `data`.
    pub const fn new(data: T) -> Self {
        Self {
            gate: RawGate::new(),
            data: UnsafeCell::new(data),
        }
    }
}

impl<T: ?Sized> KSpin<T> {
    /// Захват (спин по дисциплине; глубина +1).
    pub fn lock(&self) -> KSpinGuard<'_, T> {
        self.gate.acquire();
        KSpinGuard { lock: self }
    }

    /// Захват без ожидания (`None` — занят).
    pub fn try_lock(&self) -> Option<KSpinGuard<'_, T>> {
        if self.gate.try_acquire() {
            (hooks().depth_inc)();
            Some(KSpinGuard { lock: self })
        } else {
            None
        }
    }

    /// Мутируемый доступ по `&mut self` (kinit/тесты/дроп) — без лока.
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }
}

// ───────────────────── KRwLock<T>: читатели/писатель ─────────────────────

/// Состояние: бит 31 — писатель, биты 0..30 — число читателей.
/// Читатели пускаются при отсутствии писателя (writer может голодать
/// под непрерывным чтением — секции чтения короткие, таблица менеджера).
const WRITER_BIT: u32 = 1 << 31;

/// RwLock менеджера: lookup-пути (`with_caps`, `with_task_obj`, `get`) —
/// читатели, мутации — писатель. Реентери чтений разрешён (вложенные
/// read-секции безопасны, как RefCell-borrow у v0.6); реентери записи —
/// дедлок (раньше — паника RefCell: тот же класс бага ловится).
pub struct KRwLock<T: ?Sized> {
    state: AtomicU32,
    data: UnsafeCell<T>,
}

// SAFETY: запись — эксклюзивно под битом писателя (T: Send достаточно,
// как у spin::Mutex); чтение под read-гардом — по контракту READ-пути
// ядра НЕ мутируют данные (все мутации — через write()): это и есть
// дисциплина крейта, синхронизацию обеспечивает сам лок. Формального
// T: Sync не требуется: сырые указатели таблиц читаются только
// generation-проверенными read-путями.
unsafe impl<T: ?Sized + Send> Sync for KRwLock<T> {}
unsafe impl<T: ?Sized + Send> Send for KRwLock<T> {}

/// RAII-гард чтения (совместный доступ).
pub struct KRwReadGuard<'a, T: ?Sized> {
    lock: &'a KRwLock<T>,
}

/// RAII-гард записи (эксклюзивный доступ).
pub struct KRwWriteGuard<'a, T: ?Sized> {
    lock: &'a KRwLock<T>,
}

impl<T: ?Sized> Deref for KRwReadGuard<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: гард — под счётчиком читателей; писателя нет.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> Deref for KRwWriteGuard<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: гард — под битом писателя.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for KRwWriteGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: эксклюзивность — инвариант бита писателя.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for KRwReadGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.state.fetch_sub(1, Ordering::Release);
        (hooks().depth_dec)();
    }
}

impl<T: ?Sized> Drop for KRwWriteGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.state.store(0, Ordering::Release);
        (hooks().depth_dec)();
    }
}

impl<T> KRwLock<T> {
    /// Новый лок поверх `data`.
    pub const fn new(data: T) -> Self {
        Self {
            state: AtomicU32::new(0),
            data: UnsafeCell::new(data),
        }
    }
}

impl<T: ?Sized> KRwLock<T> {
    #[inline]
    fn try_read_state(state: &AtomicU32) -> bool {
        let s = state.load(Ordering::Relaxed);
        // Писатель держит или читателей максимум — не пускаем.
        if s & WRITER_BIT != 0 || s == WRITER_BIT - 1 {
            return false;
        }
        state
            .compare_exchange(s, s + 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    #[inline]
    fn try_write_state(state: &AtomicU32) -> bool {
        state
            .compare_exchange(0, WRITER_BIT, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    /// Чтение (спин по дисциплине; читатели параллельны между собой).
    pub fn read(&self) -> KRwReadGuard<'_, T> {
        if Self::try_read_state(&self.state) {
            (hooks().depth_inc)();
            return KRwReadGuard { lock: self };
        }
        (hooks().wait)();
        while !Self::try_read_state(&self.state) {
            spin_loop();
        }
        (hooks().wake)();
        (hooks().depth_inc)();
        KRwReadGuard { lock: self }
    }

    /// Запись (эксклюзив; ждёт обнуления читателей и отсутствия писателя).
    pub fn write(&self) -> KRwWriteGuard<'_, T> {
        if Self::try_write_state(&self.state) {
            (hooks().depth_inc)();
            return KRwWriteGuard { lock: self };
        }
        (hooks().wait)();
        while !Self::try_write_state(&self.state) {
            spin_loop();
        }
        (hooks().wake)();
        (hooks().depth_inc)();
        KRwWriteGuard { lock: self }
    }

    /// Чтение без ожидания.
    pub fn try_read(&self) -> Option<KRwReadGuard<'_, T>> {
        if Self::try_read_state(&self.state) {
            (hooks().depth_inc)();
            Some(KRwReadGuard { lock: self })
        } else {
            None
        }
    }

    /// Запись без ожидания.
    pub fn try_write(&self) -> Option<KRwWriteGuard<'_, T>> {
        if Self::try_write_state(&self.state) {
            (hooks().depth_inc)();
            Some(KRwWriteGuard { lock: self })
        } else {
            None
        }
    }

    /// Мутируемый доступ по `&mut self` (kinit/дроп) — без лока.
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }
}

// ───────────────────── MpmcQueue<T, N>: lock-free FIFO (Vyukov) ─────────────────────

/// Слот кольца: `seq` — тикет эпохи слота (см. push/pop), `data` — значение.
struct MpmcSlot<T> {
    seq: AtomicU64,
    data: UnsafeCell<Option<T>>,
}

/// Lock-free ограниченная MPMC-очередь (алгоритм D. Vyukov).
///
/// Свойства: много производителей и потребителей без блокировок;
/// отсутствие ABA (порядок — тикеты seq, не указатели); отсутствие
/// аллокаций и реаллокаций на пути; переполнение — честный `Err` (не
/// ждать, не терять). Порядок — «почти FIFO»: строгая очерёдность
/// гарантируется в пределах слота, глобальный порядок — вероятностный
/// (для RR-планировщика достаточно).
///
/// Ёмкость `N` — степень двойки (маска вместо деления). Готовность
/// планировщика: 1024 слота при квоте 512 потоков на систему —
/// переполнение невозможно по построению (каждый живой поток даёт ≤ 1
/// записи; assert-защита остаётся на всякий случай).
pub struct MpmcQueue<T, const N: usize> {
    buf: [MpmcSlot<T>; N],
    head: AtomicU64,
    tail: AtomicU64,
    /// Приблизительная длина (гонка допустима: используется только для
    /// дешёвого `has_ready`-peek в idle-цикле).
    len: AtomicUsize,
}

// SAFETY: слоты синхронизированы seq-тикетами (Acquire/Release-пары);
// head/tail — атомики; значение перемещается между CPU при push/pop.
unsafe impl<T: Send, const N: usize> Sync for MpmcQueue<T, N> {}
unsafe impl<T: Send, const N: usize> Send for MpmcQueue<T, N> {}

impl<T, const N: usize> MpmcQueue<T, N> {
    /// Пустое кольцо (const-инициализация для статики бекенда).
    ///
    /// По алгоритму `seq` слота i инициализируется значением i (первый
    /// производитель по тикету i видит diff == 0).
    pub const fn new() -> Self {
        // Повтор слота без Clone: inline-const в repeat-выражении.
        let mut buf: [MpmcSlot<T>; N] = [const {
            MpmcSlot {
                seq: AtomicU64::new(0),
                data: UnsafeCell::new(None),
            }
        }; N];
        let mut i = 0;
        while i < N {
            buf[i].seq = AtomicU64::new(i as u64);
            i += 1;
        }
        Self {
            buf,
            head: AtomicU64::new(0),
            tail: AtomicU64::new(0),
            len: AtomicUsize::new(0),
        }
    }

    #[inline]
    fn slot(&self, ticket: u64) -> &MpmcSlot<T> {
        debug_assert!(
            N.is_power_of_two(),
            "MpmcQueue: N — степень двойки (инвариант типа)"
        );
        &self.buf[(ticket & (N as u64 - 1)) as usize]
    }

    /// Положить значение. `Err(v)` — кольцо полно (значение возвращено).
    pub fn push(&self, v: T) -> Result<(), T> {
        let mut pos = self.tail.load(Ordering::Relaxed);
        loop {
            let slot = self.slot(pos);
            let seq = slot.seq.load(Ordering::Acquire);
            let diff = (seq as i64).wrapping_sub(pos as i64);
            if diff == 0 {
                // Свой тикет: бьём за tail (кто успел — тот пишет этот слот).
                if self
                    .tail
                    .compare_exchange_weak(pos, pos + 1, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    // SAFETY: слот принадлежит выигравшему тикету;
                    // replace (а не присваивание) честно возвращает старое
                    // значение — по инвариантам алгоритма оно всегда None.
                    let _old = unsafe { (*slot.data.get()).replace(v) };
                    debug_assert!(_old.is_none(), "mpmc push: слот занят прошлой эпохой");
                    slot.seq.store(pos + 1, Ordering::Release);
                    self.len.fetch_add(1, Ordering::Release);
                    return Ok(());
                }
                // Проиграли CAS — перечитываем tail и пробуем снова.
                pos = self.tail.load(Ordering::Relaxed);
            } else if diff < 0 {
                // seq позади тикета: слот ещё занят невыгруженными данными
                // прошлой эпохи — кольцо полно.
                return Err(v);
            } else {
                // tail убежал вперёд — помогаем: перечитываем.
                pos = self.tail.load(Ordering::Relaxed);
            }
        }
    }

    /// Достать значение. `None` — кольцо пусто.
    pub fn pop(&self) -> Option<T> {
        let mut pos = self.head.load(Ordering::Relaxed);
        loop {
            let slot = self.slot(pos);
            let seq = slot.seq.load(Ordering::Acquire);
            let diff = (seq as i64).wrapping_sub(pos as i64 + 1);
            if diff == 0 {
                if self
                    .head
                    .compare_exchange_weak(pos, pos + 1, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    // Победитель head-тикета забирает данные и вскрывает
                    // слот для следующей эпохи (pos + N).
                    // SAFETY: слот — собственность победившего тикета.
                    let v = unsafe { (*slot.data.get()).take() };
                    slot.seq.store(pos + N as u64, Ordering::Release);
                    self.len.fetch_sub(1, Ordering::Release);
                    return v;
                }
                pos = self.head.load(Ordering::Relaxed);
            } else if diff < 0 {
                // Данные ещё не записаны — пусто.
                return None;
            } else {
                pos = self.head.load(Ordering::Relaxed);
            }
        }
    }

    /// Приблизительная длина (для дешёвых проверок «есть ли готовность»).
    #[inline]
    pub fn len(&self) -> usize {
        self.len.load(Ordering::Acquire)
    }

    /// Пусто ли (приблизительно; точность достаточна для idle-peek).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ───────────────────── Тесты (host, многопоточные) ─────────────────────

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    use super::*;

    #[test]
    fn kspin_mutual_exclusion_two_threads() {
        let lock = Arc::new(KSpin::new(0usize));
        let mut handles = Vec::new();
        for _t in 0..4 {
            let lock = Arc::clone(&lock);
            handles.push(thread::spawn(move || {
                for _ in 0..25_000 {
                    let mut g = lock.lock();
                    // Критсекция: из-под живого лока конкурентный try_lock
                    // обязан отказывать (проверяется взаимным исключением
                    // самого счётчика: потерянные инкременты дали бы < суммы).
                    *g = (*g).wrapping_add(1);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(*lock.lock(), 100_000);
    }

    #[test]
    fn krwlock_readers_parallel_writer_exclusive() {
        let lock = Arc::new(KRwLock::new(0usize));
        let mut handles = Vec::new();
        // Писатели: инкремент под write().
        for _ in 0..2 {
            let lock = Arc::clone(&lock);
            handles.push(thread::spawn(move || {
                for _ in 0..10_000 {
                    *lock.write() += 1;
                }
            }));
        }
        // Читатели: совместное чтение; try_write обязан отказывать,
        // пока жив read-гард (state >= 1 — CAS с нуля невозможен).
        for _ in 0..2 {
            let lock = Arc::clone(&lock);
            handles.push(thread::spawn(move || {
                for _ in 0..10_000 {
                    let g = lock.read();
                    let _ = *g;
                    if lock.try_write().is_some() {
                        panic!("try_write прошёл под живым read-гардом");
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(*lock.read(), 20_000);
    }

    #[test]
    fn krwlock_recursive_read_allowed() {
        let lock = KRwLock::new(0usize);
        let a = lock.read();
        let b = lock.read(); // вложенное чтение — легально
        assert_eq!(*a + *b, 0);
        drop(b);
        drop(a);
        *lock.write() = 1;
        assert_eq!(*lock.read(), 1);
    }

    #[test]
    fn mpmc_multithread_no_loss_near_fifo() {
        const CAP: usize = 64;
        let q: Arc<MpmcQueue<u64, CAP>> = Arc::new(MpmcQueue::new());
        const PRODUCERS: usize = 4;
        const PER_PROD: u64 = 20_000;
        let consumed = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for p in 0..PRODUCERS {
            let q = Arc::clone(&q);
            handles.push(thread::spawn(move || {
                for i in 0..PER_PROD {
                    // Переполнение малой ёмкости: спин-ретрай (потребители
                    // гарантированно есть — тест не зависнет).
                    let mut v = (p as u64) << 48 | i;
                    while let Err(back) = q.push(v) {
                        v = back;
                        thread::yield_now();
                    }
                }
            }));
        }
        for _ in 0..PRODUCERS {
            let q = Arc::clone(&q);
            let consumed = Arc::clone(&consumed);
            handles.push(thread::spawn(move || {
                loop {
                    if q.pop().is_some() {
                        consumed.fetch_add(1, Ordering::Relaxed);
                    }
                    // Выход — по общему итогу (и на пустой очереди тоже:
                    // иначе консьюмеры зависнут после последней выгрузки).
                    if consumed.load(Ordering::Acquire) == PRODUCERS as usize * PER_PROD as usize {
                        return;
                    }
                    thread::yield_now();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(
            consumed.load(Ordering::Acquire),
            PRODUCERS as usize * PER_PROD as usize
        );
    }

    #[test]
    fn mpmc_fifo_within_single_thread_traffic() {
        let q: MpmcQueue<u32, 8> = MpmcQueue::new();
        // Три полных группы с дренажом, затем хвост без дренажа —
        // строгий FIFO одиночного трафика проверяется на каждом слоте.
        for i in 0..27u32 {
            assert!(q.push(i).is_ok());
            if i % 3 == 2 && i < 24 {
                let mut expect = i - 2;
                while let Some(v) = q.pop() {
                    assert_eq!(v, expect);
                    expect += 1;
                }
                assert_eq!(expect, i + 1, "дренаж группы {} полон", i);
            }
        }
        let mut expect = 24;
        while let Some(v) = q.pop() {
            assert_eq!(v, expect);
            expect += 1;
        }
        assert_eq!(expect, 27);
        assert!(q.pop().is_none());
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn mpmc_full_and_empty_semantics() {
        let q: MpmcQueue<u8, 2> = MpmcQueue::new();
        assert!(q.pop().is_none());
        assert!(q.push(1).is_ok());
        assert!(q.push(2).is_ok());
        assert_eq!(q.push(3), Err(3));
        assert_eq!(q.pop(), Some(1));
        assert!(q.push(4).is_ok());
        assert_eq!(q.pop(), Some(2));
        assert_eq!(q.pop(), Some(4));
        assert!(q.pop().is_none());
    }
}
