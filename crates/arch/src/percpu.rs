// ==== PER-CPU данные через GS-базу ====
//
// Модель x86_64 (как Linux/Redox): GS:base указывает на начало per-CPU
// блока текущего CPU; первое поле блока — указатель на сам блок
// (GS:0 == &блок), что даёт дешёвый self-доступ и живой маркер
// корректности настройки. Блок — одна страница на CPU.
//
// ВСЕ обращения здесь — через gs:[off]: они адресуют ТОЛЬКО текущий
// CPU. Крестный доступ (CPU A трогает блок CPU B) — через обычные
// указатели у владельца блоков (backend держит phys-таблицу), здесь
// его сознательно нет: неявный крестный доступ через сегмент —
// источник классических SMP-багов, запрещаем саму возможность.
//
// Согласование с backend: смещения — константы протокола, меняются
// только ДОПИСЫВАНИЕМ в конец (как у boot_info): старые не двигаются.
//
// u128-поля (Thread/TaskId из ядра) хранятся парами u64 lo/hi: слово
// gs-доступа — 8 бит; атомарности пары НЕ требуется — поле текущего
// потока/задачи пишет только сам CPU под своим входом в ядро.

/// Размер per-CPU блока: одна страница (запас под будущие поля).
pub const PERCPU_SIZE: usize = 0x1000;

// ───────────────────── Смещения полей (протокол) ─────────────────────

/// GS:0 — указатель блока на себя (маркер настройки).
pub const OFF_SELF: usize = 0x00; // u64
/// Логический номер CPU (0 = BSP).
pub const OFF_CPU_ID: usize = 0x08; // u32
/// Текущий поток (ThreadId, u128; 0 = нет/idle). lo @ 0x10, hi @ 0x18.
pub const OFF_CURRENT_THREAD: usize = 0x10;
/// Текущая задача-домен (TaskId, u128; 0 = нет).
pub const OFF_CURRENT_TASK: usize = 0x20;
/// Scratch: RSP ядрового стека для syscall/entry (TSS->rsp0 дублирует,
/// здесь — для чтения из C без парсинга TSS).
pub const OFF_KERNEL_RSP: usize = 0x30; // u64
/// Сохранённый пользовательский RSP на входе в ядро (syscall).
pub const OFF_USER_RSP: usize = 0x38; // u64
/// Глубина входа в ядро (big-kernel-lock v0.5: 0 = вне ядра).
pub const OFF_DEPTH: usize = 0x40; // u64
/// LAPIC ID текущего CPU (после MADT-сверки).
pub const OFF_LAPIC_ID: usize = 0x48; // u32
/// Указатель на фрейм входа в ядро (syscall-гейт кладёт сюда RSP фрейма;
/// читает rust-часть при блокировке потока; v0.5.1 — дописано в конец).
pub const OFF_FRAME: usize = 0x50; // u64
/// Флаг NEED_RESCHED (u64: 0/1): IPI-resched обработчик ставит 1 (asm),
/// планировщик снимает cmpxchg при проверке (v0.6 — дописано в конец).
pub const OFF_NEED_RESCHED: usize = 0x58; // u64
/// Квант текущего потока в тиках (u64; v0.6 — дописано в конец).
pub const OFF_QUANTUM: usize = 0x60; // u64

// ───────────────────── Сырой gs-доступ ─────────────────────

/// Прочитать u64 из per-CPU блока по смещению.
///
/// # Safety
///
/// `off + 8 <= PERCPU_SIZE` и GS-база установлена (`set_gs_base`);
/// вызов до установки — чтение по нулевой базе (GP/#PF).
#[inline]
pub unsafe fn read_u64(off: usize) -> u64 {
    let v: u64;
    unsafe {
        core::arch::asm!(
            ".intel_syntax noprefix",
            "mov {v}, gs:[{off}]",
            off = in(reg) off,
            v = out(reg) v,
            options(nostack, preserves_flags)
        );
    }
    v
}

/// Записать u64 в per-CPU блок по смещению.
///
/// # Safety
///
/// `off + 8 <= PERCPU_SIZE` и GS-база установлена.
#[inline]
pub unsafe fn write_u64(off: usize, val: u64) {
    unsafe {
        core::arch::asm!(
            ".intel_syntax noprefix",
            "mov gs:[{off}], {val}",
            off = in(reg) off,
            val = in(reg) val,
            options(nostack, preserves_flags)
        );
    }
}

/// Атомарный compare-exchange u64 в per-CPU блоке (lock cmpxchg).
///
/// `Ok(())` — записано `new`; `Err(old)` — в поле лежало не `expected`,
/// поле не тронуто. Сырьё для spin-блокировок поверх per-CPU полей
/// (в v0.5 так живёт big kernel lock: depth-счётчик).
///
/// # Safety
///
/// `off + 8 <= PERCPU_SIZE`, GS-база установлена; выравнивание поля
/// на 8 — ответственность протокола смещений (все поля u64-кратны).
#[inline]
pub unsafe fn cmpxchg_u64(off: usize, expected: u64, new: u64) -> Result<(), u64> {
    let old: u64;
    let ok: u8;
    unsafe {
        core::arch::asm!(
            ".intel_syntax noprefix",
            "lock cmpxchg gs:[{off}], {new}",
            "sete {ok}",
            off = in(reg) off,
            new = in(reg) new,
            inout("rax") expected => old,
            ok = out(reg_byte) ok,
            // flags затираются cmpxchg — не отмечаем preserves_flags
            options(nostack)
        );
    }
    if ok != 0 { Ok(()) } else { Err(old) }
}

// ───────────────────── Типизированные поля ─────────────────────

/// Номер текущего CPU (GS-база обязана быть установлена).
#[inline]
pub fn cpu_id() -> u32 {
    unsafe { read_u64(OFF_CPU_ID) as u32 }
}

/// Текущий поток (u128 ThreadId; 0 = нет).
#[inline]
pub fn current_thread() -> u128 {
    unsafe {
        let lo = read_u64(OFF_CURRENT_THREAD);
        let hi = read_u64(OFF_CURRENT_THREAD + 8);
        ((hi as u128) << 64) | lo as u128
    }
}

/// Установить текущий поток (только для СВОЕГО CPU).
#[inline]
pub fn set_current_thread(tid: u128) {
    unsafe {
        write_u64(OFF_CURRENT_THREAD, tid as u64);
        write_u64(OFF_CURRENT_THREAD + 8, (tid >> 64) as u64);
    }
}

/// Текущая задача-домен (u128 TaskId; 0 = нет).
#[inline]
pub fn current_task() -> u128 {
    unsafe {
        let lo = read_u64(OFF_CURRENT_TASK);
        let hi = read_u64(OFF_CURRENT_TASK + 8);
        ((hi as u128) << 64) | lo as u128
    }
}

/// Установить текущую задачу-домен.
#[inline]
pub fn set_current_task(tid: u128) {
    unsafe {
        write_u64(OFF_CURRENT_TASK, tid as u64);
        write_u64(OFF_CURRENT_TASK + 8, (tid >> 64) as u64);
    }
}

/// Ядровый RSP (scratch входа).
#[inline]
pub fn kernel_rsp() -> u64 {
    unsafe { read_u64(OFF_KERNEL_RSP) }
}

/// Установить ядровый RSP.
#[inline]
pub fn set_kernel_rsp(rsp: u64) {
    unsafe { write_u64(OFF_KERNEL_RSP, rsp) }
}

/// Сохранённый пользовательский RSP (syscall-вход).
#[inline]
pub fn user_rsp() -> u64 {
    unsafe { read_u64(OFF_USER_RSP) }
}

/// Установить пользовательский RSP.
#[inline]
pub fn set_user_rsp(rsp: u64) {
    unsafe { write_u64(OFF_USER_RSP, rsp) }
}

/// Глубина входа в ядро (0 = вне ядра).
#[inline]
pub fn depth() -> u64 {
    unsafe { read_u64(OFF_DEPTH) }
}

/// Установить глубину входа.
#[inline]
pub fn set_depth(d: u64) {
    unsafe { write_u64(OFF_DEPTH, d) }
}

/// LAPIC ID текущего CPU.
#[inline]
pub fn lapic_id() -> u32 {
    unsafe { read_u64(OFF_LAPIC_ID) as u32 }
}

/// Установить LAPIC ID.
#[inline]
pub fn set_lapic_id(id: u32) {
    unsafe { write_u64(OFF_LAPIC_ID, id as u64) }
}

// ───────────────────── SMP-поля (v0.6) ─────────────────────

/// Флаг NEED_RESCHED текущего CPU (устанавливается обработчиком IPI
/// из asm; читается/снимается планировщиком).
#[inline]
pub fn need_resched() -> bool {
    unsafe { read_u64(OFF_NEED_RESCHED) != 0 }
}

/// Снять NEED_RESCHED (возврат прежнего значения).
#[inline]
pub fn take_need_resched() -> bool {
    // Гонка с IPI-обработчиком: cmpxchg гарантирует, что флаг,
    // поставленный между чтением и снятием, не потеряется (обработчик
    // пишет 1 напрямую — наш cmpxchg либо снимет уже поставленный
    // флаг, либо не тронет новый).
    unsafe {
        loop {
            let cur = read_u64(OFF_NEED_RESCHED);
            if cur == 0 {
                return false;
            }
            match cmpxchg_u64(OFF_NEED_RESCHED, 1, 0) {
                Ok(()) => return true,
                Err(_) => continue, // обработчик перезаписал — повторить
            }
        }
    }
}

/// Установить NEED_RESCHED (локально; для чужих CPU — только IPI).
#[inline]
pub fn set_need_resched() {
    unsafe { write_u64(OFF_NEED_RESCHED, 1) }
}

/// Квант текущего потока (тики).
#[inline]
pub fn quantum() -> u64 {
    unsafe { read_u64(OFF_QUANTUM) }
}

/// Установить квант.
#[inline]
pub fn set_quantum(q: u64) {
    unsafe { write_u64(OFF_QUANTUM, q) }
}

// ───────────────────── Настройка GS ─────────────────────

/// Установить GS-базу на per-CPU блок (IA32_GS_BASE MSR; без FSGSBASE-
/// зависимости: работает на любом x86_64). Вызывает владелец блоков
/// (backend) при старте CPU — BSP из startup, AP из своего входа.
///
/// `block` — ВИРТУАЛЬНЫЙ адрес блока (physmap/identity): все дальнейшие
/// gs-доступы идут через трансляцию текущих таблиц страниц.
pub fn set_gs_base(block: u64) {
    use x86_64::registers::model_specific::GsBase;
    let mut msr = GsBase::MSR;
    // SAFETY: привилегированная wrmsr — вызывается ядром до первого
    // пользовательского контекста (пока GS никем не читается).
    unsafe { msr.write(block) };
}

/// Прямой указатель на per-CPU блок (для крестного доступа владельцем
/// блоков — backend: заполнение блока AP до SIPI, чтение чужого
/// текущего потока планировщиком). Явный — чтобы крестный доступ через
/// gs:[off] не появлялся «нечаянно» (запрещён протоколом выше).
///
/// # Safety
///
/// `off + 8 <= PERCPU_SIZE`; владелец блока гарантирует его жизнь.
#[inline]
pub unsafe fn block_ptr<T>(block: u64, off: usize) -> *mut T {
    (block + off as u64) as *mut T
}

/// Дескриптор записи полей блока (BSP заполняет блок AP до SIPI:
/// единственный законный писатель в ЧУЖОЙ блок — см. backend::smp).
pub struct BlockWriter {
    block: u64,
}

impl BlockWriter {
    /// Заполнить поля блока (все — прямые записи: AP ещё не исполняется).
    #[allow(clippy::too_many_arguments)]
    pub fn fill(block: u64, f: impl FnOnce(BlockWriter)) {
        f(BlockWriter { block })
    }

    /// GS:0 — указатель блока на себя.
    pub fn self_ptr(&self, v: u64) {
        // SAFETY: off=0 в границах; владелец пишет до старта AP.
        unsafe { core::ptr::write_volatile(block_ptr::<u64>(self.block, OFF_SELF), v) };
    }

    /// Логический номер CPU.
    pub fn cpu_id(&self, v: u32) {
        // SAFETY: см. self_ptr.
        unsafe { core::ptr::write_volatile(block_ptr::<u64>(self.block, OFF_CPU_ID), v as u64) };
    }

    /// Ядровый RSP (скретч syscall/entry).
    pub fn kernel_rsp(&self, v: u64) {
        // SAFETY: см. self_ptr.
        unsafe { core::ptr::write_volatile(block_ptr::<u64>(self.block, OFF_KERNEL_RSP), v) };
    }

    /// Глубина входа в ядро (BKL).
    pub fn depth(&self, v: u64) {
        // SAFETY: см. self_ptr.
        unsafe { core::ptr::write_volatile(block_ptr::<u64>(self.block, OFF_DEPTH), v) };
    }

    /// Флаг NEED_RESCHED.
    pub fn need_resched(&self, v: u64) {
        // SAFETY: см. self_ptr.
        unsafe { core::ptr::write_volatile(block_ptr::<u64>(self.block, OFF_NEED_RESCHED), v) };
    }

    /// Квант текущего потока.
    pub fn quantum(&self, v: u64) {
        // SAFETY: см. self_ptr.
        unsafe { core::ptr::write_volatile(block_ptr::<u64>(self.block, OFF_QUANTUM), v) };
    }
}

/// Заполнение блока через [`BlockWriter::fill`] (сахар для читаемости).
pub fn write_block(block: u64, f: impl FnOnce(BlockWriter)) {
    BlockWriter::fill(block, f)
}
