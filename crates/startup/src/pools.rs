// ==== Физические пулы из BootInfo (арх-независимо) ====
//
// Два РАЗДЕЛЬНЫХ источника кадров (владельческая гигиена L4):
//
//   * пул ЯДРА — heap (talc), таблицы страниц, slab-кэши: LLFree над
//     [span_lo..K), адрес кадра = span_lo + fid*4K (mem_base у gallocator);
//   * пул ПОЛЬЗОВАТЕЛЯ — страницы задач (UFacade): LLFree над [0..span_hi)
//     с fid 0 = физика 0 (инвариант ядра: p_addr = fid * FRAME_SIZE),
//     свободен диапазон [K..span_hi).
//
// Построение: Init::AllocAll (всё занято) + избирательное освобождение
// ТОЛЬКО Available-пересечений (крупные куски — order-9 по 2 MiB, края —
// order-0). Мусор UEFI/наши образы/ACPI-области автоматически остаются
// занятыми: карта загрузки — единственный источник истины.
//
// Ограничение v0.5 (задокументировано): статические буферы метаданных
// рассчитаны на RAM ≤ 2 GiB; превышение — паника с внятным текстом.

use llfree::{Alloc, Class, Classing, FrameId, HUGE_ORDER, LLFree, MetaData, Request};

use boot_info::{BootInfo, MemoryKind};

use crate::Platform;

/// 2 MiB — гранула крупного освобождения (HUGE_ORDER=9 × 4K = 512 кадров).
const CHUNK: u64 = (512 * 4096) as u64;
/// Предел RAM (статические буферы метаданных).
pub const MAX_RAM_BYTES: u64 = 2 << 30;
/// Ядровый пул: максимум (кучи/таблиц достаточно с запасом).
const KERNEL_POOL_BYTES: u64 = 64 << 20;
/// Минимум пользовательского пула для загрузки (иначе — фатал).
const MIN_USABLE_BYTES: u64 = 8 << 20;

// ───────────────────── Статические буферы метаданных ─────────────────────

#[repr(align(64))]
struct Buf<const N: usize>([u8; N]);

static K_LOCAL: Buf<8192> = Buf([0; 8192]);
static K_TREES: Buf<262144> = Buf([0; 262144]);
static K_LOWER: Buf<131072> = Buf([0; 131072]);

static U_LOCAL: Buf<8192> = Buf([0; 8192]);
static U_TREES: Buf<262144> = Buf([0; 262144]);
static U_LOWER: Buf<131072> = Buf([0; 131072]);

/// Пулы, готовые к передаче подсистемам (значения забираются one-shot).
pub struct Pools {
    kernel: Option<LLFree<'static>>,
    /// Физическая база кадра 0 ядрового пула (= span_lo).
    pub kernel_base: u64,
    user: Option<LLFree<'static>>,
    /// Граница пулов: [kernel_base..split) — ядро, [split..span_hi) —
    /// пользователь (физика пользователя напрямую).
    pub split: u64,
    /// Верх RAM-спана.
    pub span_hi: u64,
}

impl Pools {
    /// Забрать LLFree ядрового пула (для `gallocator::init_frames`).
    pub fn take_kernel(&mut self) -> LLFree<'static> {
        self.kernel.take().expect("kernel pool taken twice")
    }

    /// Забрать LLFree пользовательского пула (для `install_p_allocator`).
    pub fn take_user(&mut self) -> LLFree<'static> {
        self.user.take().expect("user pool taken twice")
    }
}

// ───────────────────── Построение ─────────────────────

/// Собрать пулы из карты загрузки.
///
/// Геометрия: span_lo = выровненная вниз база образа ядра (самый низкий
/// Kernel/Modules/BootInfo регион); span_hi = выровненный вниз конец
/// самого верхнего Available-региона.
pub fn build<P: Platform>(bi: &BootInfo, platform: &P) -> Pools {
    // 1. Границы спана.
    let span_lo = bi
        .memory_regions()
        .iter()
        .filter(|r| {
            matches!(
                r.kind,
                MemoryKind::Kernel | MemoryKind::Modules | MemoryKind::BootInfo
            )
        })
        .map(|r| r.base)
        .min()
        .unwrap_or(0);
    let span_hi = bi
        .memory_regions()
        .iter()
        .filter(|r| r.kind == MemoryKind::Available)
        .map(|r| r.base + r.len)
        .max()
        .unwrap_or(0);
    let span_lo = span_lo & !(CHUNK - 1);
    let span_hi = span_hi & !(CHUNK - 1);

    if span_hi <= span_lo || span_hi - span_lo < MIN_USABLE_BYTES {
        crate::fatal(platform, "pools: FATAL not enough RAM in boot map\r\n");
    }
    if span_hi > MAX_RAM_BYTES {
        crate::fatal(
            platform,
            "pools: FATAL RAM exceeds v0.5 limit (2 GiB static metadata)\r\n",
        );
    }

    // 2. Раздел: ядру min(KERNEL_POOL, 3/4 спана), выровнено на 2 MiB.
    let span_len = span_hi - span_lo;
    let kernel_len = KERNEL_POOL_BYTES.min(span_len * 3 / 4) & !(CHUNK - 1);
    let split = span_lo + kernel_len;

    // 3. LLFree-пулы поверх статики: всё занято.
    let (k_cl, _) = Classing::simple(1);
    let (u_cl, _) = Classing::simple(1);
    let kernel = make_llfree(
        &k_cl,
        (kernel_len / 4096) as usize,
        &K_LOCAL,
        &K_TREES,
        &K_LOWER,
        "kernel",
    );
    // Пользовательский пул покрывает [0..span_hi): fid = физика/4K
    // (инвариант UFacade p_addr = fid*FRAME_SIZE).
    let user = make_llfree(
        &u_cl,
        (span_hi / 4096) as usize,
        &U_LOCAL,
        &U_TREES,
        &U_LOWER,
        "user",
    );

    // 4. Освобождение ТОЛЬКО Available-пересечений со своим диапазоном.
    for r in bi.memory_regions().iter() {
        if r.kind != MemoryKind::Available {
            continue;
        }
        let lo = r.base;
        let hi = r.base + r.len;
        // Ядровая часть [span_lo..split): fid относительно span_lo.
        free_range(&kernel, span_lo, span_lo, split, lo, hi);
        // Пользовательская часть [split..span_hi): fid = физика/4K.
        free_range(&user, 0, split, span_hi, lo, hi);
    }

    // 5. Санити: проба аллокации обязана попасть в свой диапазон
    //    (расхождение геометрии с картой — фатально и РАНЬШЕ всех).
    probe(&kernel, span_lo, span_lo, split, "kernel");
    probe(&user, 0, split, span_hi, "user");

    Pools {
        kernel: Some(kernel),
        kernel_base: span_lo,
        user: Some(user),
        split,
        span_hi,
    }
}

/// LLFree над статическими буферами (Init::AllocAll — всё занято).
fn make_llfree(
    cl: &Classing,
    frames: usize,
    local: &'static Buf<8192>,
    trees: &'static Buf<262144>,
    lower: &'static Buf<131072>,
    name: &str,
) -> LLFree<'static> {
    let need = LLFree::metadata_size(cl, frames);
    assert!(
        need.local <= local.0.len() && need.trees <= trees.0.len() && need.lower <= lower.0.len(),
        "pools: {name} metadata exceeds static buffer (frames={frames}, need local={} trees={} lower={})",
        need.local,
        need.trees,
        need.lower
    );
    // SAFETY: буферы — статика, срезы 'static честны; длины обрезаны по
    // потребности (проверка выше). Init::AllocAll полностью инициализирует
    // метаданные — мусор в буферах не читается.
    let meta = unsafe {
        MetaData {
            local: core::slice::from_raw_parts_mut(local.0.as_ptr() as *mut u8, need.local),
            trees: core::slice::from_raw_parts_mut(trees.0.as_ptr() as *mut u8, need.trees),
            lower: core::slice::from_raw_parts_mut(lower.0.as_ptr() as *mut u8, need.lower),
        }
    };
    LLFree::new(frames, llfree::Init::AllocAll, cl, meta)
        .unwrap_or_else(|_| panic!("pools: {name} LLFree::new failed"))
}

/// Освободить пересечение [lo..hi) ∩ [range_lo..range_hi) пула.
///
/// `fid_base` — физика кадра fid=0 этого пула (ядровый: span_lo;
/// пользовательский: 0). Внутренность — order-9 (2 MiB) кусками,
/// края — order-0. Кадр физики 0 не раздаём никогда (нулевой указатель).
fn free_range(
    llf: &LLFree<'static>,
    fid_base: u64,
    range_lo: u64,
    range_hi: u64,
    lo: u64,
    hi: u64,
) {
    let lo = lo.max(range_lo);
    let hi = hi.min(range_hi);
    if hi <= lo {
        return;
    }
    // Выравнивание по страницам.
    let lo = (lo + 4095) & !4095;
    let hi = hi & !4095;
    if hi <= lo {
        return;
    }
    let mut fid = ((lo - fid_base) / 4096) as usize;
    let end = ((hi - fid_base) / 4096) as usize;

    // Кадр физики 0 не освобождаем (user-пул, крайний случай).
    if fid_base == 0 && fid == 0 {
        fid = 1;
    }

    // Крупные куски: 2 MiB, выровненные на 512 кадров.
    while fid + 512 <= end && fid % 512 == 0 {
        let _ = llf.put(FrameId(fid), Request::new(HUGE_ORDER, Class(1), None));
        fid += 512;
    }
    // Остаток — постранично.
    while fid < end {
        let _ = llf.put(FrameId(fid), Request::new(0, Class(0), None));
        fid += 1;
    }
}

/// Проба: выделить кадр, проверить диапазон, вернуть в пул.
fn probe(llf: &LLFree<'static>, fid_base: u64, want_lo: u64, want_hi: u64, name: &str) {
    match llf.get(None, Request::new(0, Class(0), None)) {
        Ok((fid, _)) => {
            let phys = fid_base + fid.0 as u64 * 4096;
            assert!(
                phys >= want_lo && phys < want_hi,
                "pools: {name} probe gave phys {phys:#x} outside [{want_lo:#x}..{want_hi:#x})"
            );
            let _ = llf.put(fid, Request::new(0, Class(0), None));
        }
        Err(_) => panic!("pools: {name} pool is EMPTY — no Available frames in range"),
    }
}
