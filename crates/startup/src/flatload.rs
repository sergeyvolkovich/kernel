// ==== Загрузка flat-бутстрапа + маппинг boot-архива (арх-независимо) ====
//
// Протокол загрузки v3: в ядре НЕТ парсера ELF (xmas-elf демонтирован
// с boot-пути). Модуль [0] BootInfo — boot-архив RLBA; здесь ядро
// делает ровно две «механические» вещи:
//
//   1. FLAT-загрузка бутстрапа: разбор FLX-заголовка + таблицы
//      сегментов (crate boot_archive — rigid-инварианты + CRC32),
//      кадры из ПУЛЯ ПОЛЬЗОВАТЕЛЯ (владение честное: запись фасада с
//      external=false, при смерти задачи кадры вернутся пулу),
//      отображение — [`UFacade::map_fixed`] по адресам сегментов,
//      копирование — через direct-map платформы (`phys_slice_mut`);
//   2. маппинг ВСЕГО архива RO на `ARCHIVE_BASE` (кадры — boot-память
//      модуля, external=true: они никогда не принадлежали пулу и не
//      вернутся ему при смерти задачи; разбор каталога/cpio — политика
//      юзерспейса-бутстрапа);
//
// далее — как в v2: стек старта по ABI платформы + argv-блок (имя
// «bootstrap» + boot_state-переменные как «имя=значение»; ARGV-хвост
// из протокола удалён — argv init-сервера собирает бутстрап из
// каталога RLBA при спавне).

use alloc::{string::String, vec::Vec};

use llfree::{Alloc, Class, Request, TREE_ORDER};

use boot_archive::{MAX_FLAT_SEGS, SegFlags};

use kernel_hal::traits::asid::ASIDInterface;
use kernel_hal::traits::kmap::KMAPInterface;
use kernel_hal::traits::mmap::{
    MMAPInterface, MMAPMemoryFlags, MemErrorCode, PhysADDR, VirtualADDR,
};
use pkg_generic_interface::GCTL;
use pkg_generic_interface::mem::{ARCPool, Arc, FacadeBox, MemoryManager};
use pkg_generic_interface::task::TaskId;

use crate::Platform;

/// Страница.
const PAGE: u64 = 4096;
/// Аргв-блок: 2 страницы (16 boot_state-переменных + argv, с запасом).
const ARGV_PAGES: usize = 2;
/// Смещение argv-блока вниз от вершины стека (вне стека, рядом).
const ARGV_BELOW_STACK: u64 = 1 << 20;
/// argv[0] первой задачи (конвенция протокола v3).
pub const BOOTSTRAP_NAME: &str = "bootstrap";

/// Результат загрузки.
pub struct LoadedInit {
    /// Точка входа (load_base + entry_off).
    pub entry: usize,
    /// argc стартового IPC.
    pub argc: usize,
    /// Виртуальный адрес argv-блока в пространстве бутстрапа.
    pub argv_vaddr: u64,
    /// Длина argv-блока, байт.
    pub argv_bytes: usize,
}

/// Ошибка загрузки (строка — диагностика для консоли).
pub type LoadError = &'static str;

// ───────────────────── Кадры из пула пользователя ─────────────────────

/// Выделить `pages` НЕПРЕРЫВНЫХ кадров из пула пользователя.
///
/// llfree выдаёт степени двойки: order = next_pow2(pages) (сверх — запас
/// кадры, записаны в регионе и вернутся пулу со смертью задачи).
fn user_frames(p_alloc: &Arc<ARCPool>, pages: usize) -> Result<u64, MemErrorCode> {
    let order = pages
        .checked_next_power_of_two()
        .map(|n| n.trailing_zeros() as usize)
        .ok_or(MemErrorCode::InvalidArgument("segment too large"))?;
    if order > TREE_ORDER {
        return Err(MemErrorCode::InvalidArgument(
            "segment exceeds llfree max order (2048 pages)",
        ));
    }
    let (fid, _) = p_alloc
        .as_ref()
        .get(None, Request::new(order, Class(0), None))
        .map_err(|_| MemErrorCode::NoMemoryLeft)?;
    Ok(fid.0 as u64 * PAGE)
}

// ───────────────────── Загрузка ─────────────────────

/// Локальный помощник: операция над фасадом задачи (map_fixed).
/// Отдельная generic-fn — impl-Trait в параметрах замыкания запрещён.
fn facade_map<MMAP: MMAPInterface + 'static>(
    mm: &MemoryManager<MMAP, ARCPool>,
    task: &TaskId,
    f: impl FnOnce(&mut pkg_generic_interface::mem::UFacade<MMAP, ARCPool>) -> Result<(), MemErrorCode>,
) -> Result<(), MemErrorCode> {
    mm.with_facade(task, f)
        .unwrap_or(Err(MemErrorCode::NotFound))
}

/// Загрузить flat-бутстрап в пространство задачи, смапить архив и
/// подготовить стартовый протокол.
///
/// Порядок: RLBA-заголовок (инварианты+CRC) → FLAT-сегменты
/// (map_fixed + копирование) → архив RO на ARCHIVE_BASE → стек →
/// argv-блок (значения уходят в стартовый IPC).
#[allow(clippy::too_many_arguments)]
pub fn load<P: Platform, MMAP: MMAPInterface + KMAPInterface + ASIDInterface + 'static>(
    platform: &P,
    gctl: &GCTL<MMAP>,
    task: TaskId,
    _facade: &'static FacadeBox<MMAP, ARCPool>,
    module_blob: &[u8],
    module_phys_base: u64,
    p_alloc: &Arc<ARCPool>,
    state_vars: &[(String, String)],
) -> Result<LoadedInit, LoadError> {
    // 0. Протокол RLBA: rigid-инварианты + CRC заголовка ДО маппинга
    //    (fail-closed: молчаливая работа с битой геометрией — дыра).
    let hdr = map_arch_err(boot_archive::parse_header(module_blob))?;
    map_arch_err(boot_archive::verify_header_crc(module_blob, &hdr))?;
    let (entry, nsegs, segs) = map_arch_err(boot_archive::parse_flat(module_blob, &hdr))?;
    let mm = gctl.memory_manager();

    // 1. FLAT-сегменты: кадры из пула пользователя, map_fixed, копия.
    //    [filesz..memsz) — нули (кадры из пула несут прошлый мусор).
    for s in segs.iter().take(nsegs) {
        let vstart = s.vaddr as u64;
        let pages = ((s.memsz as u64 + PAGE - 1) / PAGE) as usize;
        if pages == 0 {
            continue;
        }
        let mp = match SegFlags::from_bits(s.flags) {
            Some(SegFlags::Ro) => MMAPMemoryFlags::RO,
            Some(SegFlags::Rw) => MMAPMemoryFlags::RW,
            Some(SegFlags::Rx) => MMAPMemoryFlags::RX,
            // parse_flat уже отклонил прочие — здесь недостижимо.
            None => return Err("flat segment flags rejected by kernel policy"),
        };
        let phys = user_frames(p_alloc, pages).map_err(|_| "user pool exhausted")?;
        let dst = platform.phys_slice_mut(phys, pages * PAGE as usize);
        for b in dst[..s.memsz as usize].iter_mut() {
            *b = 0;
        }
        if s.filesz > 0 {
            let src = module_blob
                .get(
                    hdr.flat_off as usize + s.file_off as usize
                        ..hdr.flat_off as usize + s.file_off as usize + s.filesz as usize,
                )
                .ok_or("flat segment data out of blob bounds")?;
            dst[..s.filesz as usize].copy_from_slice(src);
        }
        facade_map(mm, &task, |f| {
            f.map_fixed(
                VirtualADDR(vstart as usize),
                PhysADDR(phys as usize),
                pages,
                mp,
                false,
            )
        })
        .map_err(|_| "map_fixed failed (flat segments overlap?)")?;
    }

    // 2. Boot-архив целиком — RO на ARCHIVE_BASE (zero-copy: бутстрап
    //    читает каталог/строки/cpio прямо из boot-памяти модуля).
    //    Кадры внешние (external=true): модульная память не принадлежит
    //    пулу и не возвращается ему при смерти задачи.
    let arch_pages = ((module_blob.len() as u64 + PAGE - 1) / PAGE) as usize;
    {
        let base = module_phys_base;
        if base % PAGE != 0 {
            return Err("module base is not page-aligned (protocol violation)");
        }
        facade_map(mm, &task, |f| {
            f.map_fixed(
                VirtualADDR(boot_archive::ARCHIVE_BASE as usize),
                PhysADDR(base as usize),
                arch_pages,
                MMAPMemoryFlags::RO,
                true,
            )
        })
        .map_err(|_| "map_fixed failed (archive overlap)")?;
    }

    // 3. Стек: [stack_top - pages*4K .. stack_top), RW, нули.
    let stack_top = platform.user_stack_top();
    let stack_pages = platform.user_stack_pages();
    if stack_top == 0 || stack_top % PAGE != 0 || stack_pages == 0 {
        return Err("platform ABI: bad stack geometry");
    }
    let stack_lo = stack_top - stack_pages as u64 * PAGE;
    let stack_phys =
        user_frames(p_alloc, stack_pages).map_err(|_| "user pool exhausted (stack)")?;
    {
        let dst = platform.phys_slice_mut(stack_phys, stack_pages * PAGE as usize);
        for b in dst.iter_mut() {
            *b = 0;
        }
    }
    facade_map(mm, &task, |f| {
        f.map_fixed(
            VirtualADDR(stack_lo as usize),
            PhysADDR(stack_phys as usize),
            stack_pages,
            MMAPMemoryFlags::RW,
            false,
        )
    })
    .map_err(|_| "map_fixed failed (stack overlap)")?;

    // 4. argv-блок: имя модуля + boot_state как k=v. ARGV-хвост v2
    //    удалён из протокола: argv init-сервера собирает бутстрап.
    let mut argv: Vec<String> = Vec::new();
    argv.push(String::from(BOOTSTRAP_NAME));
    for (k, v) in state_vars {
        let mut s = String::with_capacity(k.len() + v.len() + 1);
        s.push_str(k);
        s.push('=');
        s.push_str(v);
        argv.push(s);
    }
    let argc = argv.len();

    // Формат: [u64 argc][u64 ptr[argc]]..[u64 NULL][pad][asciiz-строки].
    // Указатели — виртуальные адреса пространства бутстрапа.
    let argv_vaddr = stack_top - ARGV_BELOW_STACK;
    let strings_off = (1 + argc + 2) * 8; // argc + ptrs + NULL + pad
    let mut block: Vec<u8> = Vec::with_capacity(strings_off);
    let mut strings: Vec<u8> = Vec::new();
    block.extend_from_slice(&(argc as u64).to_le_bytes());
    for a in &argv {
        let ptr = argv_vaddr + strings_off as u64 + strings.len() as u64;
        block.extend_from_slice(&ptr.to_le_bytes());
        strings.extend_from_slice(a.as_bytes());
        strings.push(0);
    }
    block.extend_from_slice(&0u64.to_le_bytes()); // NULL-терминатор
    block.extend_from_slice(&0u64.to_le_bytes()); // выравнивание до строк
    debug_assert_eq!(block.len(), strings_off);
    block.extend_from_slice(&strings);

    let argv_bytes = block.len();
    if argv_bytes > ARGV_PAGES * 4096 {
        return Err("argv block exceeds 2 pages (too many boot_state vars?)");
    }
    let argv_phys = user_frames(p_alloc, ARGV_PAGES).map_err(|_| "user pool exhausted (argv)")?;
    {
        let dst = platform.phys_slice_mut(argv_phys, ARGV_PAGES * 4096);
        for b in dst.iter_mut() {
            *b = 0;
        }
        dst[..argv_bytes].copy_from_slice(&block);
    }
    facade_map(mm, &task, |f| {
        f.map_fixed(
            VirtualADDR(argv_vaddr as usize),
            PhysADDR(argv_phys as usize),
            ARGV_PAGES,
            MMAPMemoryFlags::RW,
            false,
        )
    })
    .map_err(|_| "map_fixed failed (argv overlap)")?;

    Ok(LoadedInit {
        entry: entry as usize,
        argc,
        argv_vaddr,
        argv_bytes,
    })
}

/// Перевод ошибки формата в диагностику консоли (единый префикс).
fn map_arch_err<T>(r: Result<T, boot_archive::ArchiveError>) -> Result<T, LoadError> {
    r.map_err(|e| match e {
        boot_archive::ArchiveError::BadMagic => "RLBA: bad magic",
        boot_archive::ArchiveError::BadVersion => "RLBA: bad version",
        boot_archive::ArchiveError::BadGeometry => "RLBA: bad geometry",
        boot_archive::ArchiveError::BadCrc => "RLBA: crc mismatch",
        boot_archive::ArchiveError::TooManyEntries => "RLBA: catalog overflow",
        boot_archive::ArchiveError::TooManySegments => "RLBA: too many flat segments",
        boot_archive::ArchiveError::NoInitEntry => "RLBA: no init entry",
        boot_archive::ArchiveError::NameOutOfBounds => "RLBA: name out of bounds",
        boot_archive::ArchiveError::ArgsOutOfBounds => "RLBA: args out of bounds",
        boot_archive::ArchiveError::SegNotAligned => "RLBA: segment not aligned",
        boot_archive::ArchiveError::SegFlagsInvalid => "RLBA: segment flags invalid",
        boot_archive::ArchiveError::SegOverlap => "RLBA: segments overlap",
    })
}

// Предел сегментов фиксируется протоколом (тест раскладки в boot_archive).
const _: () = assert!(
    MAX_FLAT_SEGS >= 3,
    "flat image needs text/rodata/data at least"
);
