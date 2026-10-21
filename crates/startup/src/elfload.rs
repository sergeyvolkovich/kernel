// ==== Загрузка init-сервера (арх-независимо) ====
//
// Разбор ELF64 (xmas-elf, готовый крейт «на краю») и перенос сегментов в
// адресное пространство задачи по ФИКСИРОВАННЫМ линк-адресам:
//
//   * кадры — из ПУЛЯ ПОЛЬЗОВАТЕЛЯ (владение честное: запись фасада с
//     external=false, при смерти задачи кадры вернутся пулу);
//   * отображение — [`UFacade::map_fixed`] (окно фасада не расходуется:
//     ELF несёт свои адреса);
//   * копирование — через direct-map платформы (`phys_slice_mut`);
//   * стек старта — фиксированный регион под вершиной ABI платформы;
//   * argv-блок — протокол старта: [argc][ptr...][NULL][asciiz...]:
//     имя модуля + argv из boot_cfg.xml (хвост блоба, пишет заглушка) +
//     boot_state-переменные как «имя=значение» (транзит init).

use alloc::{string::String, vec::Vec};

use llfree::{Alloc, Class, Request, TREE_ORDER};
use xmas_elf::ElfFile;
use xmas_elf::program::Type;

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

/// Результат загрузки.
pub struct LoadedInit {
    /// Точка входа (e_entry).
    pub entry: usize,
    /// argc стартового IPC.
    pub argc: usize,
    /// Виртуальный адрес argv-блока в пространстве init.
    pub argv_vaddr: u64,
    /// Длина argv-блока, байт.
    pub argv_bytes: usize,
}

/// Ошибка загрузки (строка — диагностика для консоли).
pub type LoadError = &'static str;

// ───────────────────── Хвост блоба: argv из boot_cfg.xml ─────────────────────

/// Магия argv-хвоста, дописанного заглушкой в конец блоба модуля.
pub const ARGV_TAIL_MAGIC: u32 = u32::from_le_bytes(*b"ARGV");

/// Хвост (последние 12 байт блоба): `[u32 magic][u32 str_bytes][u32 argc]`,
/// перед ним — ASCIIZ-строки. Неверная магия — хвоста нет (модуль без argv).
pub fn parse_argv_tail(blob: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    if blob.len() < 12 {
        return strings;
    }
    let tail = &blob[blob.len() - 12..];
    let magic = u32::from_le_bytes([tail[0], tail[1], tail[2], tail[3]]);
    if magic != ARGV_TAIL_MAGIC {
        return strings;
    }
    let str_bytes = u32::from_le_bytes([tail[4], tail[5], tail[6], tail[7]]) as usize;
    let argc = u32::from_le_bytes([tail[8], tail[9], tail[10], tail[11]]) as usize;
    if str_bytes + 12 > blob.len() {
        return strings; // битый хвост — тихо считаем «без argv»
    }
    let mut bytes = &blob[blob.len() - 12 - str_bytes..blob.len() - 12];
    for _ in 0..argc {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        if end == 0 {
            break;
        }
        if let Ok(s) = core::str::from_utf8(&bytes[..end]) {
            strings.push(String::from(s));
        }
        if end + 1 > bytes.len() {
            break;
        }
        bytes = &bytes[end + 1..];
    }
    strings
}

/// Дописать argv-хвост к блобу модуля (сторона заглушки/хост-инструментов).
pub fn append_argv_tail(blob: &mut Vec<u8>, argv: &[&str]) {
    let mut strings = Vec::new();
    for a in argv {
        strings.extend_from_slice(a.as_bytes());
        strings.push(0);
    }
    blob.extend_from_slice(&strings);
    blob.extend_from_slice(&ARGV_TAIL_MAGIC.to_le_bytes());
    blob.extend_from_slice(&(strings.len() as u32).to_le_bytes());
    blob.extend_from_slice(&(argv.len() as u32).to_le_bytes());
}

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

/// Загрузить init в пространство задачи и подготовить стартовый протокол.
///
/// Порядок: ELF-разбор → сегменты (map_fixed + копирование) → стек →
/// argv-блок (значения уходят в стартовый IPC).
#[allow(clippy::too_many_arguments)]
pub fn load<P: Platform, MMAP: MMAPInterface + KMAPInterface + ASIDInterface + 'static>(
    platform: &P,
    gctl: &GCTL<MMAP>,
    task: TaskId,
    _facade: &'static FacadeBox<MMAP, ARCPool>,
    blob: &[u8],
    module_name: &str,
    p_alloc: &Arc<ARCPool>,
    state_vars: &[(String, String)],
) -> Result<LoadedInit, LoadError> {
    let elf = ElfFile::new(blob).map_err(|e| e)?;
    let mm = gctl.memory_manager();

    // 1. Сегменты PT_LOAD: кадры из пула пользователя, map_fixed, копия.
    for ph in elf.program_iter() {
        if ph.get_type() != Ok(Type::Load) {
            continue;
        }
        let mp = segment_flags(ph.flags());
        let vaddr = ph.virtual_addr();
        let filesz = ph.file_size();
        let memsz = ph.mem_size();
        if memsz == 0 {
            continue;
        }
        let vstart = vaddr & !(PAGE - 1);
        let vend = (vaddr + memsz + PAGE - 1) & !(PAGE - 1);
        let pages = ((vend - vstart) / PAGE) as usize;

        let phys = user_frames(p_alloc, pages).map_err(|_| "user pool exhausted")?;
        // Кадры из пула содержат прошлый мусор: нули по memsz-окну, затем
        // файл (BSS-хвост остаётся нулевым).
        let dst = platform.phys_slice_mut(phys, pages * PAGE as usize);
        let off = (vaddr - vstart) as usize;
        for b in dst[off..off + memsz as usize].iter_mut() {
            *b = 0;
        }
        if filesz > 0 {
            let src = blob
                .get(ph.offset() as usize..(ph.offset() + filesz) as usize)
                .ok_or("segment file data out of blob bounds")?;
            dst[off..off + filesz as usize].copy_from_slice(src);
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
        .map_err(|_| "map_fixed failed (ELF segments overlap?)")?;
    }
    let entry = elf.header.pt2.entry_point();
    if entry == 0 {
        return Err("ELF entry point is zero");
    }

    // 2. Стек: [stack_top - pages*4K .. stack_top), RW, нули.
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

    // 3. argv-блок: имя модуля + argv из boot_cfg + boot_state как k=v.
    let mut argv: Vec<String> = Vec::new();
    argv.push(String::from(module_name));
    argv.extend(parse_argv_tail(blob));
    for (k, v) in state_vars {
        let mut s = String::with_capacity(k.len() + v.len() + 1);
        s.push_str(k);
        s.push('=');
        s.push_str(v);
        argv.push(s);
    }
    let argc = argv.len();

    // Формат: [u64 argc][u64 ptr[argc]]..[u64 NULL][pad][asciiz-строки].
    // Указатели — виртуальные адреса пространства init.
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

/// W^X-перевод флагов сегмента (требование контракта MMAPMemoryFlags:
/// W и X вместе запрещены; W+X-сегмент сознательно теряет X — v0.5).
fn segment_flags(f: xmas_elf::program::Flags) -> MMAPMemoryFlags {
    if f.is_write() {
        MMAPMemoryFlags::RW
    } else if f.is_execute() {
        MMAPMemoryFlags::RX
    } else {
        MMAPMemoryFlags::RO
    }
}
