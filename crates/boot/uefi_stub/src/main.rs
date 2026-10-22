// ==== UEFI STUB: загрузочная заглушка (kernel.efi) ====
//
// Один самодостаточный файл: образ ядра ВСТРОЕН в бинарь заглушки
// (include_bytes! — «статически связаны», по дизайну загрузки).
//
// Последовательность:
//   1. watchdog off; отладка — свой mini-UART COM1 (единый канал с ядром);
//   2. ESP рядом с kernel.efi: SimpleFileSystem -> boot_cfg.xml (bootcfg);
//   3. серверы конфигурации: чтение образов, argv-хвост в блоб модуля;
//   4. ядро из ВСТРОЕННОГО образа: сегменты на KERNEL_PHYS_BASE
//      (custom MemoryType — виден в карте как Kernel);
//   5. модули + BootInfo-страница (custom MemoryType);
//   6. RSDP из configuration tables (ACPI2);
//   7. ExitBootServices -> финальная карта памяти -> BootInfo.memory;
//   8. RDI = &BootInfo (физика) -> прыжок на вход ядра (смещение 0).
//
// После EBS — ноль аллокаций (RAII-владение забыто намеренно: память
// всё равно достаётся ядру).

#![no_main]
#![no_std]

extern crate alloc;

use core::panic::PanicInfo;

#[panic_handler]
fn stub_panic(info: &PanicInfo) -> ! {
    uart_puts("[stub] PANIC: ");
    if let Some(m) = info.message().as_str() {
        uart_puts(m);
    }
    uart_puts(" @ ");
    if let Some(l) = info.location() {
        let mut b = [0u8; 16];
        let s = l.file().as_bytes();
        let n = s.len().min(12);
        b[..n].copy_from_slice(&s[..n]);
        uart_puts(core::str::from_utf8(&b[..n]).unwrap_or("?"));
    }
    uart_puts("\r\n");
    loop {}
}

use alloc::{boxed::Box, vec::Vec};
use core::arch::asm;

use uefi::CString16;
use uefi::fs::FileSystem;
use uefi::mem::memory_map::MemoryMap as _;
use uefi::mem::memory_map::MemoryType as RawMemoryType;
// SimpleFileSystem открыт через uefi::fs::FileSystem (volume от boot services).
use uefi::table::cfg::ConfigTableEntry;

use boot_info::{
    BootInfo, FirmwareTables, KernelImage, MAX_MEMORY_REGIONS, MemoryKind, MemoryRegion, ModuleInfo,
};
use bootcfg;

// Образ ядра: встраивается при сборке (build.sh обновляет kernel.bin).
static KERNEL_ELF: &[u8] = include_bytes!("../kernel.bin");

// Физическая геометрия (ABI с head.S ядра — arch_x86::boot).
// Размещение ядра ДИНАМИЧЕСКОЕ: любой 2 MiB-выровненный адрес в
// [KERNEL_MIN_PHYS .. PHYSMAP_COVERAGE). Фиксированные 16 MiB заняты
// декомпрессированным DXE-том OVMF (0x900000..0x1780000) — как и Linux
// EFI stub, размещаем образ там, где есть место (сверху вниз).
const KERNEL_MIN_PHYS: u64 = 0x0100_0000; // выше legacy-дыр низких 16 MiB
const KERNEL_LINK_BASE: u64 = 0xFFFF_FFFF_8100_0000;
const PHYSMAP_COVERAGE: u64 = 4 << 30; // head.S physmap: 4 GiB
const ALIGN_2M: u64 = 0x20_0000;

// Custom MemoryType (0x8000_0000..=0xFFFF_FFFF — свободный диапазон UEFI).
const MT_KERNEL: RawMemoryType = RawMemoryType::custom(0x8000_0001);
const MT_MODULES: RawMemoryType = RawMemoryType::custom(0x8000_0002);
const MT_BOOTINFO: RawMemoryType = RawMemoryType::custom(0x8000_0003);

/// Зеркало uefi_raw ConfigurationTable (крейт uefi_raw приватен в uefi).
#[repr(C)]
struct RawConfigEntry {
    vendor_guid: uefi::Guid,
    vendor_table: *mut core::ffi::c_void,
}

const PAGE: u64 = 4096;

/// Hex u64 без alloc-форматирования.
fn hex(v: u64) -> alloc::string::String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16 {
        buf[2 + i] = H[((v >> ((15 - i) * 4)) & 0xF) as usize];
    }
    alloc::string::String::from_utf8_lossy(&buf).into_owned()
}

// ───────────────────── Mini-UART COM1 (отладка) ─────────────────────

unsafe fn outb(port: u16, v: u8) {
    unsafe { asm!(".intel_syntax noprefix", "out dx, al", in("dx") port, in("al") v) };
}

pub fn uart_puts(s: &str) {
    // Поллинг 16550: ждём пустой THR (LSR bit 5), шлём байт.
    for &b in s.as_bytes() {
        unsafe {
            let mut lsr: u8;
            loop {
                asm!(".intel_syntax noprefix", "in al, dx", in("dx") 0x3F8u16 + 5, out("al") lsr);
                if lsr & 0x20 != 0 {
                    break;
                }
            }
            outb(0x3F8, b);
        }
    }
}

fn log(s: &str) {
    uart_puts(s);
    uart_puts("\r\n");
}

// ───────────────────── ELF (минимальный разбор ELF64) ─────────────────────

#[repr(C)]
struct Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

fn read_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

fn read_u64(b: &[u8], off: usize) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(w)
}

/// (e_entry, суммарный размер образа в страницах, сегменты-слова).
fn parse_elf(elf: &[u8]) -> Option<(u64, u64, Vec<(u64, u64, u64, u64)>)> {
    if elf.len() < 64 || &elf[0..4] != b"\x7fELF" || elf[4] != 2 {
        return None; // не ELF64
    }
    let e_entry = read_u64(elf, 24);
    let e_phoff = read_u64(elf, 32) as usize;
    let e_phentsize = read_u16(elf, 54) as usize;
    let e_phnum = read_u16(elf, 56) as usize;
    let mut segs = Vec::new();
    let mut max_end = KERNEL_LINK_BASE;
    for i in 0..e_phnum {
        let off = e_phoff + i * e_phentsize;
        if off + e_phentsize > elf.len() {
            return None;
        }
        let ph: Phdr = unsafe {
            let mut p: Phdr = core::mem::zeroed();
            core::ptr::copy_nonoverlapping(
                elf.as_ptr().add(off),
                &mut p as *mut Phdr as *mut u8,
                core::mem::size_of::<Phdr>(),
            );
            p
        };
        if ph.p_type != 1 {
            continue; // только PT_LOAD
        }
        segs.push((ph.p_offset, ph.p_vaddr, ph.p_filesz, ph.p_memsz));
        let end = ph.p_vaddr.saturating_add(ph.p_memsz);
        if end > max_end {
            max_end = end;
        }
    }
    if segs.is_empty() {
        return None;
    }
    let image_len = max_end - KERNEL_LINK_BASE;
    Some((e_entry, image_len.div_ceil(PAGE), segs))
}

// ───────────────────── argv-хвост (протокол startup::elfload) ─────────────────────

const ARGV_TAIL_MAGIC: u32 = u32::from_le_bytes(*b"ARGV");

fn append_argv_tail(blob: &mut Vec<u8>, argv: &[&str]) {
    let start = blob.len();
    for a in argv {
        blob.extend_from_slice(a.as_bytes());
        blob.push(0);
    }
    let str_bytes = blob.len() - start;
    blob.extend_from_slice(&ARGV_TAIL_MAGIC.to_le_bytes());
    blob.extend_from_slice(&(str_bytes as u32).to_le_bytes());
    blob.extend_from_slice(&(argv.len() as u32).to_le_bytes());
}

// ───────────────────── Entry ─────────────────────

#[uefi::entry]
fn main() -> uefi::Status {
    // Watchdog off (ядро грузится дольше 5 минут по умолчанию).
    let _ = uefi::boot::set_watchdog_timer(0, 0, None);

    log("[stub] rust-l4 UEFI stub v0.5");

    // 1. ESP: SimpleFileSystem образа.
    let volume = match uefi::boot::get_image_file_system(uefi::boot::image_handle()) {
        Ok(v) => v,
        Err(e) => {
            log("[stub] FATAL: no file system next to image");
            let _ = e;
            return uefi::Status::NOT_FOUND;
        }
    };
    let mut fs = FileSystem::new(volume);

    // 2. boot_cfg.xml (рядом с kernel.efi).
    let cfg_path: &uefi::CStr16 = uefi::cstr16!("boot_cfg.xml");


    let cfg_text = match fs.read_to_string(cfg_path) {
        Ok(t) => t,
        Err(_) => {
            log("[stub] FATAL: cannot read boot_cfg.xml");
            return uefi::Status::NOT_FOUND;
        }
    };

    
    let cfg = match bootcfg::parse(&cfg_text) {
        Ok(c) => c,
        Err(e) => {
            log("[stub] FATAL: boot_cfg.xml schema");
            let _ = e;
            return uefi::Status::INVALID_PARAMETER;
        }
    };
    log("[stub] boot_cfg.xml parsed");

    if cfg.servers.is_empty() {
        log("[stub] FATAL: no servers in boot_cfg.xml (init required)");
        return uefi::Status::INVALID_PARAMETER;
    }

    // Дамп карты памяти (диагностика размещения ядра; всё до 4 GiB).
    if let Ok(mmap) = uefi::boot::memory_map(uefi::mem::memory_map::MemoryType::LOADER_DATA) {
        let mut i = 0;
        for d in mmap.entries() {
            let lo = d.phys_start;
            let hi = d.phys_start + d.page_count * PAGE;
            if hi > 0x0080_0000 && lo < PHYSMAP_COVERAGE {
                let mut b = [0u8; 96];
                let mut n = 0;
                let mut push = |b: &mut [u8], n: &mut usize, s: &str| {
                    let sb = s.as_bytes();
                    let m = sb.len().min(b.len() - *n);
                    b[*n..*n + m].copy_from_slice(&sb[..m]);
                    *n += m;
                };
                push(&mut b, &mut n, "mmap: ");
                push(&mut b, &mut n, &hex(lo));
                push(&mut b, &mut n, "..");
                push(&mut b, &mut n, &hex(hi));
                push(&mut b, &mut n, " t=");
                push(&mut b, &mut n, &hex(d.ty.0 as u64));
                push(&mut b, &mut n, "\r\n");
                uart_puts(core::str::from_utf8(&b[..n]).unwrap_or(""));
                i += 1;
                if i > 24 {
                    break;
                }
            }
        }
    }

    // 3. Ядро ПЕРВЫМ (динамическое размещение: модули AnyPages не должны
    //    занять выбранное место).
    let (entry, kernel_pages, segs) = match parse_elf(KERNEL_ELF) {
        Some(v) => v,
        None => {
            log("[stub] FATAL: embedded kernel ELF is invalid");
            return uefi::Status::LOAD_ERROR;
        }
    };
    if entry < KERNEL_LINK_BASE {
        log("[stub] FATAL: kernel entry below link base");
        return uefi::Status::LOAD_ERROR;
    }
    // head.S мапит образ 2 MiB-страницами: аллоцируем целый 2 MiB-хвост,
    // чтобы каждая замапленная страница принадлежала нам.
    let big_pages = (kernel_pages as u64).div_ceil(512) * 512; // 2 MiB-гранулы
    let kbase = match place_kernel(big_pages as usize) {
        Some(b) => b,
        None => {
            log("[stub] FATAL: no 2MiB-aligned free window for kernel");
            return uefi::Status::OUT_OF_RESOURCES;
        }
    };
    let kptr = kbase as *mut u8;
    unsafe {
        core::ptr::write_bytes(kptr, 0, (big_pages * PAGE) as usize);
        for (off, vaddr, filesz, memsz) in &segs {
            let dst = (kbase + (vaddr - KERNEL_LINK_BASE)) as *mut u8;
            core::ptr::copy_nonoverlapping(
                KERNEL_ELF.as_ptr().add(*off as usize),
                dst,
                *filesz as usize,
            );
            // [filesz..memsz) уже нули (обнулили весь образ).
            let _ = memsz;
        }
    }
    log(&alloc::format!(
        "[stub] kernel image placed at {} ({} pages)",
        hex(kbase),
        big_pages
    ));

    // 4. Серверы: образ + argv-хвост (модули протокола).
    let mut modules: Vec<(u64, u64, [u8; 32])> = Vec::new(); // (phys, len, name)
    for srv in &cfg.servers {
        let path: CString16 = match CString16::try_from(srv.path.as_str()) {
            Ok(p) => p,
            Err(_) => {
                log("[stub] FATAL: non-utf16 path (too long?)");
                return uefi::Status::INVALID_PARAMETER;
            }
        };
        // SAFETY: CString16 — нуль-терминированный UCS-2 буфер.
        let cpath: &uefi::CStr16 = unsafe { uefi::CStr16::from_ptr(path.as_ptr()) };
        let mut blob = match fs.read(cpath) {
            Ok(b) => b,
            Err(_) => {
                log("[stub] FATAL: cannot read server image");
                return uefi::Status::NOT_FOUND;
            }
        };
        // argv-хвост: только <arg> сервера. Имя программы НЕ дублируем:
        // elfload prepend'ит имя модуля (argv[0] по конвенции L4/Unix) —
        // баг v0.5.2: srv.name в хвосте давал двойной «init» в argv.
        let mut argv: Vec<&str> = Vec::new();
        for a in &srv.argv {
            argv.push(a.as_str());
        }
        append_argv_tail(&mut blob, &argv);

        // Размещение модуля.
        let pages = (blob.len() as u64).div_ceil(PAGE);
        let ptr = match uefi::boot::allocate_pages(
            uefi::boot::AllocateType::AnyPages,
            MT_MODULES,
            pages as usize,
        ) {
            Ok(p) => p,
            Err(_) => {
                log("[stub] FATAL: module allocation failed");
                return uefi::Status::OUT_OF_RESOURCES;
            }
        };
        unsafe {
            ptr.as_ptr()
                .copy_from_nonoverlapping(blob.as_ptr(), blob.len());
        }
        let mut name = [0u8; 32];
        let nb = srv.name.len().min(31);
        name[..nb].copy_from_slice(&srv.name.as_bytes()[..nb]);
        modules.push((ptr.as_ptr() as u64, blob.len() as u64, name));
    }
    log("[stub] servers loaded");

    // 5. BootInfo-страница.
    // Баг v0.5.2 (корень порчи test_mode): выделяли РОВНО 1 страницу,
    // а write_bytes-обнуление идёт на size_of::<BootInfo>() (~4.2 КиБ) —
    // обнуление вылезало за границу и затирало соседний пул UEFI
    // ( surgically: String «qemu» обнулялся -> var[1] теряла значение).
    // Выделяем ceil(size/PAGE) страниц — обнуление внутри своей памяти.
    let bi_pages = core::mem::size_of::<BootInfo>().div_ceil(PAGE as usize);
    let biptr =
        match uefi::boot::allocate_pages(uefi::boot::AllocateType::AnyPages, MT_BOOTINFO, bi_pages)
        {
            Ok(p) => p,
            Err(_) => {
                log("[stub] FATAL: bootinfo allocation failed");
                return uefi::Status::OUT_OF_RESOURCES;
            }
        };
    let bi_phys = biptr.as_ptr() as u64;
    let bi = biptr.as_ptr() as *mut BootInfo;
    unsafe {
        core::ptr::write_bytes(biptr.as_ptr(), 0, core::mem::size_of::<BootInfo>());
        let bi = &mut *bi;
        *bi = BootInfo::EMPTY;

        bi.module_count = modules.len().min(boot_info::MAX_MODULES as usize) as u32;
        for (i, (phys, len, name)) in modules.iter().enumerate() {
            if i >= boot_info::MAX_MODULES {
                break;
            }
            bi.modules[i] = ModuleInfo {
                base: *phys,
                len: *len,
                name: *name,
            };
        }
        bi.firmware = FirmwareTables {
            rsdp: find_rsdp(),
            dtb: 0,
        };
        bi.kernel = KernelImage {
            phys_base: kbase,
            virt_entry: entry,
            len: big_pages * PAGE,
        };
        let cmdline = if cfg.kernel_cmdline.is_empty() {
            "arch=x86_64 console=com1\0"
        } else {
            // Заглушка не интерпретирует cmdline (это политика ядра);
            // только ASCIIZ-обрезка по полю протокола.
            let owned = alloc::format!("{}\0", cfg.kernel_cmdline);
            if owned.len() > boot_info::CMDLINE_LEN {
                log("[stub] FATAL: kernel cmdline exceeds protocol field");
                return uefi::Status::INVALID_PARAMETER;
            }
            // Времянка живёт до конца main (после EBS не аллоцируем —
            // но копирование в BootInfo идёт ДО EBS).
            let leaked: &'static str = Box::leak(owned.into_boxed_str());
            leaked
        };
        bi.cmdline[..cmdline.len()].copy_from_slice(cmdline.as_bytes());
        // boot_state (транзит init).
        match cfg.boot_state_vars() {
            Ok(vars) => {
                for (i, v) in vars.iter().enumerate() {
                    if i >= boot_info::MAX_BOOT_STATE {
                        break;
                    }
                    bi.state[i] = *v;
                }
                bi.state_count = vars.len().min(boot_info::MAX_BOOT_STATE) as u32;
            }
            Err(_) => {
                log("[stub] FATAL: boot_state exceeds protocol limits");
                return uefi::Status::INVALID_PARAMETER;
            }
        }
    }
    log("[stub] boot_info v2 ready");

    // 6. Забыть RAII-владение (после EBS дропы звать boot services не
    //    могут; память достаётся ядру).
    core::mem::forget(fs);
    core::mem::forget(cfg_text);
    core::mem::forget(cfg);

    // 7. ExitBootServices -> финальная карта.
    let mmap = unsafe { uefi::boot::exit_boot_services(None) };
    log("[stub] boot services exited");

    // 8. Карта памяти -> BootInfo (после EBS: только запись в нашу
    //    страницу, никаких аллокаций).
    unsafe {
        let bi = &mut *bi;
        let mut n = 0usize;
        for desc in mmap.entries() {
            if n >= MAX_MEMORY_REGIONS {
                break;
            }
            let kind = mem_kind(desc.ty);
            if kind.is_none() {
                continue;
            }
            bi.memory[n] = MemoryRegion {
                base: desc.phys_start,
                len: desc.page_count * PAGE,
                kind: kind.unwrap(),
            };
            n += 1;
        }
        bi.memory_count = n as u32;

        // 9. Handoff: RDI = BootInfo phys, прыжок на вход ядра
        //    (entry_offset = 0: e_entry == KERNEL_LINK_BASE по ABI).
        let entry_off = entry - KERNEL_LINK_BASE;
        let target = kbase + entry_off;
        uart_puts("[stub] jumping to kernel\r\n");
        asm!(
            "cli",
            "mov rdi, {bi}",
            "jmp rax",
            bi = in(reg) bi_phys,
            in("rax") target,
            options(noreturn),
        );
    }
}

// ───────────────────── Динамическое размещение ядра ─────────────────────

/// Найти 2 MiB-выровненное окно [base..base+pages*4K) в свободной
/// (Conventional) памяти: [16 MiB .. 4 GiB), сверху вниз (низ оставляем
/// модулям/трамплину AP). AllocateAddress перепроверяет окно сам —
/// устаревший кандидат безопасно проваливается на следующий.
fn place_kernel(pages: usize) -> Option<u64> {
    let span = pages as u64 * PAGE;
    let mut candidates: Vec<u64> = Vec::new();
    if let Ok(mmap) = uefi::boot::memory_map(RawMemoryType::LOADER_DATA) {
        for d in mmap.entries() {
            if d.ty != RawMemoryType::CONVENTIONAL {
                continue;
            }
            let lo = d.phys_start.max(KERNEL_MIN_PHYS);
            let lo = (lo + ALIGN_2M - 1) & !(ALIGN_2M - 1); // 2 MiB вверх
            let hi = (d.phys_start + d.page_count * PAGE).min(PHYSMAP_COVERAGE);
            if hi <= lo || hi - lo < span {
                continue;
            }
            let top = (hi - span) & !(ALIGN_2M - 1); // верхний 2MiB-кандидат
            if top >= lo {
                candidates.push(top);
            }
        }
    }
    candidates.sort_unstable(); // по возрастанию — берём с конца (сверху)
    for &c in candidates.iter().rev() {
        if let Ok(p) =
            uefi::boot::allocate_pages(uefi::boot::AllocateType::Address(c), MT_KERNEL, pages)
        {
            return Some(p.as_ptr() as u64);
        }
    }
    None
}

/// Конвертация типа UEFI -> протокол загрузки (None — пропустить).
fn mem_kind(ty: RawMemoryType) -> Option<MemoryKind> {
    use uefi::mem::memory_map::MemoryType as MT;
    if ty == MT::CONVENTIONAL
        || ty == MT::BOOT_SERVICES_CODE
        || ty == MT::BOOT_SERVICES_DATA
        || ty == MT::LOADER_CODE
        || ty == MT::LOADER_DATA
    {
        // LOADER_* (наша карта после EBS) — свободная память.
        Some(MemoryKind::Available)
    } else if ty == MT_KERNEL {
        Some(MemoryKind::Kernel)
    } else if ty == MT_MODULES {
        Some(MemoryKind::Modules)
    } else if ty == MT_BOOTINFO {
        Some(MemoryKind::BootInfo)
    } else if ty == MT::ACPI_RECLAIM {
        Some(MemoryKind::AcpiReclaim)
    } else if ty == MT::ACPI_NON_VOLATILE {
        Some(MemoryKind::AcpiNvs)
    } else {
        // RUNTIME_*, MMIO, RESERVED, PERSISTENT, UNUSABLE, PAL...
        Some(MemoryKind::Reserved)
    }
}

/// RSDP из configuration tables (ACPI 2.0 preferred).
fn find_rsdp() -> u64 {
    let st = match uefi::table::system_table_raw() {
        Some(p) => p,
        None => return 0,
    };
    // SAFETY: system table валидна до/после EBS (runtime).
    let st = unsafe { st.as_ref() };
    let n = st.number_of_configuration_table_entries;
    let tbl = st.configuration_table as *const RawConfigEntry;
    for i in 0..n {
        // SAFETY: массив конфигураций длины n по указателю.
        let ct = unsafe { &*tbl.add(i) };
        if ct.vendor_table.is_null() {
            continue;
        }
        if ct.vendor_guid == ConfigTableEntry::ACPI2_GUID {
            return ct.vendor_table as u64;
        }
    }
    0
}
