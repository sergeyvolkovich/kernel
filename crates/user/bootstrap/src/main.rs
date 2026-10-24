// ==== BOOTSTRAP: первая задача (протокол загрузки v3) ====
//
// Flat-executable из заголовка RLBA: ядро (kinit::flatload) больше не
// знает ELF — разбор архива, целостность и спавн init-сервера —
// политика ЭТОЙ задачи (модель seL4 root task, шаги S1..S8):
//
//   S1  стартовое IPC от ядра: argc/argv (argv[0]=«bootstrap»,
//       boot_state k=v + rsdp=… + archive_len=… транзитом);
//   S2  каталог RLBA: инварианты + CRC32 заголовка (ядро проверило то
//       же — здесь защита от порчи В ПАМЯТИ между kinit и стартом);
//   S3  INIT-запись каталога: CRC32 данных (verify-then-use) →
//       pie::Plan (ELF-разбор — в юзерспейсе, ET_EXEC StaticFixed);
//   S4  стейджинг: MEM_ALLOC-регионы для сегментов/стека/argv,
//       копирование из RO-архива (архив мапнут ядром на ARCHIVE_BASE);
//   S5  TASK_SPAWN_IMAGE: init-домен из готового образа;
//   S6  MEM_MAP_AT: архив RO в пространство init (тот же ARCHIVE_BASE)
//       — init читает каталог/спавнит серверы без копий;
//   S7  CAP_SEND: init получает гранты root-сервера (IommuAdmin +
//       IoResource Mmio/IoPort/Irq) и TaskTCB(самого себя);
//   S8  парковка: внешние кадры init принадлежат бутстрапу (L4 pager)
//       — он живёт вечно, дожидаясь сообщений на open-receive.
//
// Никакой кучи: статика + сырые слова (дисциплина userlib-серверов).

#![no_std]
#![no_main]

use boot_archive::{
    ARCHIVE_BASE, ArchiveError, entry_args, entry_data, entry_name, entry_verify, find_init,
    parse_header, verify_header_crc,
};
use pie::{ImageKind, Plan};

use userlib::{
    USER_STACK_PAGES, USER_STACK_TOP, l4_cap_list, l4_cap_send, l4_ipc_recv_any, l4_mem_alloc,
    l4_mem_map_at, l4_sys_time, l4_task_spawn_image,
};

// ───────────────────────── Константы протокола ─────────────────────────

/// TaskId init-домена (детерминизм отладки; lo/hi слова ABI).
const INIT_TASK_ID_LO: u64 = 0x2000;
const INIT_TASK_ID_HI: u64 = 0x0;
/// ThreadId главного потока init (НЕ 0x2001..0x2003 — это внутренние
/// TID воркеров init; главный поток — 0x2100).
const INIT_THREAD_ID_LO: u64 = 0x2100;
/// Приоритет init (как у kinit-задач v2: 120).
const INIT_PRIORITY: u8 = 120;
/// Права кодирования MMAPMemoryFlags.
const FLAG_RO: u64 = 0b001;
const FLAG_RW: u64 = 0b011;
/// Аргв-блок init: 2 страницы, на 1 МиБ ниже вершины стека
/// (та же геометрия, что у kinit::flatload для бутстрапа).
const ARGV_PAGES: u64 = 2;
const ARGV_BELOW_STACK: u64 = 1 << 20;
/// Максимум сегментов дескриптора спавна (ABI ядра: 16).
const MAX_SPAWN_SEGS: usize = 16;
/// Максимум argv-слов init (boot_state + служебные + args каталога).
const MAX_ARGV: usize = 24;
/// Kind-коды CAP_LIST (ABI ядра), передаваемые init.
const CAP_KIND_TASK_TCB: i64 = 2;
const CAP_KIND_IOMMU_ADMIN: i64 = 5;
const CAP_KIND_IO_MMIO: i64 = 6;
const CAP_KIND_IO_PORT: i64 = 7;
const CAP_KIND_IO_IRQ: i64 = 8;

// ───────────────────────── Статика (без кучи) ─────────────────────────

/// Дескриптор спавна: заголовок 0x70 + 16 сегментов по 32 байта
/// (байтовые записи — выравнивание не требуется).
static mut SPAWN_DESC: [u8; 0x70 + MAX_SPAWN_SEGS * 32] = [0; 0x70 + MAX_SPAWN_SEGS * 32];

/// Аргв-блок init (собирается здесь, копируется в MEM_ALLOC-регион;
/// байтовые записи — выравнивание не требуется).
static mut ARGV_BLOCK: [u8; 8192] = [0; 8192];

/// Кольцевой скретч для ASCIIZ→&str (однопоточная фаза; 8 слотов
/// достаточно: разбор argv идёт последовательно, ссылки не живут
/// дольше итерации... кроме массива argv-строк — он тоже ≤ MAX_ARGV).
static mut CSTR_SCRATCH: [[u8; 128]; 32] = [[0; 128]; 32];
static mut CSTR_NEXT: usize = 0;

// ───────────────────────── Печать ─────────────────────────

fn puts(s: &str) {
    // SAFETY-контракт: порции ≤40 байт; l4_debug_write_bytes — safe
    // обёртка над DEBUG_WRITE (сама разыменовывает слайс по len).
    let mut rest = s.as_bytes();
    while !rest.is_empty() {
        let n = rest.len().min(40);
        userlib::l4_debug_write_bytes(rest[..n].as_ptr(), n as u64);
        rest = &rest[n..];
    }
    userlib::l4_debug_write_bytes(b"\r\n".as_ptr(), 2);
}

fn putdec(prefix: &str, v: u64) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    let mut x = v;
    loop {
        i -= 1;
        buf[i] = b'0' + (x % 10) as u8;
        x /= 10;
        if x == 0 {
            break;
        }
    }
    for chunk in prefix.as_bytes().chunks(40) {
        userlib::l4_debug_write_bytes(chunk.as_ptr(), chunk.len() as u64);
    }
    for chunk in buf[i..].chunks(40) {
        userlib::l4_debug_write_bytes(chunk.as_ptr(), chunk.len() as u64);
    }
    userlib::l4_debug_write_bytes(b"\r\n".as_ptr(), 2);
}

/// Фаталь: печать + TASK_EXIT(код) (бутстрап умер — образ не поднялся,
/// честный отказ вместо молчаливой деградации).
fn fatal(what: &str, code: u64) -> ! {
    puts(what);
    userlib::l4_task_exit(code)
}

// ───────────────────────── Утилиты ─────────────────────────

/// Запись u64-слова в буфер дескриптора (little-endian).
///
/// SAFETY-контракт: [desc+off, desc+off+8) — валидная для записи
/// память (static mut SPAWN_DESC, однопоточная фаза).
unsafe fn desc_word(desc: *mut u8, off: usize, v: u64) {
    unsafe {
        core::ptr::copy_nonoverlapping(v.to_le_bytes().as_ptr(), desc.add(off), 8);
    }
}

/// Обнулить регион MEM_ALLOC (кадры из пула несут прошлый мусор).
///
/// SAFETY-контракт: [vaddr, vaddr+len) — валидное RW-окно вызывающего.
unsafe fn zero_region(vaddr: u64, len: u64) {
    unsafe {
        let p = vaddr as *mut u8;
        for i in 0..len as usize {
            p.add(i).write_volatile(0);
        }
    }
}

/// Слотов скретча (константа: `.len()` на static mut создаёт ссылку).
const CSTR_SLOTS: usize = 32;

/// ASCIIZ C-стрелка → &str через статический скретч (без кучи; буферы
/// кольцевые: одновременно живёт не больше CSTR_SLOTS строк).
///
/// SAFETY-контракт: p — нуль-терминированная строка (≤127 байт)
/// в валидной памяти вызывающего; фаза однопоточна.
unsafe fn cstr(p: *const i8) -> &'static str {
    const MAX: usize = 127;
    const SLOT: usize = 128;
    let b = p as *const u8;
    // SAFETY: static mut — только raw-указатели (edition 2024);
    // однопоточная фаза (до спавна и парковки).
    let slot: *mut u8 = unsafe {
        let idx = CSTR_NEXT;
        CSTR_NEXT = (idx + 1) % CSTR_SLOTS;
        core::ptr::addr_of_mut!(CSTR_SCRATCH)
            .cast::<u8>()
            .add(idx * SLOT)
    };
    let mut n = 0usize;
    // SAFETY: читаем до нуля или MAX байт — контракт указателя.
    unsafe {
        while n < MAX && b.add(n).read_volatile() != 0 {
            slot.add(n).write_volatile(b.add(n).read_volatile());
            n += 1;
        }
        slot.add(n).write_volatile(0);
        // Живучесть: скретч — статическая память; ссылки живут только
        // в однопоточной фазе (кольцо не перекрывает живые слоты).
        core::str::from_utf8_unchecked(core::slice::from_raw_parts(slot, n))
    }
}

// ───────────────────────── main ─────────────────────────

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const i8) -> i32 {
    puts("bootstrap: up (root task, boot protocol v3)");
    putdec("bootstrap: sys_time = ", l4_sys_time() as u64);

    // S1: найти archive_len в транзитных boot_state (kinit добавляет
    // его к argv вместе с rsdp=…; без него образ не читается).
    let mut archive_len: u64 = 0;
    for i in 0..argc.max(0) as usize {
        // SAFETY: argv-блок построен ядром (2 страницы под стеком);
        // ASCIIZ-строки по контракту стартового протокола.
        let p = unsafe { *argv.add(i) };
        if p.is_null() {
            break;
        }
        let s = unsafe { cstr(p) };
        if let Some(rest) = s.strip_prefix("archive_len=") {
            archive_len = rest.parse().unwrap_or(0);
        }
    }
    if archive_len == 0 || archive_len > 64 << 20 {
        fatal("bootstrap: FATAL no archive_len in start argv", 1);
    }
    putdec("bootstrap: archive bytes = ", archive_len);

    // S2: RLBA-заголовок (архив — RO на ARCHIVE_BASE, мапнут ядром).
    // SAFETY: ядро замапило [ARCHIVE_BASE, ARCHIVE_BASE+len) RO ДО
    // первого такта этой задачи (контракт kinit::flatload).
    let blob =
        unsafe { core::slice::from_raw_parts(ARCHIVE_BASE as *const u8, archive_len as usize) };
    let hdr = match parse_header(blob) {
        Ok(h) => h,
        Err(e) => fatal(arch_fatal(e), 2),
    };
    if let Err(e) = verify_header_crc(blob, &hdr) {
        fatal(arch_fatal(e), 2);
    }
    putdec("bootstrap: catalog entries = ", hdr.catalog_count as u64);

    // S3: INIT-запись: имя, argv из каталога, CRC32 данных, ELF-план.
    let entry = match find_init(blob, &hdr) {
        Ok(e) => e,
        Err(e) => fatal(arch_fatal(e), 3),
    };
    let name = entry_name(blob, &hdr, &entry).unwrap_or("?");
    let args = entry_args(blob, &hdr, &entry).unwrap_or(None);
    if let Err(e) = entry_verify(blob, &entry) {
        fatal(arch_fatal(e), 4);
    }
    let init_data = match entry_data(blob, &entry) {
        Ok(d) => d,
        Err(e) => fatal(arch_fatal(e), 4),
    };
    puts("bootstrap: init CRC32 ok, parsing ELF");
    let plan = match Plan::parse(init_data) {
        Ok(p) => p,
        Err(_) => fatal("bootstrap: FATAL init ELF parse failed", 5),
    };
    if plan.kind != ImageKind::StaticFixed {
        fatal("bootstrap: FATAL init must be ET_EXEC (StaticFixed)", 5);
    }
    putdec("bootstrap: init segments = ", plan.n_segs as u64);

    // S4: стейджинг. Сегменты образа + стек — RW-регионы у СЕБЯ;
    // дочернее пространство получит те же кадры с правами из
    // дескриптора (map_external_at у ядра).
    let mut n_desc_segs = 0usize;
    // SAFETY: SPAWN_DESC — static mut; только raw-указатель, поток
    // один, гонок нет (до S5).
    let desc: *mut u8 = unsafe { core::ptr::addr_of_mut!(SPAWN_DESC) }.cast();
    for s in plan.segs.iter().take(plan.n_segs) {
        let src = match alloc_region(s.pages, FLAG_RW) {
            Ok(v) => v,
            Err(_) => fatal("bootstrap: FATAL staging alloc failed", 6),
        };
        // SAFETY: [src, src+pages*4K) — свежий RW-регион фасада.
        unsafe {
            zero_region(src, s.pages * 4096);
            copy_into(
                src + s.in_seg,
                &init_data[s.file_off as usize..(s.file_off + s.filesz) as usize],
            );
        }
        write_desc_seg(desc, n_desc_segs, src, s.vstart, s.pages, s.flags);
        n_desc_segs += 1;
        if n_desc_segs >= MAX_SPAWN_SEGS - 1 {
            fatal("bootstrap: FATAL too many init segments", 6);
        }
    }
    // Стек init: тот же ABI, что у kinit (16 страниц под вершиной).
    let stack_top = USER_STACK_TOP;
    let stack_lo = stack_top - USER_STACK_PAGES * 4096;
    let stack_src = match alloc_region(USER_STACK_PAGES, FLAG_RW) {
        Ok(v) => v,
        Err(_) => fatal("bootstrap: FATAL stack alloc failed", 6),
    };
    // SAFETY: свежий RW-регион.
    unsafe { zero_region(stack_src, USER_STACK_PAGES * 4096) };
    write_desc_seg(
        desc,
        n_desc_segs,
        stack_src,
        stack_lo,
        USER_STACK_PAGES,
        FLAG_RW,
    );
    n_desc_segs += 1;

    // Аргв-блок init: [0]=имя записи, слова из args каталога,
    // транзит boot_state (argv[1..] бутстрапа).
    // SAFETY: ARGV_BLOCK/CSTR_SCRATCH — static mut, только raw, фаза
    // однопоточна.
    let (argv_src, argc_out, argv_bytes) = unsafe {
        let buf: *mut u8 = core::ptr::addr_of_mut!(ARGV_BLOCK).cast();
        build_argv_block(buf, name, args, argc, argv)
    };
    if argv_src == 0 {
        fatal("bootstrap: FATAL argv block overflow", 7);
    }
    let argv_dst = stack_top - ARGV_BELOW_STACK;

    // Дескриптор спавна (раскладка — syscall/nums.rs ядра, 0x70).
    // SAFETY: desc — raw-указатель на static mut (однопоточная фаза);
    // записи ограничены размером SPAWN_DESC.
    unsafe {
        desc_word(desc, 0x00, plan.entry); // entry
        desc_word(desc, 0x08, stack_top); // stack_top
        desc_word(desc, 0x10, INIT_THREAD_ID_LO); // thread_id lo
        desc_word(desc, 0x18, INIT_TASK_ID_HI); // thread_id hi (0)
        desc_u32(desc, 0x20, n_desc_segs as u32);
        desc_u32(desc, 0x24, ARGV_PAGES as u32);
        desc_word(desc, 0x28, argv_src); // argv у РОДИТЕЛЯ
        desc_word(desc, 0x30, argv_dst); // argv у РЕБЁНКА
        desc_word(desc, 0x38, argv_bytes as u64);
        desc_word(desc, 0x40, argc_out as u64);
        // Лимиты: init — доверенный root-сервер (TaskLimits::UNLIMITED).
        desc_word(desc, 0x48, u64::MAX); // max_pages
        desc_word(desc, 0x50, u64::MAX); // threads | eps<<32
        desc_word(desc, 0x58, u64::MAX); // shm | caps<<32
        desc_word(desc, 0x60, 0x1FF); // prio 255 | may_spawn<<8
        desc.add(0x68).write_volatile(INIT_PRIORITY);
        desc_u32(desc, 0x6C, 0xFFFF_FFFF); // cpu_quota: без лимита
    }

    // Право творца: TaskTCB на себя (kinit выдал грант при создании).
    let self_tcb = match find_self_tcb() {
        Some(h) => h,
        None => fatal("bootstrap: FATAL no self TaskTCB handle", 8),
    };

    // S5: спавн init из готового образа.
    let r = l4_task_spawn_image(
        self_tcb,
        INIT_TASK_ID_LO,
        INIT_TASK_ID_HI,
        // SAFETY: дескриптор — static mut через raw; ядро читает его
        // синхронно в рамках сискола (копия в свой буфер).
        unsafe { core::ptr::addr_of!(SPAWN_DESC) }.cast::<u8>() as u64,
        (0x70 + n_desc_segs * 32) as u64,
    );
    if r <= 0 {
        putdec("bootstrap: FATAL spawn_image ret ", r as u64);
        userlib::l4_task_exit(9);
    }
    let init_tcb = r as u64;
    puts("bootstrap: init spawned, handing off root grants");

    // S6: архив RO в пространство init (init читает каталог для спавна
    // следующих серверов; zero-copy, кадры остаются у бутстрапа).
    let arch_pages = (archive_len + 4095) / 4096;
    let r = l4_mem_map_at(init_tcb, ARCHIVE_BASE, arch_pages, ARCHIVE_BASE, FLAG_RO);
    if r < 0 {
        putdec("bootstrap: FATAL map archive to init ret ", r as u64);
        userlib::l4_task_exit(10);
    }
    puts("bootstrap: archive mapped RO into init");

    // S7: гранты root-сервера — init (TaskTCB(init) + IommuAdmin +
    // IoResource×3; свой TaskTCB не передаём — бутстрапу он больше не
    // нужен, но и init-у бесполезен).
    send_root_grants(init_tcb, INIT_TASK_ID_LO, INIT_TASK_ID_HI);
    puts("bootstrap: root grants sent to init");

    // S8: парковка навсегда (L4 pager: внешние кадры init — наши).
    // Ожидание open-receive: сообщения (если будут) игнорируются.
    loop {
        let _ = l4_ipc_recv_any(0);
        puts("bootstrap: (parked)");
    }
}

// ───────────────────────── Помощники ─────────────────────────

/// Копировать байты в регион MEM_ALLOC.
///
/// SAFETY-контракт: [dst, dst+src.len()) — валидное RW-окно вызывающего.
unsafe fn copy_into(dst: u64, src: &[u8]) {
    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr(), dst as *mut u8, src.len());
    }
}

/// Выделить регион под стейджинг (MEM_ALLOC; RW у родителя — права
/// ребёнка задаёт дескриптор спавна, не этот флаг).
fn alloc_region(pages: u64, flags: u64) -> Result<u64, ()> {
    let r = l4_mem_alloc(pages, flags);
    if r <= 0 { Err(()) } else { Ok(r as u64) }
}

/// Запись u32-слова в буфер дескриптора (little-endian).
///
/// SAFETY-контракт: [desc+off, desc+off+4) — валидная для записи
/// память (static mut SPAWN_DESC, однопоточная фаза).
unsafe fn desc_u32(desc: *mut u8, off: usize, v: u32) {
    unsafe {
        core::ptr::copy_nonoverlapping(v.to_le_bytes().as_ptr(), desc.add(off), 4);
    }
}

/// Сегмент дескриптора спавна (32 байта: src, dst, pages, flags).
///
/// SAFETY-контракт: desc указывает на SPAWN_DESC; фаза однопоточна.
fn write_desc_seg(desc: *mut u8, idx: usize, src: u64, dst: u64, pages: u64, flags: u64) {
    let off = 0x70 + idx * 32;
    // SAFETY: внутри границ SPAWN_DESC (idx ≤ MAX_SPAWN_SEGS).
    unsafe {
        desc_word(desc, off, src);
        desc_word(desc, off + 8, dst);
        desc_word(desc, off + 16, pages);
        desc_word(desc, off + 24, flags);
    }
}

/// Собрать argv-блок init в статическом буфере; вернуть (адрес
/// MEM_ALLOC-региона с копией, argc, байты) или (0, 0, 0) при отказе.
///
/// Формат — протокол старта: [u64 argc][u64 ptr[argc]][u64 NULL][pad]
/// [asciiz…]; указатели — адреса в пространстве РЕБЁНКА (argv_dst).
///
/// SAFETY: buf — raw-указатель на static mut ARGV_BLOCK (8 КиБ);
/// фаза однопоточна (до спавна).
#[allow(clippy::too_many_arguments)]
unsafe fn build_argv_block(
    buf: *mut u8,
    init_name: &str,
    catalog_args: Option<&str>,
    parent_argc: i32,
    parent_argv: *const *const i8,
) -> (u64, usize, usize) {
    const BUF_LEN: usize = 8192;
    // Сначала собираем список строк (≤ MAX_ARGV; скретч cstr кольцевой
    // на 32 слота: сброс счётчика гарантирует, что ≤ argc+2 живых
    // ссылок не перекроют друг друга).
    // SAFETY: static mut — однопоточная фаза.
    unsafe { CSTR_NEXT = 0 };
    let mut strings: [&str; MAX_ARGV] = [""; MAX_ARGV];
    let mut n = 0usize;
    macro_rules! push {
        ($s:expr) => {{
            if n >= MAX_ARGV {
                return (0, 0, 0);
            }
            strings[n] = $s;
            n += 1;
        }};
    }
    push!(init_name);
    if let Some(args) = catalog_args {
        for word in args.split(' ').filter(|w| !w.is_empty()) {
            push!(word);
        }
    }
    for i in 1..parent_argc.max(0) as usize {
        // SAFETY: argv-блок построен ядром (контракт стартового IPC).
        let p = unsafe { *parent_argv.add(i) };
        if p.is_null() {
            break;
        }
        // SAFETY: ASCIIZ по контракту; скретч валиден до конца функции.
        let s = unsafe { cstr(p) };
        push!(s);
    }

    let argv_dst = USER_STACK_TOP - ARGV_BELOW_STACK;
    let strings_off = (1 + n + 2) * 8;
    let mut cur = strings_off;
    // SAFETY: границы [off, off+len) проверяются против BUF_LEN;
    // buf — static mut через raw (edition 2024), фаза однопоточна.
    unsafe {
        core::ptr::write_bytes(buf, 0, BUF_LEN);
        core::ptr::copy_nonoverlapping((n as u64).to_le_bytes().as_ptr(), buf, 8);
        for (i, s) in strings.iter().take(n).enumerate() {
            if cur + s.len() + 1 > BUF_LEN {
                return (0, 0, 0);
            }
            let ptr = argv_dst + cur as u64;
            core::ptr::copy_nonoverlapping(ptr.to_le_bytes().as_ptr(), buf.add(8 + i * 8), 8);
            core::ptr::copy_nonoverlapping(s.as_ptr(), buf.add(cur), s.len());
            *buf.add(cur + s.len()) = 0;
            cur += s.len() + 1;
        }
        // NULL-терминатор + pad (формат ядра): уже нули от write_bytes,
        // но фиксируем явно — протокол не должен зависеть от обнуления.
        core::ptr::copy_nonoverlapping(0u64.to_le_bytes().as_ptr(), buf.add(8 + n * 8), 16);
    }
    let argv_bytes = cur;

    // Копия в MEM_ALLOC-регион (кадры уйдут ребёнку).
    let region = match alloc_region(ARGV_PAGES, FLAG_RW) {
        Ok(v) => v,
        Err(_) => return (0, 0, 0),
    };
    // SAFETY: свежий RW-регион; buf — static mut через raw.
    unsafe {
        zero_region(region, ARGV_PAGES * 4096);
        core::ptr::copy_nonoverlapping(buf, region as *mut u8, argv_bytes);
    }
    (region, n, argv_bytes)
}

/// Свой TaskTCB (право творца; kinit выдал при создании задачи).
fn find_self_tcb() -> Option<u64> {
    let mut idx = 1u64;
    for _ in 0..64 {
        let handle = l4_cap_list(idx);
        let kind = l4_cap_list(idx + 1);
        if handle <= 0 && kind <= 0 {
            break; // конец списка
        }
        if kind == CAP_KIND_TASK_TCB && handle > 0 {
            return Some(handle as u64);
        }
        idx += 2;
    }
    None
}

/// Передать init гранты root-сервера: IommuAdmin (5), IoResource
/// Mmio/IoPort/Irq (6/7/8) и TaskTCB(init) (возврат спавна).
///
/// ПОРЯДОК критичен: CAP_SEND — ПЕРЕНОС (transfer), а право на передачу
/// в чужой cspace требует TaskTCB на получателя У ВЫЗЫВАЮЩЕГО. Отправив
/// TaskTCB(init) первым, бутстрап теряет право слать что-то ещё
/// («cap transfer blocked: no TaskTCB on destination» — багрепресс v3).
/// Поэтому: ресурсы — пока TaskTCB(init) ещё у нас, его самого — последним.
fn send_root_grants(init_tcb: u64, init_lo: u64, init_hi: u64) {
    let self_lo = userlib::l4_self_info(0);
    let self_hi = userlib::l4_self_info(1);
    let mut idx = 1u64;
    for _ in 0..64 {
        let handle = l4_cap_list(idx);
        let kind = l4_cap_list(idx + 1);
        if handle <= 0 && kind <= 0 {
            break;
        }
        if handle > 0 {
            match kind {
                CAP_KIND_IOMMU_ADMIN | CAP_KIND_IO_MMIO | CAP_KIND_IO_PORT | CAP_KIND_IO_IRQ => {
                    // Гранты root-сервера — все туда (право на передачу
                    // ещё есть: TaskTCB(init) у нас).
                    let _ = l4_cap_send(handle as u64, init_lo, init_hi);
                }
                CAP_KIND_TASK_TCB => {
                    // СВОЙ TaskTCB — пропустить (право творца остаётся у
                    // бутстрапа); TaskTCB(init) отправим последним (ниже).
                    let lo = userlib::l4_cap_info(handle as u64, 4);
                    let hi = userlib::l4_cap_info(handle as u64, 5);
                    if !(lo == self_lo && hi == self_hi) && handle as u64 != init_tcb {
                        let _ = l4_cap_send(handle as u64, init_lo, init_hi);
                    }
                }
                _ => {}
            }
        }
        idx += 2;
    }
    // TaskTCB(init) — ПОСЛЕДНИМ: перенос снимает его у бутстрапа (право
    // на дальнейшие передачи исчерпано; init создаёт потоки/домены).
    let _ = l4_cap_send(init_tcb, init_lo, init_hi);
}

/// Диагностика фатали формата (статические строки — без fmt).
fn arch_fatal(e: ArchiveError) -> &'static str {
    match e {
        ArchiveError::BadMagic => "bootstrap: FATAL RLBA bad magic",
        ArchiveError::BadVersion => "bootstrap: FATAL RLBA bad version",
        ArchiveError::BadGeometry => "bootstrap: FATAL RLBA bad geometry",
        ArchiveError::BadCrc => "bootstrap: FATAL RLBA crc mismatch",
        ArchiveError::TooManyEntries => "bootstrap: FATAL RLBA catalog overflow",
        ArchiveError::TooManySegments => "bootstrap: FATAL RLBA too many segments",
        ArchiveError::NoInitEntry => "bootstrap: FATAL RLBA no init entry",
        ArchiveError::NameOutOfBounds => "bootstrap: FATAL RLBA name out of bounds",
        ArchiveError::ArgsOutOfBounds => "bootstrap: FATAL RLBA args out of bounds",
        ArchiveError::SegNotAligned => "bootstrap: FATAL RLBA segment unaligned",
        ArchiveError::SegFlagsInvalid => "bootstrap: FATAL RLBA segment flags",
        ArchiveError::SegOverlap => "bootstrap: FATAL RLBA segments overlap",
    }
}
