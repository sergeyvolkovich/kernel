// ==== INIT: первый пользовательский сервер (v0.6: SMP-стресс + IOMMU) ====
//
// Статический ELF @ 0x40000000 (без libc/рантайма: только ядро и сырые
// сисколы). Протокол запуска L4:
//
//   1. IPC_RECV_ANY — стартовое сообщение ядра (парковано в очередь
//      потока): слова = [argc, argv_ptr, argv_bytes, 0, 0];
//   2. argv-блок по argv_ptr: [u64 argc][u64 ptr[argc]]..[NULL][pad]
//      [asciiz-строки]: имя модуля + argv из boot_cfg.xml + boot_state
//      переменные («имя=значение») — конфигурация транзитом из XML;
//   3. печать всего через DEBUG_WRITE (по 40 байт за вызов).
//
// Демонстрация v0.8 (SMP + VT-d/AMD-Vi: IR + huge + мульти):
//
//   S1. SELF_INFO(5) — cpu_count; печать топологии пользователя.
//   S2. IOMMU smoke: ENUM -> ATTACH(00:1f.2) -> MAP(2 стр) -> MAP
//       huge (512 стр, 2 МиБ-выровнено) -> UNMAP -> IRQ_MAP/IRQ_UNMAP
//       (IRTE, v0.8) -> UNMAP -> DETACH — реальный проход DMAR/DRHD/QI/
//       SSPT+IRTA/IRTE (Intel) либо IVRS/IVHD/DTE/командный буфер/
//       v1-таблицы+IRTE (AMD-Vi) ядра.
//   S3. SMP-стресс: по потоку на CPU (THREAD_CREATE по TaskTCB-гранту
//       из kinit): разделяемый счётчик (MEM_ALLOC-страница, volatile),
//       каждый поток гоняет инкременты + THREAD_YIELD; гистограмма
//       «на каких CPU исполнялся» — миграция потоков видна в выводе.
//   S4. TASK_EXIT(0) — домен умирает, ядро сообщает «все ушли».
//
// Демонстрация v0.9 (песочница GTCB + спавн по готовому образу):
//
//   S4. SANDBOX: init встраивает ОБРАЗ дочерней задачи (crates/rogue,
//       include_bytes байтов) и спавнит её через TASK_SPAWN_IMAGE —
//       сискол принимает ТОЛЬКО указатели на уже готовую память:
//       init сам (a) парсит залинкованный ELF, (b) выделяет свои
//       регионы MEM_ALLOC, (c) копирует сегменты/стек/argv, (d)
//       собирает дескриптор с АТРИБУТАМИ ПЕСОЧНИЦЫ (max_pages/
//       threads/endpoints/shm/caps/prio, may_spawn=0). Ребёнок
//       открывает порты, обменивается информацией (ping-pong x3),
//       затем пытается ВЫРВАТЬСЯ и устроить DoS — квоты GTCB и
//       capability-модель гасят каждую попытку (аудит ядра — в
//       консоль), ребёнок шлёт отчёт и сдаётся; init получает
//       exit-уведомление на свой порт, возвращает staging-страницы
//       пулу (MEM_FREE) и выносит вердикт.
//   S5. TASK_EXIT(0) — домен умирает, ядро сообщает «все ушли».
//
// Никаких capability не запрашивается напрямую: TaskTCB(себя) выдан
// kinit (право творца), хендл находится через CAP_LIST (kind = 2);
// IommuAdmin (гейт группы 0x80) тоже выдан kinit — детям НЕ передаётся.

#![no_std]
#![no_main]

use core::arch::asm;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    main_loop()
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // Паники в init — смерть домена (ядро напечатает диагностику).
    unsafe { sys_exit(13) }
}

// ───────────────────────── Syscall ABI (x86_64) ─────────────────────────
// rax = номер; rdi, rsi, rdx, r10, r8, r9 = аргументы; возврат rax.

#[inline(always)]
unsafe fn syscall6(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> i64 {
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

// Номера (nums.rs ядра).
const SYS_SELF_INFO: u64 = 0x03;
const SYS_TASK_EXIT: u64 = 0x12;
const SYS_THREAD_CREATE: u64 = 0x15;
const SYS_THREAD_TERMINATE: u64 = 0x17;
const SYS_THREAD_YIELD: u64 = 0x1B;
const SYS_CAP_LIST: u64 = 0x25;
const SYS_IPC_RECV_ANY: u64 = 0x36;
const SYS_IPC_SEND_THREAD: u64 = 0x35;
const SYS_IPC_MSG_WORD: u64 = 0x37;
const SYS_DEBUG_WRITE: u64 = 0x71;
const SYS_MEM_ALLOC: u64 = 0x51;
const SYS_MEM_FREE: u64 = 0x52;
const SYS_IOMMU_ENUM: u64 = 0x80;
const SYS_IOMMU_ATTACH: u64 = 0x81;
const SYS_IOMMU_MAP: u64 = 0x82;
const SYS_IOMMU_UNMAP: u64 = 0x83;
const SYS_IOMMU_DETACH: u64 = 0x84;
const SYS_IOMMU_IRQ_MAP: u64 = 0x85;
const SYS_IOMMU_IRQ_UNMAP: u64 = 0x86;
// v0.9: спавн/песочница/права.
const SYS_TASK_KILL: u64 = 0x13;
const SYS_CAP_MINT: u64 = 0x21;
const SYS_CAP_SEND: u64 = 0x22;
const SYS_EP_CREATE: u64 = 0x31;
const SYS_IPC_SEND: u64 = 0x32;
const SYS_IPC_RECV: u64 = 0x33;
const SYS_TASK_LIMITS_INFO: u64 = 0x1E;
const SYS_TASK_SPAWN_IMAGE: u64 = 0x1F;

unsafe fn recv_any(flags: u64) -> i64 {
    syscall6(SYS_IPC_RECV_ANY, flags, 0, 0, 0, 0, 0)
}

unsafe fn msg_word(idx: u64) -> i64 {
    syscall6(SYS_IPC_MSG_WORD, idx, 0, 0, 0, 0, 0)
}

/// DEBUG_WRITE: до 40 байт (5 слов little-endian) за вызов.
unsafe fn debug_write(bytes: &[u8]) {
    let mut words = [0u64; 5];
    let n = bytes.len().min(40);
    for (i, &b) in bytes[..n].iter().enumerate() {
        words[i / 8] |= (b as u64) << ((i % 8) * 8);
    }
    syscall6(
        SYS_DEBUG_WRITE,
        words[0],
        words[1],
        words[2],
        words[3],
        words[4],
        0,
    );
}

/// Печать строки (порциями по 40 байт) + \r\n.
unsafe fn puts(s: &str) {
    unsafe {
        let mut rest = s.as_bytes();
        while !rest.is_empty() {
            let n = rest.len().min(40);
            debug_write(&rest[..n]);
            rest = &rest[n..];
        }
        debug_write(b"\r\n");
    }
}

unsafe fn sys_exit(code: u64) -> ! {
    syscall6(SYS_TASK_EXIT, code, 0, 0, 0, 0, 0);
    // TASK_EXIT не возвращается при живом ядре; если вернул (баг) —
    // крутиться без привилегированных инструкций (hlt в ring3 = #GP).
    loop {
        core::hint::spin_loop();
    }
}

// ───────────────────────── Демонстрация IOMMU ─────────────────────────

/// S2: сквозной проход IOMMU (контроллер — QEMU intel-iommu ИЛИ
/// amd-iommu; без них ENUM вернёт 0 и демо честно пропускается).
unsafe fn iommu_smoke() {
    unsafe {
        let n = syscall6(SYS_IOMMU_ENUM, 0xFFFF_FFFF, 0, 0, 0, 0, 0);
        if n <= 0 {
            puts("init: iommu: no controllers (run QEMU with -device intel-iommu|amd-iommu)");
            return;
        }
        let flags = syscall6(SYS_IOMMU_ENUM, 0, 0, 0, 0, 0, 0);
        let ver = syscall6(SYS_IOMMU_ENUM, 0, 1, 0, 0, 0, 0);
        puts("init: iommu: controller present, smoking map/unmap cycle");
        debug_word_line("init: iommu flags  = ", flags as u64);
        debug_word_line("init: iommu version= ", ver as u64);

        // Attach BDF 00:1f.2 (встроенный ICH9 AHCI q35): устройство реально
        // присутствует на шине — есть и в IVHD-записях AMD-Vi (QEMU
        // генерирует Select-записи), и под INCLUDE_PCI_ALL Intel. После
        // загрузки контроллер не DMA-ит — строим таблицы честно.
        let dev = syscall6(SYS_IOMMU_ATTACH, 0, 0, 0x1f, 2, 0, 0);
        if dev < 0 {
            puts("init: iommu: ATTACH failed");
            debug_word_line("init: iommu: ATTACH errno = ", dev as u64);
            return;
        }
        debug_word_line("init: iommu dev id = ", dev as u64);

        // MAP: 2 страницы RW по iova 0x10000 -> phys 0x03000000.
        // Физика — демонстрационная (реального DMA нет: валидируем
        // прохождение SSPT+QI через эмулированный VT-d).
        let prot_rw = 0b011u64;
        let packed = 2 | (prot_rw << 32);
        let r = syscall6(
            SYS_IOMMU_MAP,
            0,
            dev as u64,
            0x1_0000,
            0x0300_0000,
            packed,
            0,
        );
        debug_word_line("init: iommu map    -> ", r as u64);
        // Повтор на тот же диапазон — IovaConflict (EEXIST).
        let r2 = syscall6(
            SYS_IOMMU_MAP,
            0,
            dev as u64,
            0x1_0000,
            0x0300_0000,
            packed,
            0,
        );
        debug_word_line("init: iommu remap  -> (expect -17) ", r2 as u64);

        let u = syscall6(SYS_IOMMU_UNMAP, 0, dev as u64, 0x1_0000, 2, 0, 0);
        debug_word_line("init: iommu unmap  -> ", u as u64);

        // v0.8: крупные страницы — 512 стр 2 МиБ-выровнено: один
        // huge-лист (SS-PDE Intel / v1-лист уровня 2 AMD); ядро печатает
        // «map huge 2MiB» на консоль отладки.
        let packed_h = 512 | (prot_rw << 32);
        let mh = syscall6(
            SYS_IOMMU_MAP,
            0,
            dev as u64,
            0x0400_0000,
            0x0300_0000,
            packed_h,
            0,
        );
        debug_word_line("init: iommu map huge (512p) -> ", mh as u64);
        let uh = syscall6(SYS_IOMMU_UNMAP, 0, dev as u64, 0x0400_0000, 512, 0, 0);
        debug_word_line("init: iommu unmap huge      -> ", uh as u64);

        // v0.8: IRQ-ремаппинг — IRTE (vector 0x41 -> APIC 0); возврат —
        // handle: его драйвер устройства кладёт в MSI-адрес.
        let h = syscall6(SYS_IOMMU_IRQ_MAP, 0, dev as u64, 0x41, 0, 0, 0);
        debug_word_line("init: iommu irq_map handle  -> ", h as u64);
        let iu = if h > 0 {
            syscall6(SYS_IOMMU_IRQ_UNMAP, 0, dev as u64, h as u64, 0, 0, 0)
        } else {
            -1
        };
        debug_word_line("init: iommu irq_unmap       -> ", iu as u64);

        let d = syscall6(SYS_IOMMU_DETACH, 0, dev as u64, 0, 0, 0, 0);
        debug_word_line("init: iommu detach -> ", d as u64);
        if r == 0 && u == 0 && d == 0 && mh == 0 && uh == 0 && h > 0 && iu == 0 {
            puts("init: iommu smoke OK (map+huge+irq+unmap+detach)");
        } else {
            puts("init: iommu smoke FAILED");
        }
    }
}

// ───────────────────────── SMP-стресс ─────────────────────────

/// Страница разделяемой статистики воркеров (статик, не MEM_ALLOC:
/// главному потоку видна ДО создания воркеров). Раскладка (u64):
/// [0] = фазовые флаги (bit i: поток i финишировал);
/// [1..1+NCPU] = гистограмма исполнений по CPU (последний SELF_INFO(4)
/// каждого пакета); [64+slot] = счётчик инкрементов потока;
/// [128+slot] = последний CPU потока.
const MAX_WORKERS: u64 = 8;
/// Итераций на поток (пакет = 256 инкрементов, между пакетами — yield:
/// вытеснение/миграция происходят и по кванту, и по yield).
const ITER_PACKS: u64 = 64;
const PACK: u64 = 256;

/// Выровненная страница статистики (repr(align) на статиках запрещён —
/// оборачиваем типом).
#[repr(align(4096))]
pub struct SharedPage(pub [u64; 512]);

#[unsafe(no_mangle)]
pub static mut SMP_SHARED_PAGE: SharedPage = SharedPage([0; 512]);

/// Точка входа воркера (все регистры нулевые; свой tid — SELF_INFO).
#[unsafe(no_mangle)]
extern "C" fn smp_worker() -> ! {
    unsafe {
        let tid_lo = syscall6(SYS_SELF_INFO, 2, 0, 0, 0, 0, 0) as u64;
        let cpu_cnt = syscall6(SYS_SELF_INFO, 5, 0, 0, 0, 0, 0) as u64;
        // Слот воркера: tid совпадает с 0x1002+i (main создаёт с этими
        // id); индекс = tid - 0x1002.
        let slot = (tid_lo - 0x1002) as usize;
        let hist = &mut (*core::ptr::addr_of_mut!(SMP_SHARED_PAGE)).0;
        for _p in 0..ITER_PACKS {
            for _i in 0..PACK {
                // Пакет инкрементов: общий счётчик в слоте 64+slot
                // (volatile — компилятор не выносит из цикла).
                let p = core::ptr::addr_of_mut!(hist[64 + slot]);
                let v = p.read_volatile();
                p.write_volatile(v + 1);
                core::hint::spin_loop();
            }
            // Гистограмма CPU + yield (миграция между пакетами).
            let cpu = syscall6(SYS_SELF_INFO, 4, 0, 0, 0, 0, 0) as u64;
            if (cpu as usize) < 64 {
                let h = core::ptr::addr_of_mut!(hist[1 + cpu as usize]);
                h.write_volatile(h.read_volatile() + 1);
            }
            let last = core::ptr::addr_of_mut!(hist[128 + slot]);
            last.write_volatile(cpu);
            let _ = syscall6(SYS_THREAD_YIELD, 0, 0, 0, 0, 0, 0);
        }
        // Финиш: флаг в слоте 0.
        let f = core::ptr::addr_of_mut!(hist[0]);
        f.write_volatile(f.read_volatile() | (1u64 << slot));
        let _ = syscall6(SYS_THREAD_TERMINATE, tid_lo, 0, 0, 0, 0, 0);
        loop {
            core::hint::spin_loop();
        }
    }
}

/// Стек воркера: 8 страниц (MEM_ALLOC).
unsafe fn worker_stack(pages: u64) -> Option<u64> {
    unsafe {
        // READ|WRITE = 0b011.
        let v = syscall6(SYS_MEM_ALLOC, pages, 0b011, 0, 0, 0, 0);
        if v <= 0 {
            return None;
        }
        Some(v as u64 + pages * 4096)
    }
}

/// Найти хендл TaskTCB(себя) через CAP_LIST. Слот = ДВА слова:
/// [1+2i] = handle_bits (полный u64 с generation), [2+2i] = kind
/// (2 = TaskTCB).
unsafe fn find_tcb_handle() -> Option<u64> {
    unsafe {
        let n = syscall6(SYS_CAP_LIST, 0, 0, 0, 0, 0, 0);
        if n <= 0 {
            return None;
        }
        let mut idx = 1u64;
        for _ in 0..n {
            let handle = syscall6(SYS_CAP_LIST, idx, 0, 0, 0, 0, 0);
            let kind = syscall6(SYS_CAP_LIST, idx + 1, 0, 0, 0, 0, 0);
            if kind == 2 && handle > 0 {
                return Some(handle as u64);
            }
            idx += 2;
        }
        None
    }
}

/// S3: создать min(cpu_count, MAX_WORKERS)-1 воркеров, ждать флаги,
/// напечатать гистограмму.
unsafe fn smp_stress(cpu_count: u64) {
    unsafe {
        let want = (cpu_count - 1).min(MAX_WORKERS - 1);
        if want == 0 {
            puts("init: smp: single CPU — stress skipped");
            return;
        }
        puts("init: smp: spawning workers (shared counter + yield migration)");
        let tcb = match find_tcb_handle() {
            Some(h) => h,
            None => {
                puts("init: smp: no TaskTCB handle (kinit grant missing?) — skipped");
                return;
            }
        };
        let mut spawned = 0u64;
        for i in 0..want {
            let tid = 0x1002 + i;
            let stack = match worker_stack(8) {
                Some(s) => s,
                None => {
                    puts("init: smp: MEM_ALLOC failed — fewer workers");
                    break;
                }
            };
            let r = syscall6(SYS_THREAD_CREATE, tcb, smp_worker as u64, stack, tid, 0, 0);
            if r == 0 {
                spawned += 1;
            } else {
                debug_word_line("init: smp: THREAD_CREATE ret ", r as u64);
            }
        }
        debug_word_line("init: smp: workers spawned = ", spawned);
        if spawned == 0 {
            return;
        }
        // Ждать флаги финиширования (volatile чтение слота 0).
        let hist = &mut (*core::ptr::addr_of_mut!(SMP_SHARED_PAGE)).0;
        let mask = (1u64 << spawned) - 1;
        loop {
            let f = core::ptr::addr_of_mut!(hist[0]);
            if f.read_volatile() & mask == mask {
                break;
            }
            core::hint::spin_loop();
        }
        puts("init: smp: all workers finished; per-cpu run histogram:");
        for c in 0..(cpu_count.min(32)) {
            let h = core::ptr::addr_of_mut!(hist[1 + c as usize]);
            let v = h.read_volatile();
            if v > 0 {
                debug_word_line("init: smp: cpu runs = ", (c << 48) | (v & 0xFFFF_FFFF_FFFF));
            }
        }
        let mut total = 0u64;
        for i in 0..spawned {
            let p = core::ptr::addr_of_mut!(hist[64 + i as usize]);
            total += p.read_volatile();
        }
        debug_word_line("init: smp: total increments = ", total);
        let expect = spawned * ITER_PACKS * PACK;
        debug_word_line("init: smp: expected         = ", expect);
        if total == expect {
            puts("init: smp stress OK");
        } else {
            puts("init: smp stress LOST UPDATES (bug!)");
        }
    }
}

// ==== S4 (v0.9): ПЕСОЧНИЦА — спавн rogue-домена из встроенного образа ====
//
// Порядок (спавн-сервер в юзерспейсе, L4):
//   1. Разбор залинкованного ELF64 rogue (вшит байтами ниже): точка
//      входа + PT_LOAD-план (линк-адреса — фиксированные, 0x40000000).
//   2. Подготовка ПАМЯТИ РОДИТЕЛЕМ (к этому моменту всё аллоцировано
//      юзерспейсом): по региону MEM_ALLOC на сегмент (+ копия байтов),
//      стек (16 стр), argv-блок, дескриптор спавна. Ядро потом
//      принимает ТОЛЬКО указатели — данные не пересылаются, кадры
//      мапятся в ребёнка как external-окна (L4 pager-модель: собственник
//      — init до самого конца).
//   3. TASK_SPAWN_IMAGE: домен + пространство + ПЕСОЧНИЦА (лимиты
//      применяются ДО первого потока) + главный поток + стартовое IPC
//      [argc, argv] — атомарно. Возврат — хендл TaskTCB(ребёнка).
//   4. Порты: EP_CREATE(ёмкость 4) у init; CAP_SEND(порт -> ребёнок) +
//      CAP_MINT(TaskTCB(ребёнка) -> ребёнок): у rogue появляется
//      ровно два права — порт родителя и своя кухня.
//   5. GO -> ребёнку (IPC_SEND_THREAD, fast-path): [cmd, parent_tid].
//   6. Обмен: READY -> PING x3 (эхо + контрольная сумма) -> ATTACK.
//   7. Отчёт rogue [REPORT_MAGIC, blocked] -> exit-уведомление на
//      порт init (TASK_SET_EXIT_EP ребёнка) -> MEM_FREE всех
//      staging-регионов -> вердикт.

/// Образ дочерней задачи: байты залинкованного rogue-ELF (вшил
/// build-скрипт из $ROGUE_ELF; пусто — демо пропускается).
static CHILD_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/child.bin"));

// Геометрия ребёнка — выбор init (всё в дескрипторе; ядро мапит куда
// сказано). Образ линкуется к 0x40000000; стек/argv — рядом.
const CHILD_STACK_TOP: u64 = 0x4002_0000;
const CHILD_STACK_PAGES: u64 = 16;
const CHILD_ARGV_DST: u64 = 0x4003_0000;
const CHILD_ARGV_PAGES: u64 = 1;
const CHILD_TASK_ID: u128 = 0x2000_0000;
const CHILD_THREAD_ID: u128 = 0x2000_0001;

// Атрибуты песочницы (GTCB ребёнка): жёсткие, но живые.
const CHILD_MAX_PAGES_HEADROOM: u64 = 40; // сверх образа+стека+argv
const CHILD_MAX_THREADS: u64 = 4; // главный + 3 флуд-потока
const CHILD_MAX_ENDPOINTS: u64 = 3;
const CHILD_MAX_SHM: u64 = 2;
const CHILD_MAX_CAPS: u64 = 8;
const CHILD_MAX_PRIO: u8 = 100;
const CHILD_PRIORITY: u8 = 90;

// Протокол (слова IPC; см. crates/rogue).
const CMD_GO: u64 = 0x474F;
const CMD_PING: u64 = 1;
const CMD_ATTACK: u64 = 2;
const CMD_READY: u64 = 0x5259;
const REPORT_MAGIC: u64 = 0xB10C;

// Дескриптор спавна (ABI syscall::nums::TASK_SPAWN_IMAGE).
const SPAWN_HDR: usize = 0x70;
const SPAWN_SEG: usize = 32;
/// Максимум сегментов в дескрипторе (ядро: SPAWN_MAX_SEGMENTS).
const SPAWN_SEGS_MAX: usize = 16;

/// PT_LOAD-сегмент залинкованного образа (линк-адреса).
#[derive(Clone, Copy)]
struct SegPlan {
    dst: u64,    // линк-адрес (4K-выровнен)
    pages: u64,  // страниц (memsz, округлённо вверх)
    in_seg: u64, // смещение p_vaddr внутри региона
    offset: u64, // файловое смещение сегмента (p_offset)
    filesz: u64,
    flags: u64, // MMAPMemoryFlags (RO/RW/RX)
}

/// Минимальный разбор ELF64 (только то, что нужно спавну): entry +
/// PT_LOAD-план. Библиотека не нужна — несколько машинных слов.
fn elf64_plan(blob: &[u8]) -> Option<(u64, [SegPlan; SPAWN_SEGS_MAX], usize)> {
    if blob.len() < 64 || &blob[0..4] != b"\x7fELF" {
        return None;
    }
    let r64 = |o: usize| -> u64 {
        let mut w = [0u8; 8];
        w.copy_from_slice(&blob[o..o + 8]);
        u64::from_le_bytes(w)
    };
    let r16 = |o: usize| -> u64 {
        let mut w = [0u8; 2];
        w.copy_from_slice(&blob[o..o + 2]);
        u16::from_le_bytes(w) as u64
    };
    let r32 = |o: usize| -> u64 {
        let mut w = [0u8; 4];
        w.copy_from_slice(&blob[o..o + 4]);
        u32::from_le_bytes(w) as u64
    };
    let entry = r64(0x18);
    let phoff = r64(0x20) as usize;
    let phentsize = r16(0x36) as usize;
    let phnum = r16(0x38) as usize;
    let mut segs = [SegPlan {
        dst: 0,
        pages: 0,
        in_seg: 0,
        offset: 0,
        filesz: 0,
        flags: 0,
    }; SPAWN_SEGS_MAX];
    let mut n = 0usize;
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        if ph + 0x38 > blob.len() {
            return None;
        }
        if r32(ph) != 1 {
            continue; // PT_LOAD (p_type — u32, не u64!)
        }
        let p_flags = r32(ph + 4) as u8;
        let offset = r64(ph + 0x08);
        let vaddr = r64(ph + 0x10);
        let filesz = r64(ph + 0x20);
        let memsz = r64(ph + 0x28);
        if memsz == 0 || n == segs.len() {
            continue;
        }
        let vstart = vaddr & !0xFFF;
        let vend = (vaddr + memsz + 0xFFF) & !0xFFF;
        // W^X-перевод (тот же протокол, что у elfload ядра).
        let flags: u64 = if p_flags & 0x2 != 0 {
            0b011 // RW
        } else if p_flags & 0x1 != 0 {
            0b101 // RX
        } else {
            0b001 // RO
        };
        segs[n] = SegPlan {
            dst: vstart,
            pages: (vend - vstart) / 0x1000,
            in_seg: vaddr - vstart,
            offset,
            filesz,
            flags,
        };
        n += 1;
    }
    if entry == 0 || n == 0 {
        return None;
    }
    Some((entry, segs, n))
}

/// Запись u64 little-endian в свою память (регион MEM_ALLOC).
unsafe fn put64(buf: *mut u8, off: usize, v: u64) {
    unsafe {
        let b = v.to_le_bytes();
        for i in 0..8 {
            buf.add(off + i).write_volatile(b[i]);
        }
    }
}

/// Нулевизация диапазона (кадры из пула несут прошлый мусор).
unsafe fn zero(buf: *mut u8, off: usize, len: usize) {
    unsafe {
        for i in 0..len {
            buf.add(off + i).write_volatile(0);
        }
    }
}

/// Копия байтов образа в staging-регион (volatile — реальная память).
unsafe fn copy_bytes(dst: *mut u8, src: &[u8]) {
    unsafe {
        for (i, &b) in src.iter().enumerate() {
            dst.add(i).write_volatile(b);
        }
    }
}

/// Строка ASCIIZ в буфер (для argv-блока). Возврат — длина с нулём.
unsafe fn copy_str(dst: *mut u8, s: &[u8]) -> usize {
    unsafe {
        for (i, &b) in s.iter().enumerate() {
            dst.add(i).write_volatile(b);
        }
        dst.add(s.len()).write_volatile(0);
        s.len() + 1
    }
}

unsafe fn sandbox_demo() {
    unsafe {
        puts("=== init: S4 sandbox demo (spawn from embedded image) ===");

        if CHILD_ELF.is_empty() {
            puts("init: sandbox: no embedded child image (set ROGUE_ELF at build), skipped");
            return;
        }
        let (entry, segs, n_segs) = match elf64_plan(CHILD_ELF) {
            Some(v) => v,
            None => {
                puts("init: sandbox: embedded image is not a valid ELF64, skipped");
                return;
            }
        };
        debug_word_line("init: sandbox: child entry = ", entry);
        debug_word_line("init: sandbox: PT_LOAD segments = ", n_segs as u64);

        // Право творца init: TaskTCB(себя) — от kinit.
        let tcb_self = match find_tcb_handle() {
            Some(h) => h,
            None => {
                puts("init: sandbox: no creator TCB (kinit grant missing?) — skipped");
                return;
            }
        };

        // ---- (2) Подготовка памяти РОДИТЕЛЕМ: сегменты образа ----
        // Staging-регионы init: их адреса пойдут в дескриптор; после
        // смерти ребёнка init вернёт страницы пулу (MEM_FREE).
        let mut srcs = [0u64; SPAWN_SEGS_MAX + 2]; // сегменты + стек + argv
        let mut image_pages = 0u64;
        for i in 0..n_segs {
            let seg = segs[i];
            let v = syscall6(SYS_MEM_ALLOC, seg.pages, 0b011, 0, 0, 0, 0);
            if v <= 0 {
                puts("init: sandbox: staging MEM_ALLOC failed — abort");
                return;
            }
            let region = v as u64 as *mut u8;
            // Нули по memsz-окну, затем файл (BSS-хвост остаётся нулевым).
            zero(region, 0, seg.pages as usize * 0x1000);
            let file_end = seg.in_seg as usize + seg.filesz as usize;
            if seg.filesz > 0
                && seg.offset + seg.filesz <= CHILD_ELF.len() as u64
                && file_end <= seg.pages as usize * 0x1000
            {
                copy_bytes(
                    region.add(seg.in_seg as usize),
                    &CHILD_ELF[seg.offset as usize..(seg.offset + seg.filesz) as usize],
                );
            }
            srcs[i] = region as u64;
            image_pages += seg.pages;
        }

        // ---- Стек ребёнка (16 стр RW, нули) ----
        let stack_v = syscall6(SYS_MEM_ALLOC, CHILD_STACK_PAGES, 0b011, 0, 0, 0, 0);
        if stack_v <= 0 {
            puts("init: sandbox: stack staging failed — abort");
            return;
        }
        zero(
            stack_v as u64 as *mut u8,
            0,
            CHILD_STACK_PAGES as usize * 0x1000,
        );
        srcs[n_segs] = stack_v as u64;
        let stack_dst = CHILD_STACK_TOP - CHILD_STACK_PAGES * 0x1000;

        // ---- argv-блок: [argc][ptr0][ptr1][NULL][pad][asciiz...] ----
        let argv_v = syscall6(SYS_MEM_ALLOC, CHILD_ARGV_PAGES, 0b011, 0, 0, 0, 0);
        if argv_v <= 0 {
            puts("init: sandbox: argv staging failed — abort");
            return;
        }
        let argv_region = argv_v as u64 as *mut u8;
        zero(argv_region, 0, CHILD_ARGV_PAGES as usize * 0x1000);
        // argc = 2; строки со смещения (1+2+2)*8 = 40.
        put64(argv_region, 0, 2);
        put64(argv_region, 8, CHILD_ARGV_DST + 40);
        put64(argv_region, 16, CHILD_ARGV_DST + 40 + 6);
        put64(argv_region, 24, 0); // NULL
        put64(argv_region, 32, 0); // pad
        let mut off = 40usize;
        off += copy_str(argv_region.add(off), b"rogue");
        off += copy_str(argv_region.add(off), b"sandbox=v09");
        let argv_bytes = off;
        srcs[n_segs + 1] = argv_v as u64;

        // ---- «Приманка» для атак: собственный SHM-регион init (id=1) ----
        // rogue будет пытаться разрушить ЕГО (owner-гейт) и флудить свои.
        let shm_bait = syscall6(0x61, 1, 0, 0, 0, 0, 0);
        debug_word_line("init: sandbox: bait shm region id = ", shm_bait as u64);
        if shm_bait <= 0 {
            puts("init: sandbox: bait SHM_CREATE failed — attack demo degraded");
        }

        // ---- Дескриптор спавна (свой регион; ядро читает по указателю) ----
        let desc_v = syscall6(SYS_MEM_ALLOC, 1, 0b011, 0, 0, 0, 0);
        if desc_v <= 0 {
            puts("init: sandbox: desc staging failed — abort");
            return;
        }
        let desc = desc_v as u64 as *mut u8;
        let total_pages = image_pages + CHILD_STACK_PAGES + CHILD_ARGV_PAGES;
        let max_pages = total_pages + CHILD_MAX_PAGES_HEADROOM;
        zero(desc, 0, 0x1000);
        put64(desc, 0x00, entry); // entry
        put64(desc, 0x08, CHILD_STACK_TOP); // stack_top
        put64(desc, 0x10, CHILD_THREAD_ID as u64); // thread_id lo
        put64(desc, 0x18, (CHILD_THREAD_ID >> 64) as u64); // hi
        // n_segments = образ + стек; argv — отдельные поля дескриптора.
        put64(desc, 0x20, (n_segs + 1) as u64 | (CHILD_ARGV_PAGES << 32)); // n_seg | argv_pages
        put64(desc, 0x28, argv_v as u64); // argv_src (у родителя)
        put64(desc, 0x30, CHILD_ARGV_DST); // argv_dst
        put64(desc, 0x38, argv_bytes as u64);
        put64(desc, 0x40, 2); // argc
        put64(desc, 0x48, max_pages); // limits[0]: max_pages
        // limits[1]: max_threads | max_endpoints << 32
        put64(desc, 0x50, CHILD_MAX_THREADS | (CHILD_MAX_ENDPOINTS << 32));
        // limits[2]: max_shm | max_caps << 32
        put64(desc, 0x58, CHILD_MAX_SHM | (CHILD_MAX_CAPS << 32));
        // limits[3]: max_prio | may_spawn<<8 (0 — гасим право творца)
        put64(desc, 0x60, CHILD_MAX_PRIO as u64);
        let b = CHILD_PRIORITY.to_le_bytes();
        for i in 0..b.len() {
            desc.add(0x68 + i).write_volatile(b[i]);
        }
        // Сегменты: образ (по плану) + стек.
        for i in 0..n_segs {
            let base = SPAWN_HDR + i * SPAWN_SEG;
            put64(desc, base, srcs[i]); // src у родителя
            put64(desc, base + 8, segs[i].dst); // dst у ребёнка
            put64(desc, base + 16, segs[i].pages);
            put64(desc, base + 24, segs[i].flags);
        }
        let base = SPAWN_HDR + n_segs * SPAWN_SEG;
        put64(desc, base, srcs[n_segs]); // src стека
        put64(desc, base + 8, stack_dst);
        put64(desc, base + 16, CHILD_STACK_PAGES);
        put64(desc, base + 24, 0b011); // RW
        let desc_len = SPAWN_HDR + (n_segs + 1) * SPAWN_SEG;

        // ---- (3) СПАВН: ядро принимает только указатели ----
        let cv = CHILD_TASK_ID;
        let r = syscall6(
            SYS_TASK_SPAWN_IMAGE,
            tcb_self,
            cv as u64,
            (cv >> 64) as u64,
            desc_v as u64,
            desc_len as u64,
            0,
        );
        debug_word_line("init: sandbox: spawn_image ret = ", r as u64);
        if r <= 0 {
            puts("init: sandbox: SPAWN FAILED, aborting demo");
            return;
        }
        let tcb_child = r as u64;
        debug_word_line("init: sandbox: child TaskTCB handle = ", tcb_child);

        // ---- (4) Порты и права ----
        let gate = syscall6(SYS_EP_CREATE, 4, 0, 0, 0, 0, 0);
        if gate <= 0 {
            puts("init: sandbox: EP_CREATE failed — abort");
            return;
        }
        debug_word_line("init: sandbox: my port handle = ", gate as u64);
        // Копия порта родителя -> cspace ребёнка (CAP_MINT, не CAP_SEND:
        // send ПЕРЕДАЁТ хендл и гасит его у источника — init оставляет
        // копию себе для IPC_RECV exit-уведомления).
        let s1 = syscall6(
            SYS_CAP_MINT,
            gate as u64,
            cv as u64,
            (cv >> 64) as u64,
            0xFF,
            0xFFFF_FFFF_FFFF_FFFF,
            0,
        );
        debug_word_line("init: sandbox: cap_mint(port->child) = ", s1 as u64);
        // Производная TaskTCB(ребёнка) -> ребёнку: «своя кухня» — на ней
        // rogue и покажет, что квоты держат даже хозяина собственного TCB.
        let s2 = syscall6(
            SYS_CAP_MINT,
            tcb_child,
            cv as u64,
            (cv >> 64) as u64,
            0xFF,
            0xFFFF_FFFF_FFFF_FFFF,
            0,
        );
        debug_word_line("init: sandbox: cap_mint(tcb->child) = ", s2 as u64);

        // ---- (5) GO: ребёнок ждёт в recv_any ----
        let self_tid = syscall6(SYS_SELF_INFO, 2, 0, 0, 0, 0, 0);
        let tv = CHILD_THREAD_ID;
        let go = syscall6(
            SYS_IPC_SEND_THREAD,
            tv as u64,
            (tv >> 64) as u64,
            CMD_GO,
            self_tid as u64,
            2,
            0,
        );
        debug_word_line("init: sandbox: GO -> ", go as u64);

        // ---- (6) Обмен: READY -> PING x3 -> ATTACK ----
        let mut ready = false;
        if recv_any(0) >= 0 && msg_word(0) as u64 == CMD_READY {
            ready = true;
            let ports = msg_word(1) as u64;
            debug_word_line("init: sandbox: child READY; ports opened = ", ports);
        }
        if !ready {
            puts("init: sandbox: child did not report READY, aborting");
            return;
        }
        let mut ping_ok = 0u64;
        for round in 1..=3u64 {
            let p = syscall6(
                SYS_IPC_SEND_THREAD,
                tv as u64,
                (tv >> 64) as u64,
                CMD_PING,
                round,
                2,
                0,
            );
            let _ = p;
            if recv_any(0) < 0 {
                break;
            }
            let echo = msg_word(0) as u64;
            let crc = msg_word(1) as u64;
            let expect = round.wrapping_mul(31).wrapping_add(7);
            if echo == round && crc == expect {
                ping_ok += 1;
                debug_word_line("init: sandbox: info exchange round ok: ", echo);
            } else {
                debug_word_line("init: sandbox: BAD EXCHANGE, echo = ", echo);
            }
        }
        debug_word_line("init: sandbox: ping-pong rounds ok = ", ping_ok);
        if ping_ok != 3 {
            puts("init: sandbox: ping-pong FAILED, aborting");
            return;
        }

        puts("init: sandbox: ordering the attack (child will try to escape)");
        let a = syscall6(
            SYS_IPC_SEND_THREAD,
            tv as u64,
            (tv >> 64) as u64,
            CMD_ATTACK,
            0,
            2,
            0,
        );
        let _ = a;

        // Отчёт: [REPORT_MAGIC, blocked].
        let mut blocked = 0u64;
        let mut reported = false;
        if recv_any(0) >= 0 && msg_word(0) as u64 == REPORT_MAGIC {
            blocked = msg_word(1) as u64;
            reported = true;
        }
        if reported {
            debug_word_line(
                "init: sandbox: child report: violations blocked = ",
                blocked,
            );
        } else {
            puts("init: sandbox: NO REPORT from child (broken protocol)");
        }

        // ---- (7) Exit-уведомление на порт init (TASK_SET_EXIT_EP ребёнка) ----
        // ExitPayload-протокол: w0 = tag (1=Exit), w1..2 = task id,
        // w3 = код выхода (0x5A — «честная сдача» rogue).
        let exit_tag = syscall6(SYS_IPC_RECV, gate as u64, 0, 0, 0, 0, 0);
        debug_word_line("init: sandbox: exit notification tag = ", exit_tag as u64);
        let exit_code = msg_word(3);
        debug_word_line("init: sandbox: child exit code = ", exit_code as u64);
        let clean_exit = exit_tag == 1 && exit_code == 0x5A;

        // Приманка отработала: уничтожаем СВОЙ регион (владелец — init).
        let bait_gone = syscall6(0x65, shm_bait as u64, 0, 0, 0, 0, 0);
        debug_word_line("init: sandbox: bait shm destroyed = ", bait_gone as u64);

        // Staging-страницы — назад пулу (кадры принадлежали init).
        let mut freed = 0u64;
        for i in 0..(n_segs + 2) {
            if srcs[i] != 0 {
                let f = syscall6(SYS_MEM_FREE, srcs[i], 0, 0, 0, 0, 0);
                if f == 0 {
                    freed += 1;
                }
            }
        }
        let _ = syscall6(SYS_MEM_FREE, desc_v as u64, 0, 0, 0, 0, 0);
        debug_word_line("init: sandbox: staging regions returned = ", freed);
        // Проверка учёта: TASK_LIMITS_INFO(self): слово 1 = usage pages.
        let usage = syscall6(SYS_TASK_LIMITS_INFO, tcb_self, 1, 0, 0, 0, 0);
        debug_word_line("init: sandbox: init page usage now = ", usage as u64);

        if reported && blocked >= 8 && ping_ok == 3 && clean_exit {
            puts("init: sandbox VERDICT: sandbox HELD — all escape/DoS attempts blocked");
        } else {
            puts("init: sandbox VERDICT: demo finished with anomalies (see above)");
        }
    }
}

// ───────────────────────── Main ─────────────────────────

fn main_loop() -> ! {
    unsafe {
        // Стартовое сообщение: rcx-стиль возврата — слово 0 = argc.
        let argc = recv_any(0);
        if argc < 0 {
            puts("init: recv_any failed, exiting");
            sys_exit(1);
        }
        let argv_ptr = msg_word(1) as u64;
        let argv_bytes = msg_word(2) as u64;

        puts("=== init: first user server (L4 start protocol) ===");

        // self id (SELF_INFO: слова 2/3 = thread id lo/hi) + топология.
        let tid_lo = syscall6(SYS_SELF_INFO, 2, 0, 0, 0, 0, 0);
        let tid_hi = syscall6(SYS_SELF_INFO, 3, 0, 0, 0, 0, 0);
        puts("init: thread id (lo,hi) printed next");
        debug_word_line("init: tid lo = ", tid_lo as u64);
        debug_word_line("init: tid hi = ", tid_hi as u64);

        // argv-блок.
        let mut line = [0u8; 64];
        let argc = argc as u64 as usize;
        if argv_ptr != 0 && argv_bytes >= 16 && argc <= 64 {
            let base = argv_ptr as *const u64;
            let block_argc = base.read_volatile() as usize;
            puts("init: boot configuration (argv + boot_state):");
            if block_argc == argc {
                for i in 0..argc {
                    let p = base.add(1 + i).read_volatile();
                    if p == 0 {
                        continue;
                    }
                    // Скопировать ASCIIZ (до 60 байт).
                    let src = p as *const u8;
                    let mut n = 0;
                    while n < 60 && src.add(n).read_volatile() != 0 {
                        line[n] = src.add(n).read_volatile();
                        n += 1;
                    }
                    line[n] = b' ';
                    line[n + 1] = 0;
                    let mut prefix = [b' ', b' ', b' ', b' '];
                    let _ = &mut prefix;
                    debug_write(b"    ");
                    debug_write(&line[..n]);
                    debug_write(b"\r\n");
                }
            }
        } else {
            puts("init: no argv block in start message");
        }

        // S1: топология CPU.
        let cpu_count = syscall6(SYS_SELF_INFO, 5, 0, 0, 0, 0, 0);
        if cpu_count > 0 {
            puts("init: boot policy done; v0.8 feature demos follow");
            debug_word_line("init: cpu_count = ", cpu_count as u64);

            // S2: IOMMU (пропускается без контроллера).
            iommu_smoke();

            // S3: SMP-стресс.
            smp_stress(cpu_count as u64);

            // S4 (v0.9): песочница — спавн rogue-домена из встроенного
            // образа, порты, обмен, атаки, вердикт.
            sandbox_demo();
        }
        puts("init: all demos done, exiting with code 0");
        sys_exit(0)
    }
}

/// Строка-подпись + hex-слово (порционно, длины не ограничены).
unsafe fn debug_word_line(prefix: &str, v: u64) {
    unsafe {
        let mut rest = prefix.as_bytes();
        while !rest.is_empty() {
            let n = rest.len().min(40);
            debug_write(&rest[..n]);
            rest = &rest[n..];
        }
        let mut buf = [0u8; 19];
        const HEX: &[u8; 16] = b"0123456789abcdef";
        buf[0] = b'0';
        buf[1] = b'x';
        for i in 0..16 {
            let nib = (v >> ((15 - i) * 4)) & 0xF;
            buf[2 + i] = HEX[nib as usize];
        }
        buf[18] = 0;
        debug_write(&buf);
        debug_write(b"\r\n");
    }
}
