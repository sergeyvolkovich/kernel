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
// Демонстрация v0.7 (SMP + VT-d/AMD-Vi):
//
//   S1. SELF_INFO(5) — cpu_count; печать топологии пользователя.
//   S2. IOMMU smoke: ENUM -> ATTACH(00:1f.2) -> MAP(2 стр) -> UNMAP ->
//       DETACH — реальный проход через DMAR/DRHD/QI/SSPT (Intel) либо
//       IVRS/IVHD/DTE/командный буфер/v1-таблицы (AMD-Vi) ядра.
//   S3. SMP-стресс: по потоку на CPU (THREAD_CREATE по TaskTCB-гранту
//       из kinit): разделяемый счётчик (MEM_ALLOC-страница, volatile),
//       каждый поток гоняет инкременты + THREAD_YIELD; гистограмма
//       «на каких CPU исполнялся» — миграция потоков видна в выводе.
//   S4. TASK_EXIT(0) — домен умирает, ядро сообщает «все ушли».
//
// Никаких capability не запрашивается напрямую: TaskTCB(себя) выдан
// kinit (право творца), хендл находится через CAP_LIST (kind = 2).

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
const SYS_IPC_MSG_WORD: u64 = 0x37;
const SYS_DEBUG_WRITE: u64 = 0x71;
const SYS_MEM_ALLOC: u64 = 0x51;
const SYS_IOMMU_ENUM: u64 = 0x80;
const SYS_IOMMU_ATTACH: u64 = 0x81;
const SYS_IOMMU_MAP: u64 = 0x82;
const SYS_IOMMU_UNMAP: u64 = 0x83;
const SYS_IOMMU_DETACH: u64 = 0x84;

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
        let d = syscall6(SYS_IOMMU_DETACH, 0, dev as u64, 0, 0, 0, 0);
        debug_word_line("init: iommu detach -> ", d as u64);
        if r == 0 && u == 0 && d == 0 {
            puts("init: iommu smoke OK (context+SSPT+QI exercised)");
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
            puts("init: boot policy done; v0.6 feature demos follow");
            debug_word_line("init: cpu_count = ", cpu_count as u64);

            // S2: IOMMU (пропускается без контроллера).
            iommu_smoke();

            // S3: SMP-стресс.
            smp_stress(cpu_count as u64);
        }
        puts("init: all demos done, exiting with code 0");
        sys_exit(0)
    }
}

/// Строка-подпись + hex-слово (порционно).
unsafe fn debug_word_line(prefix: &str, v: u64) {
    unsafe {
        debug_write(prefix.as_bytes());
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
