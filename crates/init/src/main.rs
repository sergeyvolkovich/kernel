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

// ==== S4 (v0.9→v0.11): ПЕСОЧНИЦА + PIE-СПАВН ====
//
// Порядок (спавн-сервер в юзерспейсе, L4):
//   1. Разбор образа rogue (вшит байтами ниже) — крейт pie: точка входа,
//      PT_LOAD-план и (v0.11) таблица R_X86_64_RELATIVE из PT_DYNAMIC.
//   2. Подготовка ПАМЯТИ РОДИТЕЛЕМ: по региону MEM_ALLOC на сегмент
//      (+ копия байтов), стек (16 стр), argv-блок, дескриптор спавна.
//   3. v0.11, PIE: выбор БАЗЫ инстанса — образ линкуется ET_DYN; init
//      накатывает релокации в свои staging-копии (store: линк-адрес X ->
//      base + X), контрольный readback каждой записи, и лишь потом
//      отдаёт ядру УЖЕ залинкованный образ (контракт v0.9: ядро знает
//      про ELF ровно ничего — только указатели).
//   4. TASK_SPAWN_IMAGE: домен + пространство + ПЕСОЧНИЦА (лимиты
//      применяются ДО первого потока) + главный поток + стартовое IPC
//      [argc, argv] — атомарно. Возврат — хендл TaskTCB(ребёнка).
//   5. Порты: EP_CREATE(ёмкость 4) у init; CAP_SEND нет — CAP_MINT
//      (порт -> ребёнок) + CAP_MINT(TaskTCB(ребёнка) -> ребёнок).
//   6. GO -> ребёнку (IPC_SEND_THREAD, fast-path): [cmd, parent_tid].
//   7. Обмен: READY (+ PIE_PTR: значение статического указателя ребёнка
//      — сверка с базой) -> PING x3 (эхо + контрольная сумма) -> ATTACK.
//   8. Отчёт rogue [REPORT_MAGIC, blocked] -> exit-уведомление на порт
//      init -> MEM_FREE всех staging-регионов -> вердикт инстанса.
//
// PIE-вердикт: ОДИН И ТОТ ЖЕ образ исполняется на ДВУХ базах
// (0x40000000 и 0x50000000) с полным протоколом песочницы на каждой.

/// Образ дочерней задачи: байты залинкованного rogue-ELF (вшил
/// build-скрипт из $ROGUE_ELF; пусто — демо пропускается). Сборка
/// build.sh линкует rogue как static-pie (ET_DYN + RELATIVE-релоки).
static CHILD_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/child.bin"));

/// v0.14: встроенный образ acpid — ACPI-менеджер в юзерспейсе (AML
/// вынесен из ядра). Сборка build.sh (ACPID_ELF) -> OUT_DIR/acpid.bin;
/// пусто — демо S6 пропускается.
static ACPID_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/acpid.bin"));

/// Пойманный из boot_state факт прошивки: "rsdp=0x..." (kinit ->
/// argv init -> argv acpid: ядро передаёт ССЫЛКУ на таблицы,
/// интерпретация ACPI — юзерспейс).
static mut RSDP_LINE: [u8; 24] = [0; 24];
static mut RSDP_LINE_LEN: usize = 0;

// Геометрия ребёнка — выбор init (всё в дескрипторе; ядро мапит куда
// сказано). Для PIE стек/argv кладутся ЗА образом (относительно базы);
// для статического образа (легаси-режим сборки rogue) база — 0, адреса
// абсолютные.
const CHILD_STACK_PAGES: u64 = 16;
const CHILD_ARGV_PAGES: u64 = 1;

// Атрибуты песочницы (GTCB ребёнка): жёсткие, но живые.
const CHILD_MAX_PAGES_HEADROOM: u64 = 40; // сверх образа+стека+argv
const CHILD_MAX_THREADS: u64 = 4; // главный + 3 флуд-потока
const CHILD_MAX_ENDPOINTS: u64 = 3;
const CHILD_MAX_SHM: u64 = 2;
const CHILD_MAX_CAPS: u64 = 8;
const CHILD_MAX_PRIO: u8 = 100;
const CHILD_PRIORITY: u8 = 90;
/// CPU-квота ребёнка (v0.10, тики за период): rogue — болтливый IPC-задач
/// (GO/READY/PING x3/ATTACK/REPORT = ~5-6 парков), каждая парковка —
/// минимум 1 тик заряда; квота 3 трипается в середине пинг-понга —
/// ядро включает троттлинг (аудит «[kernel: sandbox] cpu quota»), но
/// протокол продолжает идти (парковки IPC не ждут refill) — квота не
/// душит насмерть, а дисциплинирует. Период бекенда: 100 глобальных
/// тиков; sustained-спиннер парковался бы вовсе до границы периода.
const CHILD_CPU_QUOTA: u32 = 3;

// Протокол (слова IPC; см. crates/rogue).
const CMD_GO: u64 = 0x474F;
const CMD_PING: u64 = 1;
const CMD_ATTACK: u64 = 2;
const CMD_READY: u64 = 0x5259;
const REPORT_MAGIC: u64 = 0xB10C;
/// v0.11: доказательство релокации — ребёнок шлёт ЗНАЧЕНИЕ статического
/// указателя из своего .data (patched загрузчиком под базу инстанса).
const PIE_MAGIC: u64 = 0x1E11;

// Дескриптор спавна (ABI syscall::nums::TASK_SPAWN_IMAGE).
const SPAWN_HDR: usize = 0x70;
const SPAWN_SEG: usize = 32;
/// Максимум сегментов в дескрипторе (ядро: SPAWN_MAX_SEGMENTS).
const SPAWN_SEGS_MAX: usize = 16;

/// Конфигурация инстанса ребёнка: где живёт и как представляется.
struct InstanceCfg {
    /// База загрузки (PIE). Для статического образа поле игнорируется.
    base: u64,
    /// TaskId/ThreadId домена и главного потока (128-бит L4-идентификаторы).
    task: u128,
    thread: u128,
    /// Метка argv (различает инстансы в выводе и протоколе).
    tag: &'static str,
}

/// Два инстанса ОДНОГО образа на разных базах — позиционная
/// независимость видна и в адресах, и в идентификаторах доменов.
const INSTANCES: [InstanceCfg; 2] = [
    InstanceCfg {
        base: 0x4000_0000,
        task: 0x2000_0000,
        thread: 0x2000_0001,
        tag: "inst=a",
    },
    InstanceCfg {
        base: 0x5000_0000,
        task: 0x2200_0000,
        thread: 0x2200_0001,
        tag: "inst=b",
    },
];

/// Итог прогона инстанса (собирается по ходу протокола; без аллокаций).
struct ChildOutcome {
    /// Ребёнок доложил READY.
    ready: bool,
    /// Значение статического указателя из READY-дополнения (PIE_PTR).
    self_ptr: u64,
    /// Указатель совпал с base+addend какой-то релокации образа.
    self_ptr_verified: bool,
    /// PING-эхо прошло все 3 раунда.
    ping_ok: u64,
    /// Ребёнок прислал отчёт об атаках.
    reported: bool,
    /// Число заблокированных попыток выхода/DoS.
    blocked: u64,
    /// Чистый exit (tag=1, код 0x5A).
    clean_exit: bool,
    /// CPU-квота сработала (был троттлинг).
    cpu_held: bool,
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

/// Чтение u64 little-endian из своей памяти (readback релокаций).
unsafe fn read64(buf: *mut u8, off: usize) -> u64 {
    unsafe {
        let mut w = [0u8; 8];
        for i in 0..8 {
            w[i] = buf.add(off + i).read_volatile();
        }
        u64::from_le_bytes(w)
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

/// Адрес staging-слова для линк-адреса образа (релокации).
unsafe fn staging_ptr_of(plan: &pie::Plan, srcs: &[u64], vaddr: u64) -> Option<(*mut u8, usize)> {
    let (i, seg) = plan.seg_of(vaddr)?;
    let ptr = srcs[i] as *mut u8;
    Some((ptr, (vaddr - seg.vstart) as usize))
}

/// Полный прогон одного инстанса: staging (+релоки) -> спавн -> обмен
/// -> атаки -> exit -> возврат staging пулу. None — фатальный сбой
/// (диагностика уже напечатана; вердикт S4 соберёт отказ).
unsafe fn spawn_and_run_child(
    plan: &pie::Plan,
    inst: &InstanceCfg,
    tcb_self: u64,
) -> Option<ChildOutcome> {
    unsafe {
        let is_pie = plan.kind == pie::ImageKind::Pie;
        // База: PIE — выбранная; статический образ — 0 (адреса абсолютны).
        let base = if is_pie { inst.base } else { 0 };
        let image_end = plan.image_end();
        // Геометрия за образом: стек и argv (4K-выровнены от базы).
        let stack_dst = (base + image_end + 0xFFF) & !0xFFF;
        let stack_top = stack_dst + CHILD_STACK_PAGES * 0x1000;
        let argv_dst = (stack_top + 0xFFF) & !0xFFF;
        debug_word_line("init: pie: base          = ", base);
        debug_word_line("init: pie: image end     = ", base + image_end);
        debug_word_line("init: pie: entry (link)  = ", plan.entry);

        // ---- (2) Подготовка памяти РОДИТЕЛЕМ: сегменты образа ----
        let mut srcs = [0u64; SPAWN_SEGS_MAX + 2]; // сегменты + стек + argv
        let mut image_pages = 0u64;
        let n_segs = plan.n_segs;
        for i in 0..n_segs {
            let seg = plan.segs[i];
            let v = syscall6(SYS_MEM_ALLOC, seg.pages, 0b011, 0, 0, 0, 0);
            if v <= 0 {
                puts("init: pie: staging MEM_ALLOC failed — abort");
                return None;
            }
            let region = v as u64 as *mut u8;
            // Нули по всему окну (BSS-хвост чист), затем файл.
            zero(region, 0, seg.pages as usize * 0x1000);
            if seg.filesz > 0 {
                let file_end = seg.in_seg as u64 + seg.filesz;
                if seg.file_off + file_end <= CHILD_ELF.len() as u64 {
                    copy_bytes(
                        region.add(seg.in_seg as usize),
                        &CHILD_ELF[seg.file_off as usize..(seg.file_off + seg.filesz) as usize],
                    );
                }
            }
            srcs[i] = region as u64;
            image_pages += seg.pages;
        }

        // ---- (3) v0.11: РЕЛОКАЦИИ — накат RELATIVE в staging ----
        // Контракт: ядро получает УЖЕ залинкованный образ; позиционной
        // независимостью занимается загрузчик (этот код) — как в L4.
        let mut reloc_ok = !is_pie; // статике накатывать нечего
        if is_pie {
            let applied = plan.apply_rela(base, |vaddr, val| {
                if let Some((ptr, off)) = staging_ptr_of(&plan, &srcs, vaddr) {
                    unsafe { put64(ptr, off, val) };
                }
            });
            // Readback: каждая запись обязана читаться как base+addend.
            let mut bad = 0u64;
            for r in &plan.relas[..plan.n_relas] {
                if let Some((ptr, off)) = staging_ptr_of(plan, &srcs, r.offset) {
                    let expect = base.wrapping_add(r.addend);
                    if read64(ptr, off) != expect {
                        bad += 1;
                    }
                } else {
                    bad += 1;
                }
            }
            debug_word_line("init: pie: relocs applied   = ", applied as u64);
            debug_word_line("init: pie: relocs bad      = ", bad);
            reloc_ok = applied == plan.n_relas && bad == 0;
        }

        // ---- Стек ребёнка (16 стр RW, нули) ----
        let stack_v = syscall6(SYS_MEM_ALLOC, CHILD_STACK_PAGES, 0b011, 0, 0, 0, 0);
        if stack_v <= 0 {
            puts("init: pie: stack staging failed — abort");
            return None;
        }
        zero(
            stack_v as u64 as *mut u8,
            0,
            CHILD_STACK_PAGES as usize * 0x1000,
        );
        srcs[n_segs] = stack_v as u64;

        // ---- argv-блок: [argc][ptr0][ptr1][NULL][pad][asciiz...] ----
        let argv_v = syscall6(SYS_MEM_ALLOC, CHILD_ARGV_PAGES, 0b011, 0, 0, 0, 0);
        if argv_v <= 0 {
            puts("init: pie: argv staging failed — abort");
            return None;
        }
        let argv_region = argv_v as u64 as *mut u8;
        zero(argv_region, 0, CHILD_ARGV_PAGES as usize * 0x1000);
        // argc = 2 ("rogue" + метка инстанса); строки со смещения 40.
        put64(argv_region, 0, 2);
        put64(argv_region, 8, argv_dst + 40);
        put64(argv_region, 16, argv_dst + 40 + 6);
        put64(argv_region, 24, 0); // NULL
        put64(argv_region, 32, 0); // pad
        let mut off = 40usize;
        off += copy_str(argv_region.add(off), b"rogue");
        off += copy_str(argv_region.add(off), inst.tag.as_bytes());
        let argv_bytes = off;
        srcs[n_segs + 1] = argv_v as u64;

        // ---- Дескриптор спавна (свой регион; ядро читает по указателю) ----
        let desc_v = syscall6(SYS_MEM_ALLOC, 1, 0b011, 0, 0, 0, 0);
        if desc_v <= 0 {
            puts("init: pie: desc staging failed — abort");
            return None;
        }
        let desc = desc_v as u64 as *mut u8;
        let total_pages = image_pages + CHILD_STACK_PAGES + CHILD_ARGV_PAGES;
        let max_pages = total_pages + CHILD_MAX_PAGES_HEADROOM;
        zero(desc, 0, 0x1000);
        put64(desc, 0x00, base + plan.entry); // entry ( relocated )
        put64(desc, 0x08, stack_top); // stack_top
        put64(desc, 0x10, inst.thread as u64); // thread_id lo
        put64(desc, 0x18, (inst.thread >> 64) as u64); // hi
        // n_segments = образ + стек; argv — отдельные поля дескриптора.
        put64(desc, 0x20, (n_segs + 1) as u64 | (CHILD_ARGV_PAGES << 32));
        put64(desc, 0x28, argv_v as u64); // argv_src (у родителя)
        put64(desc, 0x30, argv_dst); // argv_dst (у ребёнка)
        put64(desc, 0x38, argv_bytes as u64);
        put64(desc, 0x40, 2); // argc
        put64(desc, 0x48, max_pages); // limits[0]: max_pages
        put64(desc, 0x50, CHILD_MAX_THREADS | (CHILD_MAX_ENDPOINTS << 32));
        put64(desc, 0x58, CHILD_MAX_SHM | (CHILD_MAX_CAPS << 32));
        put64(desc, 0x60, CHILD_MAX_PRIO as u64); // may_spawn = 0
        let b = CHILD_PRIORITY.to_le_bytes();
        for i in 0..b.len() {
            desc.add(0x68 + i).write_volatile(b[i]);
        }
        // v0.10: CPU-квота ребёнка — u32 @ 0x6C хвоста заголовка.
        let q = CHILD_CPU_QUOTA.to_le_bytes();
        for i in 0..4 {
            desc.add(0x6C + i).write_volatile(q[i]);
        }
        // Сегменты: образ (dst = base + vstart) + стек.
        for i in 0..n_segs {
            let seg = plan.segs[i];
            let at = SPAWN_HDR + i * SPAWN_SEG;
            put64(desc, at, srcs[i]); // src у родителя
            put64(desc, at + 8, base + seg.vstart); // dst у ребёнка
            put64(desc, at + 16, seg.pages);
            put64(desc, at + 24, seg.flags);
        }
        let at = SPAWN_HDR + n_segs * SPAWN_SEG;
        put64(desc, at, srcs[n_segs]); // src стека
        put64(desc, at + 8, stack_dst);
        put64(desc, at + 16, CHILD_STACK_PAGES);
        put64(desc, at + 24, 0b011); // RW
        let desc_len = SPAWN_HDR + (n_segs + 1) * SPAWN_SEG;

        // ---- (4) СПАВН: ядро принимает только указатели ----
        let cv = inst.task;
        let r = syscall6(
            SYS_TASK_SPAWN_IMAGE,
            tcb_self,
            cv as u64,
            (cv >> 64) as u64,
            desc_v as u64,
            desc_len as u64,
            0,
        );
        debug_word_line("init: pie: spawn_image ret = ", r as u64);
        if r <= 0 {
            return None;
        }
        let tcb_child = r as u64;
        // v0.10: подтверждение квоты — слово 6 (cpu_quota) сразу после
        // спавна: ребёнок родился в CPU-песочнице (дескриптор, u32 @ 0x6C).
        let qw = syscall6(SYS_TASK_LIMITS_INFO, tcb_child, 6, 0, 0, 0, 0);
        debug_word_line("init: pie: child cpu_quota word = ", qw as u64);

        // ---- (5) Порты и права ----
        let gate = syscall6(SYS_EP_CREATE, 4, 0, 0, 0, 0, 0);
        if gate <= 0 {
            puts("init: pie: EP_CREATE failed — abort");
            return None;
        }
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
        let _ = s1;
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
        let _ = s2;

        // ---- (6) GO: ребёнок ждёт в recv_any ----
        let self_tid = syscall6(SYS_SELF_INFO, 2, 0, 0, 0, 0, 0);
        let tv = inst.thread;
        let go = syscall6(
            SYS_IPC_SEND_THREAD,
            tv as u64,
            (tv >> 64) as u64,
            CMD_GO,
            self_tid as u64,
            2,
            0,
        );
        debug_word_line("init: pie: GO -> ", go as u64);

        // ---- (7) Обмен: READY + PIE_PTR -> PING x3 -> ATTACK ----
        let mut out = ChildOutcome {
            ready: false,
            self_ptr: 0,
            self_ptr_verified: false,
            ping_ok: 0,
            reported: false,
            blocked: 0,
            clean_exit: false,
            cpu_held: false,
        };
        if recv_any(0) >= 0 && msg_word(0) as u64 == CMD_READY {
            out.ready = true;
            debug_word_line("init: pie: child READY, ports = ", msg_word(1) as u64);
        }
        if !out.ready {
            puts("init: pie: child did not report READY, aborting instance");
            return Some(out);
        }
        // PIE_PTR: значение статического указателя ребёнка (отправляется
        // ВСЕГДА — иначе сообщение осталось бы в ящике и сместило бы эхо
        // PING). Проверка — только в PIE-режиме: значение обязано быть
        // base + addend одной из релокаций (загрузчик патчил .data).
        if recv_any(0) >= 0 && msg_word(0) as u64 == PIE_MAGIC {
            out.self_ptr = msg_word(1) as u64;
            debug_word_line("init: pie: child self-ptr   = ", out.self_ptr);
            if is_pie && out.self_ptr >= base && out.self_ptr < base + image_end {
                for r in &plan.relas[..plan.n_relas] {
                    if base.wrapping_add(r.addend) == out.self_ptr {
                        out.self_ptr_verified = true;
                        break;
                    }
                }
            }
        }
        debug_word_line(
            "init: pie: self-ptr verified = ",
            out.self_ptr_verified as u64,
        );

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
                out.ping_ok += 1;
            } else {
                debug_word_line("init: pie: BAD EXCHANGE, echo = ", echo);
            }
        }
        debug_word_line("init: pie: ping-pong rounds ok = ", out.ping_ok);
        if out.ping_ok != 3 {
            return Some(out);
        }

        puts("init: pie: ordering the attack (child will try to escape)");
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
        if recv_any(0) >= 0 && msg_word(0) as u64 == REPORT_MAGIC {
            out.blocked = msg_word(1) as u64;
            out.reported = true;
        }
        if !out.reported {
            puts("init: pie: NO REPORT from child (broken protocol)");
        }

        // ---- (8) Exit-уведомление на порт init (TASK_SET_EXIT_EP) ----
        let exit_tag = syscall6(SYS_IPC_RECV, gate as u64, 0, 0, 0, 0, 0);
        let exit_code = msg_word(3);
        let cpu_used = msg_word(4);
        let throttle_events = msg_word(5);
        debug_word_line("init: pie: exit notification tag = ", exit_tag as u64);
        debug_word_line("init: pie: child exit code = ", exit_code as u64);
        debug_word_line("init: pie: child cpu_used (ticks) = ", cpu_used as u64);
        debug_word_line(
            "init: pie: child cpu throttle events = ",
            throttle_events as u64,
        );
        out.clean_exit = exit_tag == 1 && exit_code == 0x5A;
        out.cpu_held = throttle_events > 0;

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
        debug_word_line("init: pie: staging regions returned = ", freed);
        out.self_ptr_verified = out.self_ptr_verified && reloc_ok;
        Some(out)
    }
}

/// S4: песочница + PIE. Спавнит ВСТРОЕННЫЙ образ как домен(ы) с полной
/// песочницей GTCB; PIE-сборка — дважды, на разных базах.
unsafe fn sandbox_pie_demo() {
    unsafe {
        puts("=== init: S4 sandbox + pie spawn demo (embedded image) ===");

        if CHILD_ELF.is_empty() {
            puts("init: pie: no embedded child image (set ROGUE_ELF at build), skipped");
            return;
        }
        let plan = match pie::Plan::parse(CHILD_ELF) {
            Ok(p) => p,
            Err(e) => {
                puts("init: pie: embedded image rejected by loader (fail-closed)");
                debug_word_line("init: pie: loader error code = ", e.code());
                return;
            }
        };
        match plan.kind {
            pie::ImageKind::Pie => {
                puts("init: pie: image is ET_DYN — relocatable, spawn at chosen bases")
            }
            pie::ImageKind::StaticFixed => {
                puts("init: pie: image is ET_EXEC (legacy build) — single fixed-base spawn")
            }
        }
        debug_word_line("init: pie: PT_LOAD segments = ", plan.n_segs as u64);
        debug_word_line("init: pie: RELATIVE relocs = ", plan.n_relas as u64);

        // Право творца init: TaskTCB(себя) — от kinit.
        let tcb_self = match find_tcb_handle() {
            Some(h) => h,
            None => {
                puts("init: pie: no creator TCB (kinit grant missing?) — skipped");
                return;
            }
        };

        // «Приманка» для атак: собственный SHM-регион init (id — как
        // выдаст ядро) — оба инстанса будут пытаться разрушить ЧУЖОЙ
        // регион (owner-гейт); гасим её ПОСЛЕ прогонов сами.
        let shm_bait = syscall6(0x61, 1, 0, 0, 0, 0, 0);
        debug_word_line("init: pie: bait shm region id = ", shm_bait as u64);

        // Прогоны: PIE — оба инстанса (разные базы); статический образ —
        // только первый (второй базе взяться неоткуда: адреса вшиты).
        let only_first = plan.kind == pie::ImageKind::StaticFixed;
        let mut verdict_ok = true;
        for inst in INSTANCES.iter() {
            puts("init: pie: === instance ===");
            let outcome = spawn_and_run_child(&plan, inst, tcb_self);
            let Some(out) = outcome else {
                verdict_ok = false;
                continue;
            };
            let inst_ok = out.ready
                && out.ping_ok == 3
                && out.reported
                && out.blocked >= 8
                && out.clean_exit
                && out.cpu_held;
            let pie_ok = match plan.kind {
                pie::ImageKind::Pie => out.self_ptr_verified,
                pie::ImageKind::StaticFixed => true,
            };
            debug_word_line("init: pie: instance verdict = ", inst_ok as u64);
            verdict_ok &= inst_ok && pie_ok;
            if only_first {
                break;
            }
        }

        // Приманка отработала: уничтожаем СВОЙ регион (владелец — init).
        let bait_gone = syscall6(0x65, shm_bait as u64, 0, 0, 0, 0, 0);
        debug_word_line("init: pie: bait shm destroyed = ", bait_gone as u64);
        // Проверка учёта: TASK_LIMITS_INFO(self): слово 1 = usage pages.
        let usage = syscall6(SYS_TASK_LIMITS_INFO, tcb_self, 1, 0, 0, 0, 0);
        debug_word_line("init: pie: init page usage now = ", usage as u64);

        if verdict_ok {
            puts("init: sandbox VERDICT: sandbox HELD — all escape/DoS attempts blocked");
            puts("init: sandbox VERDICT: cpu quota HELD — child throttled by GTCB budget");
            match plan.kind {
                pie::ImageKind::Pie => {
                    puts("init: pie VERDICT: PIE spawn OK — same image ran at two different bases")
                }
                pie::ImageKind::StaticFixed => {
                    puts("init: pie VERDICT: static spawn OK (legacy image, single base)")
                }
            }
        } else {
            puts("init: sandbox VERDICT: demo finished with anomalies (see above)");
        }
    }
}

// ───────────────────────── S5 (v0.11): внешние линии ─────────────────────────

const SYS_IRQ_ATTACH: u64 = 0x46;
const SYS_IRQ_DETACH: u64 = 0x47;
const SYS_IRQ_ACK: u64 = 0x48;
const SYS_SYS_TIME: u64 = 0x04;

/// S5: НАСТОЯЩАЯ линия железа как L4-сообщение (COM1, ISA IRQ4 -> GSI 4).
///
/// v0.14: право на линию подтверждает IoResource(Irq)-cap (kinit-грант):
/// перебираем свои capability (CAP_LIST), находим kind=8 (Irq-диапазон)
/// и привязываем GSI 4 к endpoint. Реестра устройств в ядре больше нет —
/// ядро возводит линию (IOAPIC RTE; при включённом ремаппинге IOMMU —
/// IRTE+remapped-RTE — аудит ядра в консоли), вывод консоли осушает
/// передатчик — IRQ4 -> signal(=gsi) в наш endpoint. ACK -> detach ->
/// вердикт: полный контур линии в сообщениях L4.
unsafe fn ioapic_demo() {
    unsafe {
        puts("=== init: S5 external irq demo (real COM1 line, L4 signal) ===");
        // Endpoint приёма сигналов линии.
        let gate = syscall6(SYS_EP_CREATE, 4, 0, 0, 0, 0, 0);
        if gate <= 0 {
            puts("init: ioapic: EP_CREATE failed — skipped");
            return;
        }
        // Irq-cap (kind 8) — kinit-грант сырых ресурсов.
        let n = syscall6(SYS_CAP_LIST, 0, 0, 0, 0, 0, 0);
        if n <= 0 {
            puts("init: ioapic: no capabilities (kinit grants missing?) — skipped");
            return;
        }
        let mut irq_cap = 0u64;
        let mut idx = 1u64;
        for _ in 0..n {
            // CAP_LIST: ПО ДВА слова на слот ([idx] = handle, [idx+1] = kind).
            let handle = syscall6(SYS_CAP_LIST, idx, 0, 0, 0, 0, 0) as u64;
            let kind = syscall6(SYS_CAP_LIST, idx + 1, 0, 0, 0, 0, 0) as u64;
            if kind == 8 && handle > 0 {
                irq_cap = handle;
                break;
            }
            idx += 2;
        }
        if irq_cap == 0 {
            puts("init: ioapic: no IoResource(Irq) cap (kinit grant?) — skipped");
            return;
        }
        // Привязка GSI 4 (edge — ISO MADT канонизует триггер в бекенде).
        let attach = syscall6(SYS_IRQ_ATTACH, irq_cap, 4, gate as u64, 0, 0, 0);
        if attach != 0 {
            debug_word_line("init: ioapic: IRQ_ATTACH(4) ret = ", attach as u64);
            puts("init: ioapic: line attach failed — skipped");
            return;
        }
        // Строка ниже осушает передатчик: THR-empty -> IRQ4 latch-ится
        // и прибудет signal-ом на первом же sysret.
        puts("init: ioapic: line up (ISA IRQ4 -> GSI 4); console drain fires it");
        // Приём сигнала (edge: события до pending склеиваются одним
        // словом — семантика уведомлений L4).
        let r = syscall6(SYS_IPC_RECV, gate as u64, 0, 0, 0, 0, 0);
        let word = msg_word(0);
        debug_word_line("init: ioapic: signal word = ", word as u64);
        let ack = syscall6(SYS_IRQ_ACK, 4, 0, 0, 0, 0, 0);
        let detach = syscall6(SYS_IRQ_DETACH, 4, 0, 0, 0, 0, 0);
        debug_word_line("init: ioapic: irq_ack ret    = ", ack as u64);
        debug_word_line("init: ioapic: irq_detach ret = ", detach as u64);
        if r >= 0 && word == 4 && detach == 0 {
            puts(
                "init: ioapic VERDICT: real hw IRQ delivered as L4 signal (IOAPIC->LAPIC->endpoint)",
            );
        } else {
            puts("init: ioapic VERDICT: demo finished with anomalies (see above)");
        }
    }
}

// ───────────── S6 (v0.14): acpid — ACPI/AML в юзерспейсе, S5-poweroff ─────────────

/// Идентификаторы домена acpid (L4: 128-бит, выбирает init).
const ACPID_TASK: u128 = 0x2600_0000;
const ACPID_THREAD: u128 = 0x2600_0001;
/// База PIE-образа acpid (S4-инстансы уже умерли и вернули кадры).
const ACPID_BASE: u64 = 0x5000_0000;

/// Квоты acpid (менеджер — не песочница: щедрые, но конечные).
const ACPID_PAGES_HEADROOM: u64 = 2560; // + bump-куча 2048 и AML-namespace
const ACPID_MAX_THREADS: u64 = 4;
const ACPID_MAX_ENDPOINTS: u64 = 4;
const ACPID_MAX_SHM: u64 = 2;
const ACPID_MAX_CAPS: u64 = 16;
const ACPID_PRIO: u8 = 100;
const ACPID_CPU_QUOTA: u32 = 100;

/// S6: спавн acpid — ACPI-менеджера в юзерспейсе. AML-интерпретатор
/// (тяжелейшая часть ACPI) теперь НЕ в ядре: паника AML убивает
/// acpid, а не ядро. init передаёт ребёнку (a) argv с rsdp=0x... и
/// (b) три IoResource-гранта (физика/порты/линии) через CAP_MINT —
/// acpid сам читает таблицы, обходит namespace, подписывается на SCI
/// и ВЫКЛЮЧАЕТ ПК записью S5|SLP_EN в PM1a_CNT (IOP_OUT за cap).
unsafe fn acpid_demo() {
    unsafe {
        puts("=== init: S6 acpid demo (userspace AML + S5 power-off) ===");
        if ACPID_ELF.is_empty() {
            puts("init: acpid: no embedded image (set ACPID_ELF at build) — skipped");
            return;
        }
        let rsdp_len = unsafe { RSDP_LINE_LEN };
        if rsdp_len == 0 {
            puts("init: acpid: no rsdp= in boot_state (kinit?) — skipped");
            return;
        }
        let plan = match pie::Plan::parse(ACPID_ELF) {
            Ok(p) => p,
            Err(e) => {
                puts("init: acpid: image rejected by loader (fail-closed)");
                debug_word_line("init: acpid: loader error code = ", e.code());
                return;
            }
        };
        if plan.kind == pie::ImageKind::Pie {
            puts("init: acpid: image is ET_DYN — spawn at chosen base")
        } else {
            puts("init: acpid: image is ET_EXEC (legacy) — fixed-base spawn")
        }
        debug_word_line("init: acpid: PT_LOAD segments = ", plan.n_segs as u64);
        debug_word_line("init: acpid: RELATIVE relocs = ", plan.n_relas as u64);

        // Право творца init: TaskTCB(себя) — от kinit.
        let Some(tcb_self) = find_tcb_handle() else {
            puts("init: acpid: no creator TCB (kinit grant missing?) — skipped");
            return;
        };

        // ---- Staging: сегменты (как у S4) ----
        let is_pie = plan.kind == pie::ImageKind::Pie;
        let base = if is_pie { ACPID_BASE } else { 0 };
        let image_end = plan.image_end();
        let stack_dst = (base + image_end + 0xFFF) & !0xFFF;
        let stack_top = stack_dst + CHILD_STACK_PAGES * 0x1000;
        let argv_dst = (stack_top + 0xFFF) & !0xFFF;

        let mut srcs = [0u64; SPAWN_SEGS_MAX + 2];
        let mut image_pages = 0u64;
        let n_segs = plan.n_segs;
        for i in 0..n_segs {
            let seg = plan.segs[i];
            let v = syscall6(SYS_MEM_ALLOC, seg.pages, 0b011, 0, 0, 0, 0);
            if v <= 0 {
                puts("init: acpid: staging MEM_ALLOC failed — abort");
                return;
            }
            let region = v as u64 as *mut u8;
            zero(region, 0, seg.pages as usize * 0x1000);
            if seg.filesz > 0 {
                let file_end = seg.in_seg as u64 + seg.filesz;
                if seg.file_off + file_end <= ACPID_ELF.len() as u64 {
                    copy_bytes(
                        region.add(seg.in_seg as usize),
                        &ACPID_ELF[seg.file_off as usize..(seg.file_off + seg.filesz) as usize],
                    );
                }
            }
            srcs[i] = region as u64;
            image_pages += seg.pages;
        }
        // Релокации PIE (контракт: ядро получает залинкованный образ).
        if is_pie {
            let _ = plan.apply_rela(base, |vaddr, val| {
                if let Some((ptr, off)) = staging_ptr_of(&plan, &srcs, vaddr) {
                    unsafe { put64(ptr, off, val) };
                }
            });
        }

        // Стек.
        let stack_v = syscall6(SYS_MEM_ALLOC, CHILD_STACK_PAGES, 0b011, 0, 0, 0, 0);
        if stack_v <= 0 {
            puts("init: acpid: stack staging failed — abort");
            return;
        }
        zero(
            stack_v as u64 as *mut u8,
            0,
            CHILD_STACK_PAGES as usize * 0x1000,
        );
        srcs[n_segs] = stack_v as u64;

        // argv-блок: ["acpid", "rsdp=0x..."] — факт прошивки транзитом.
        let argv_v = syscall6(SYS_MEM_ALLOC, CHILD_ARGV_PAGES, 0b011, 0, 0, 0, 0);
        if argv_v <= 0 {
            puts("init: acpid: argv staging failed — abort");
            return;
        }
        let argv_region = argv_v as u64 as *mut u8;
        zero(argv_region, 0, CHILD_ARGV_PAGES as usize * 0x1000);
        let rsdp = unsafe { &RSDP_LINE[..rsdp_len] };
        let name_len = "acpid".len();
        put64(argv_region, 0, 2); // argc
        put64(argv_region, 8, argv_dst + 40);
        put64(argv_region, 16, argv_dst + 40 + (name_len + 1) as u64);
        put64(argv_region, 24, 0); // NULL
        put64(argv_region, 32, 0); // pad
        let mut off = 40usize;
        off += copy_str(argv_region.add(off), b"acpid");
        for (i, &b) in rsdp.iter().enumerate() {
            argv_region.add(off + i).write_volatile(b);
        }
        off += rsdp_len;
        let argv_bytes = off;
        srcs[n_segs + 1] = argv_v as u64;

        // Дескриптор спавна.
        let desc_v = syscall6(SYS_MEM_ALLOC, 1, 0b011, 0, 0, 0, 0);
        if desc_v <= 0 {
            puts("init: acpid: desc staging failed — abort");
            return;
        }
        let desc = desc_v as u64 as *mut u8;
        let max_pages = image_pages + CHILD_STACK_PAGES + CHILD_ARGV_PAGES + ACPID_PAGES_HEADROOM;
        zero(desc, 0, 0x1000);
        put64(desc, 0x00, base + plan.entry);
        put64(desc, 0x08, stack_top);
        put64(desc, 0x10, ACPID_THREAD as u64);
        put64(desc, 0x18, (ACPID_THREAD >> 64) as u64);
        put64(desc, 0x20, (n_segs + 1) as u64 | (CHILD_ARGV_PAGES << 32));
        put64(desc, 0x28, argv_v as u64);
        put64(desc, 0x30, argv_dst);
        put64(desc, 0x38, argv_bytes as u64);
        put64(desc, 0x40, 2); // argc
        put64(desc, 0x48, max_pages);
        put64(desc, 0x50, ACPID_MAX_THREADS | (ACPID_MAX_ENDPOINTS << 32));
        put64(desc, 0x58, ACPID_MAX_SHM | (ACPID_MAX_CAPS << 32));
        put64(desc, 0x60, ACPID_PRIO as u64); // may_spawn = 0
        let b = ACPID_PRIO.to_le_bytes();
        for i in 0..b.len() {
            desc.add(0x68 + i).write_volatile(b[i]);
        }
        let q = ACPID_CPU_QUOTA.to_le_bytes();
        for i in 0..4 {
            desc.add(0x6C + i).write_volatile(q[i]);
        }
        for i in 0..n_segs {
            let seg = plan.segs[i];
            let at = SPAWN_HDR + i * SPAWN_SEG;
            put64(desc, at, srcs[i]);
            put64(desc, at + 8, base + seg.vstart);
            put64(desc, at + 16, seg.pages);
            put64(desc, at + 24, seg.flags);
        }
        let at = SPAWN_HDR + n_segs * SPAWN_SEG;
        put64(desc, at, srcs[n_segs]);
        put64(desc, at + 8, stack_dst);
        put64(desc, at + 16, CHILD_STACK_PAGES);
        put64(desc, at + 24, 0b011);
        let desc_len = SPAWN_HDR + (n_segs + 1) * SPAWN_SEG;

        // Спавн.
        let r = syscall6(
            SYS_TASK_SPAWN_IMAGE,
            tcb_self,
            ACPID_TASK as u64,
            (ACPID_TASK >> 64) as u64,
            desc_v as u64,
            desc_len as u64,
            0,
        );
        debug_word_line("init: acpid: spawn_image ret = ", r as u64);
        if r <= 0 {
            puts("init: acpid: spawn failed — demo aborted");
            return;
        }
        let tcb_child = r as u64;

        // Гранты сырых ресурсов: копии IoResource init -> cspace acpid
        // (CAP_MINT; init сохраняет свои — раздаёт копии).
        let n = syscall6(SYS_CAP_LIST, 0, 0, 0, 0, 0, 0);
        let mut granted = 0u64;
        if n > 0 {
            let mut idx = 1u64;
            for _ in 0..n {
                // CAP_LIST: ПО ДВА слова на слот ([idx] = handle, [idx+1] = kind).
                let handle = syscall6(SYS_CAP_LIST, idx, 0, 0, 0, 0, 0) as u64;
                let kind = syscall6(SYS_CAP_LIST, idx + 1, 0, 0, 0, 0, 0) as u64;
                if (6..=8).contains(&kind) && handle > 0 {
                    let m = syscall6(
                        SYS_CAP_MINT,
                        handle,
                        ACPID_TASK as u64,
                        (ACPID_TASK >> 64) as u64,
                        0xFF,
                        0xFFFF_FFFF_FFFF_FFFF,
                        0,
                    );
                    if m > 0 {
                        granted += 1;
                    } else {
                        debug_word_line("init: acpid: CAP_MINT(kind) ret = ", m as u64);
                    }
                }
                idx += 2;
            }
        }
        // «Своя кухня» домена: копия TaskTCB(acpid) -> acpid.
        let _ = syscall6(
            SYS_CAP_MINT,
            tcb_child,
            ACPID_TASK as u64,
            (ACPID_TASK >> 64) as u64,
            0xFF,
            0xFFFF_FFFF_FFFF_FFFF,
            0,
        );
        debug_word_line("init: acpid: IoResource grants minted = ", granted);
        if granted < 3 {
            puts("init: acpid: WARN: fewer than 3 IoResource grants (kinit?)");
        }

        puts("init: acpid spawned: userspace AML -> enumerate -> SCI -> S5 power-off");
        puts("init: parking (VM should power off from userspace; timeout = failure)");
        // Парковка с дедлайном диагностики (60 с): успех = VM выключена.
        let deadline = syscall6(SYS_SYS_TIME, 0, 0, 0, 0, 0, 0) as u64 + 60_000_000_000u64;
        loop {
            let now = syscall6(SYS_SYS_TIME, 0, 0, 0, 0, 0, 0);
            if now as u64 >= deadline {
                puts("init: acpid VERDICT: VM still alive after 60s — S5 failed (see log)");
                break;
            }
            let _ = syscall6(SYS_THREAD_YIELD, 0, 0, 0, 0, 0, 0);
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
                    // v0.14: rsdp=0x... — транзит для acpid (S6).
                    if n >= 6 && &line[..5] == b"rsdp=" && n <= 24 {
                        unsafe {
                            RSDP_LINE[..n].copy_from_slice(&line[..n]);
                            RSDP_LINE_LEN = n;
                        }
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

            // S4 (v0.9→v0.11): песочница + PIE-спавн — образ rogue
            // грузится на выборных базах (дважды для PIE), порты, обмен,
            // атаки, вердикт.
            sandbox_pie_demo();

            // S5 (v0.11): настоящая линия железа (COM1 IRQ4 -> GSI 4)
            // как L4-signal: полный контур IOAPIC->LAPIC->endpoint.
            ioapic_demo();

            // S6 (v0.14): acpid — ACPI/AML-менеджер в юзерспейсе;
            // успех = ВЫКЛЮЧЕНИЕ ПК юзерспейсом (S5, PM1a_CNT).
            acpid_demo();
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
