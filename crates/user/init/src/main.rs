// ==== INIT: init-сервер (boot-chain smoke, v3) ====
//
// Первый СЕРВЕР юзерспейса (спавнится бутстрапом из boot-архива RLBA;
// модуль [0] BootInfo v3 — сам архив, не этот образ).
//
// Сценарий (все шаги печатаются в serial через DEBUG_WRITE):
//   S1. стартовое IPC (от ядра через TASK_SPAWN_IMAGE): argc/argv
//       (+ boot_state транзитом, имя = «init» + args из каталога RLBA);
//   S2. SELF_INFO: task/thread id, CPU, cpu_count;
//   S3. IPC ping-pong: рабочий поток + main гоняют сообщение через
//       пару гейтов (EP_CREATE) ROUNDS раз — на SMP это упражняет
//       парковку/пробуждение (resched-IPI в hlt!), миграции между
//       очередями и preempt-путь EEVDF; миграции CPU печатаются;
//   S4. воркер гасится THREAD_TERMINATE(себя), main — TASK_EXIT(0):
//       ядро печатает «all user threads gone — halting» = цепочка OK.
//
// Никакой кучи: статика + сырые слова (дисциплина userlib-серверов).

#![no_std]
#![no_main]

use userlib::{
    l4_cap_list, l4_ep_create, l4_ipc_msg_word, l4_ipc_recv, l4_ipc_send, l4_self_info,
    l4_sys_time, l4_task_exit, l4_thread_create, l4_thread_terminate,
};

/// Раундов ping-pong: достаточно, чтобы поймать preempt-тики и (на
/// удачной фазе) миграцию воркера между CPU.
const ROUNDS: u64 = 200;

/// CPU-bound фаза после ping-pong (нс): ТРИ готовых потока одновременно
/// на одном CPU — переподписка 3:1. Важно для EEVDF: равные веса при
/// 2-поточной конкуренции дают slip = 0 (каждое ожидание = ровно vslice
/// — свойство честности), а при 3:1 каждый ждёт 2 слайса при vslice в
/// 1 слайс → опоздание ≈ 1 vslice → pressure → 255 → витрина → кража
/// балансировщиком — миграция видна в печати.
const SPIN_NS: u64 = 1_000_000_000;

/// Запас main перед TASK_EXIT: воркеры начинают фазу позже — дадим им
/// закончить и напечатать свой финиш.
const SPIN_MAIN_EXTRA_NS: u64 = 500_000_000;

/// Печатать сводку каждые N раундов.
const PRINT_EVERY: u64 = 50;

/// Тиды воркеров (малые, старшее слово = 0).
const WORKER_TID: u64 = 0x2001;
const WORKER2_TID: u64 = 0x2002;
const WORKER3_TID: u64 = 0x2003;

/// Стеки воркеров: по 8 страниц в .bss, выравнивание 4K через
/// тип-обёртку (repr(align) на static напрямую нельзя).
#[repr(align(4096))]
struct AlignedStack([u8; 8 * 4096]);

static mut WORKER_STACK: AlignedStack = AlignedStack([0; 8 * 4096]);
static mut WORKER2_STACK: AlignedStack = AlignedStack([0; 8 * 4096]);
static mut WORKER3_STACK: AlignedStack = AlignedStack([0; 8 * 4096]);

/// Гейт воркер -> main (сообщения-ходы).
static mut GATE_MAIN: u64 = 0;
/// Гейт main -> воркер (ответы).
static mut GATE_WORK: u64 = 0;
/// Гейт main -> воркер2 (GO на CPU-bound фазу).
static mut GATE_W2: u64 = 0;
/// Гейт main -> воркер3 (GO на CPU-bound фазу).
static mut GATE_W3: u64 = 0;

// ───────────────────────── Печать (serial) ─────────────────────────

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
    // Префикс — без перевода строки (число в той же строке).
    let mut rest = prefix.as_bytes();
    while !rest.is_empty() {
        let n = rest.len().min(40);
        userlib::l4_debug_write_bytes(rest[..n].as_ptr(), n as u64);
        rest = &rest[n..];
    }
    let mut rest = &buf[i..];
    while !rest.is_empty() {
        let n = rest.len().min(40);
        userlib::l4_debug_write_bytes(rest[..n].as_ptr(), n as u64);
        rest = &rest[n..];
    }
    userlib::l4_debug_write_bytes(b"\r\n".as_ptr(), 2);
}

// ───────────────────────── Воркер ─────────────────────────

/// CPU-bound фаза: крутиться SPIN_NS наносекунд, отслеживая миграции
/// (SELF_INFO слово 4 — текущий CPU). Это давление на EEVDF-дедлайны
/// — триггер публикации витрины и почерки для вор.
fn spin_phase(tag: &str, ns: u64) {
    let t0 = l4_sys_time() as u64;
    let mut cpu_last = l4_self_info(4) as u64;
    let mut n: u32 = 0;
    loop {
        n = n.wrapping_add(1);
        if n & 0x1FF == 0 {
            if l4_sys_time() as u64 - t0 >= ns {
                break;
            }
            let cpu = l4_self_info(4) as u64;
            if cpu != cpu_last {
                putdec("init: LB: migrated from cpu ", cpu_last);
                putdec("init: LB:               to cpu ", cpu);
                cpu_last = cpu;
            }
        }
        core::hint::spin_loop();
    }
    putdec(tag, cpu_last);
}

/// Рабочий поток ping-pong: ход -> гейт main, ответ <- гейт work.
#[unsafe(no_mangle)]
extern "C" fn init_worker() -> ! {
    let tid_lo = l4_self_info(2) as u64;
    let tid_hi = l4_self_info(3) as u64;
    let mut cpu_last = l4_self_info(4) as u64;
    putdec("init: worker: up on cpu ", cpu_last);
    for i in 0..ROUNDS {
        // SAFETY: чтение static mut (написан main'ом до THREAD_CREATE).
        let (gm, gw) = unsafe { (GATE_MAIN, GATE_WORK) };
        // Ход: main ждёт на GATE_MAIN.
        l4_ipc_send(gm, i, 0, 0, 0);
        // Ответ: ждать на GATE_WORK (парковка -> main нас разбудит).
        let _ = l4_ipc_recv(gw, 0);
        // Где мы оказались: миграция между CPU — подарок LB.
        let cpu = l4_self_info(4) as u64;
        if cpu != cpu_last {
            putdec("init: worker: migrated cpu ", cpu_last);
            putdec("init: worker:          -> cpu ", cpu);
            cpu_last = cpu;
        }
        if i % PRINT_EVERY == 0 {
            putdec("init: worker: round ", i);
        }
    }
    // CPU-bound фаза: вместе с main (оба готовы одновременно) —
    // давление на планировщик для триггера балансировки.
    spin_phase("init: worker spin done on cpu ", SPIN_NS);
    // Финиш: погасить себя (main после своего цикла выходит из
    // задачи; TASK_EXIT прибьёт и этот поток, но честный порядок
    // чище: воркер умирает первым, main видит тишину на гейтах).
    let _ = l4_thread_terminate(tid_lo, tid_hi);
    unreachable!()
}

/// Второй/третий воркеры: ждут GO на своих гейтах (не мешают
/// ping-pong), затем CPU-bound фаза — переподписка 4:1: каждый ждёт
/// 3 слайса при hot-окне в 2 — кандидаты становятся ХОЛОДНЫМИ и
/// витрина публикует их через штатный путь (без hard-рельефа).
#[unsafe(no_mangle)]
extern "C" fn init_worker2() -> ! {
    let tid_lo = l4_self_info(2) as u64;
    let tid_hi = l4_self_info(3) as u64;
    // Ждать GO (парковка на гейте: не конкурирует за CPU).
    let gw = unsafe { GATE_W2 };
    let _ = l4_ipc_recv(gw, 0);
    spin_phase("init: worker2 spin done on cpu ", SPIN_NS);
    let _ = l4_thread_terminate(tid_lo, tid_hi);
    unreachable!()
}

#[unsafe(no_mangle)]
extern "C" fn init_worker3() -> ! {
    let tid_lo = l4_self_info(2) as u64;
    let tid_hi = l4_self_info(3) as u64;
    let gw = unsafe { GATE_W3 };
    let _ = l4_ipc_recv(gw, 0);
    spin_phase("init: worker3 spin done on cpu ", SPIN_NS);
    let _ = l4_thread_terminate(tid_lo, tid_hi);
    unreachable!()
}

// ───────────────────────── main ─────────────────────────

/// Найти хендл своего TaskTCB (kind == 2) перебором CAP_LIST — тот же
/// паттерн, что у init/rogue: kinit выдаёт задаче грант на себя.
fn find_tcb_handle() -> Option<u64> {
    let mut idx = 1u64;
    for _ in 0..64 {
        let handle = l4_cap_list(idx);
        let kind = l4_cap_list(idx + 1);
        if handle <= 0 && kind <= 0 {
            break; // конец списка
        }
        if kind == 2 && handle > 0 {
            return Some(handle as u64);
        }
        idx += 2;
    }
    None
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const i8) -> i32 {
    putdec("init: hello from init server (v3, spawned by bootstrap)", 0);
    putdec("init: argc = ", argc as u64);
    putdec("init: sys_time = ", l4_sys_time() as u64);

    // argv (+ boot_state транзитом): печать построчно.
    for i in 0..argc.max(0) as usize {
        // SAFETY: argv-блок построен ядром (2 страницы под стеком).
        let p = unsafe { *argv.add(i) };
        if p.is_null() {
            break;
        }
        puts("init: argv:");
        let mut q = p;
        let mut buf = [0u8; 40];
        'arg: loop {
            let mut n = 0usize;
            // SAFETY: ASCIIZ-строка по контракту стартового блока.
            while n < 40 && unsafe { *q.add(n) } != 0 {
                buf[n] = unsafe { *q.add(n) } as u8;
                n += 1;
            }
            if n > 0 {
                userlib::l4_debug_write_bytes(buf.as_ptr(), n as u64);
            }
            if n < 40 {
                break 'arg;
            }
            q = unsafe { q.add(40) };
        }
        userlib::l4_debug_write_bytes(b"\r\n".as_ptr(), 2);
    }

    // Конфигурация SMP.
    let cpu = l4_self_info(4) as u64;
    let cpus = l4_self_info(5) as u64;
    putdec("init: main on cpu ", cpu);
    putdec("init: cpu_count = ", cpus);

    // Гейты ping-pong (буферизованные, capacity 8: без rendezvous).
    unsafe {
        GATE_MAIN = l4_ep_create(8) as u64;
        GATE_WORK = l4_ep_create(8) as u64;
        GATE_W2 = l4_ep_create(8) as u64;
        GATE_W3 = l4_ep_create(8) as u64;
    }
    if unsafe { GATE_MAIN } <= 0
        || unsafe { GATE_WORK } <= 0
        || unsafe { GATE_W2 } <= 0
        || unsafe { GATE_W3 } <= 0
    {
        puts("init: EP_CREATE failed");
        return 3;
    }

    // Стек воркера: top = база + размер (растёт вниз, ABI x86_64).
    // SAFETY: чтение адреса поля static mut (написан до THREAD_CREATE,
    // потоки ещё не запущены — гонок нет).
    let stack_top = unsafe { core::ptr::addr_of_mut!(WORKER_STACK.0) } as *const u8 as u64
        + core::mem::size_of::<AlignedStack>() as u64;

    // Свой TaskTCB (право на THREAD_CREATE в домене).
    let Some(tcb) = find_tcb_handle() else {
        puts("init: no TaskTCB handle (kinit grant missing?)");
        return 4;
    };

    // Поднять воркеров: worker — ping-pong партнёр, worker2 — ждёт GO
    // на своём гейте (парковка, за CPU не конкурирует до времени).
    let r = l4_thread_create(tcb, init_worker as *const () as u64, stack_top, WORKER_TID);
    if r != 0 {
        putdec("init: THREAD_CREATE ret ", r as u64);
        return 5;
    }
    // SAFETY: как WORKER_STACK (обе записи завершены до запуска).
    let stack2_top = unsafe { core::ptr::addr_of_mut!(WORKER2_STACK.0) } as *const u8 as u64
        + core::mem::size_of::<AlignedStack>() as u64;
    let r2 = l4_thread_create(
        tcb,
        init_worker2 as *const () as u64,
        stack2_top,
        WORKER2_TID,
    );
    if r2 != 0 {
        putdec("init: THREAD_CREATE(2) ret ", r2 as u64);
        return 6;
    }
    // SAFETY: как WORKER_STACK (обе записи завершены до запуска).
    let stack3_top = unsafe { core::ptr::addr_of_mut!(WORKER3_STACK.0) } as *const u8 as u64
        + core::mem::size_of::<AlignedStack>() as u64;
    let r3 = l4_thread_create(
        tcb,
        init_worker3 as *const () as u64,
        stack3_top,
        WORKER3_TID,
    );
    if r3 != 0 {
        putdec("init: THREAD_CREATE(3) ret ", r3 as u64);
        return 7;
    }
    puts("init: workers spawned, ping-pong start");

    // main-петля: принять ход, ответать. Блокировка на GATE_MAIN —
    // парковка; пробуждение — путь wake/notify планировщика.
    for i in 0..ROUNDS {
        // SAFETY: чтёние static mut (написаны выше до create).
        let (gm, gw) = unsafe { (GATE_MAIN, GATE_WORK) };
        let _ = l4_ipc_recv(gm, 0);
        let w = l4_ipc_msg_word(0) as u64;
        let _ = l4_ipc_send(gw, w + 1, 0, 0, 0);
        if i % PRINT_EVERY == 0 {
            putdec("init: main: round ", i);
        }
    }

    // GO второму воркеру, затем CPU-bound фаза: ТРИ готовых потока —
    // переподписка 3:1 (триггер pressure/витрины/кражи). Запас
    // времени — чтобы воркеры напечатали свой финиш до TASK_EXIT.
    let (gw2, gw3) = unsafe { (GATE_W2, GATE_W3) };
    let _ = l4_ipc_send(gw2, 1, 0, 0, 0);
    let _ = l4_ipc_send(gw3, 1, 0, 0, 0);
    spin_phase("init: main spin done on cpu ", SPIN_NS + SPIN_MAIN_EXTRA_NS);

    // Дать воркеру умереть (он завершил свой цикл и терминировал себя).
    puts("init: ping-pong done");
    puts("init: boot chain OK — exiting via TASK_EXIT(0)");
    l4_task_exit(0)
}
