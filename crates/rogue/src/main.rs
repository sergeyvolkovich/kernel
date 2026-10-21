// ==== ROGUE: дочерняя задача песочницы (sandbox-демо v0.9) ====
//
// Злонамеренный гость: init спавнит ЭТОТ образ из байтов, вшитых в
// init (include_bytes), через TASK_SPAWN_IMAGE — по дескриптору, где
// все регионы уже выделены и скопированы родителем (ядро принимает
// только указатели). Ребёнок рождается в песочнице GTCB:
//
//   max_pages/max_threads/max_endpoints/max_shm/max_caps/max_prio,
//   may_spawn=0, IommuAdmin-гранта нет, TaskTCB на родителя нет.
//
// Протокол (порты + обмен информацией):
//   1. _start (userlib) принял стартовое IPC -> main(argc, argv);
//   2. recv_any: GO [cmd, parent_tid] — родитель успел выдать права;
//   3. CAP_LIST: сам находит TaskTCB(себя) (kind 2) и Gate(порт
//      родителя) (kind 3) — «открывает порты» (EP_CREATE свои);
//   4. TASK_SET_EXIT_EP(gate): уведомление о своей смерти родителю;
//   5. READY -> родителю (IPC_SEND_THREAD fast-path, зная его tid);
//   6. PING x3 (родитель шлёт номер — ребёнок отвечает эхо+контрольная);
//   7. ATTACK: каскад попыток выхода/DoS (каждая ПЕЧАТАЕТ errno,
//      ядро печатает аудит «[kernel: sandbox] ...» в консоль);
//   8. REPORT -> родителю; TASK_EXIT(0x5A) — «честная сдача».
//
// Никакого alloc: статика + сырые слова; консоль — DEBUG_WRITE
// (l4_puts из userlib).

#![no_std]
#![no_main]

// ───────────────────────── Константы протокола ─────────────────────────

const CMD_GO: u64 = 0x474F; // "GO"
const CMD_PING: u64 = 1;
const CMD_ATTACK: u64 = 2;
const CMD_READY: u64 = 0x5259; // "RY"
const REPORT_MAGIC: u64 = 0xB10C;
/// v0.11: доказательство релокации — [PIE_MAGIC, SELF_PTRS[0]] сразу
/// после READY: значение патченного .data-указателя (загрузчик init).
const PIE_MAGIC: u64 = 0x1E11;

// errno-ожидания атак (Linux-конвенция ядра): -1 EPERM (capability-
// модель), -122 EDQUOT (квоты GTCB), -9 EBADF (угаданный хендл).

// ───────────────────────── Консоль ─────────────────────────

/// Порция ≤40 байт в DEBUG_WRITE (ABI ядра: 5 слов little-endian).
fn debug_bytes(bytes: &[u8]) {
    let n = bytes.len().min(40);
    unsafe { userlib::l4_debug_write_bytes(bytes.as_ptr(), n as u64) };
}

fn puts(s: &str) {
    let mut rest = s.as_bytes();
    while !rest.is_empty() {
        let n = rest.len().min(40);
        debug_bytes(&rest[..n]);
        rest = &rest[n..];
    }
    debug_bytes(b"\r\n");
}

fn put_hex(prefix: &str, v: i64) {
    let mut rest = prefix.as_bytes();
    while !rest.is_empty() {
        let n = rest.len().min(40);
        debug_bytes(&rest[..n]);
        rest = &rest[n..];
    }
    let mut buf = [0u8; 19];
    buf[0] = b'0';
    buf[1] = b'x';
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let u = v as u64;
    for i in 0..16 {
        let nib = (u >> ((15 - i) * 4)) & 0xF;
        buf[2 + i] = HEX[nib as usize];
    }
    buf[18] = 0;
    debug_bytes(&buf);
    debug_bytes(b"\r\n");
}

// ───────────────────────── Воркер потока-флуда ─────────────────────────

/// Точка входа потока-флуда: живёт и уступает CPU — ни фолтов, ни
/// помех протоколу (адрес попадает в THREAD_CREATE как entry).
#[unsafe(no_mangle)]
extern "C" fn flood_worker() -> ! {
    loop {
        let _ = userlib::l4_thread_yield();
    }
}

// ───────────────────── PIE-верификация (v0.11) ─────────────────────

/// Адреса в .data: линкер описывает их R_X86_64_RELATIVE; загрузчик
/// init патчит под выбранную базу инстанса. Значение [0] отправляется
/// родителю (PIE_PTR) и печатается — по нему видно, ГДЕ образ живёт.
/// (Обёртка: fn-item кастится в `*const ()` (advice компилятора), а
/// Sync мы объявляем сами — по адресам никто не зовёт, только читает.)
pub struct FnPtr(pub *const ());
unsafe impl Sync for FnPtr {}

pub static SELF_PTRS: [FnPtr; 3] = [
    FnPtr(flood_worker as *const ()),
    FnPtr(main as *const ()),
    FnPtr(puts as *const ()),
];

// ───────────────────────── main ─────────────────────────

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, _argv: *const *const i8) -> i32 {
    unsafe {
        puts("rogue: spawned inside sandbox; protocol handshake...");
        put_hex("rogue: argc = ", argc as i64);

        // 1. GO от родителя: [cmd, parent_tid_lo] (word0 — возврат recv).
        let _ = userlib::l4_ipc_recv_any(0);
        let cmd = userlib::l4_ipc_msg_word(0);
        let parent_tid = userlib::l4_ipc_msg_word(1);
        if cmd != CMD_GO as i64 {
            puts("rogue: bad start command, exiting");
            return 1;
        }
        put_hex("rogue: parent tid = ", parent_tid);

        // 2. Разведка cspace: TaskTCB(себя) и Gate(порт родителя).
        let n = userlib::l4_cap_list(0);
        let mut tcb_self: u64 = 0;
        let mut gate_parent: u64 = 0;
        if n > 0 {
            let mut idx = 1u64;
            for _ in 0..n {
                let handle = userlib::l4_cap_list(idx);
                let kind = userlib::l4_cap_list(idx + 1);
                if kind == 2 && tcb_self == 0 {
                    tcb_self = handle as u64;
                }
                if kind == 3 && gate_parent == 0 {
                    gate_parent = handle as u64;
                }
                idx += 2;
            }
        }
        put_hex("rogue: my TaskTCB handle = ", tcb_self as i64);
        put_hex("rogue: parent gate handle = ", gate_parent as i64);
        if tcb_self == 0 || gate_parent == 0 {
            puts("rogue: capabilities missing (spawn protocol broken?)");
            return 2;
        }

        // 3. Регистрируем exit-endpoint: родитель получит уведомление
        //    о нашей смерти через СВОЙ же порт (мы честно сдаёмся).
        let _ = userlib::l4_task_set_exit_ep(gate_parent);
        puts("rogue: exit endpoint registered on parent port");

        // 4. «Открывает порты»: свои endpoint'ы (в пределах квоты —
        //    остальное по своей воле; флуд ниже — уже атакой).
        let mut ports = 0u64;
        for _ in 0..8 {
            let h = userlib::l4_ep_create(4);
            if h > 0 {
                ports += 1;
                put_hex("rogue: opened port, handle = ", h);
            } else {
                put_hex("rogue: port flood BLOCKED by kernel, errno = ", h);
                break;
            }
        }

        // 5. READY родителю (fast-path по его tid) + PIE_PTR: значение
        //    статического указателя ПОСЛЕ релокации (v0.11) — родитель
        //    сверит его с базой, на которую нас положил. Read_volatile
        //    обязателен: без него LTO «вшивает» массив адресов в lea и
        //    релокаций в образе нет — а с ним .data обязан существовать.
        let self_ptr = unsafe { core::ptr::read_volatile(&SELF_PTRS[0]) }.0 as u64;
        let _ = userlib::l4_ipc_send_thread(parent_tid as u64, 0, CMD_READY as u64, ports, 2);
        let _ = userlib::l4_ipc_send_thread(parent_tid as u64, 0, PIE_MAGIC as u64, self_ptr, 2);
        put_hex("rogue: self .data ptr (relocated) = ", self_ptr as i64);
        puts("rogue: ready; awaiting ping-pong");

        // 6. PING x3: родитель шлёт [PING, round] — отвечаем [round, crc].
        for _ in 0..3 {
            let _ = userlib::l4_ipc_recv_any(0);
            let c = userlib::l4_ipc_msg_word(0);
            let round = userlib::l4_ipc_msg_word(1);
            if c != CMD_PING as i64 {
                if c == CMD_ATTACK as i64 {
                    break;
                }
                continue;
            }
            let crc = round.wrapping_mul(31).wrapping_add(7);
            let _ = userlib::l4_ipc_send_thread(parent_tid as u64, 0, round as u64, crc as u64, 2);
            put_hex("rogue: exchanged info round ", round);
        }

        // 7. ATTACK: ждём команду атаки.
        loop {
            let _ = userlib::l4_ipc_recv_any(0);
            let c = userlib::l4_ipc_msg_word(0);
            if c == CMD_ATTACK as i64 {
                break;
            }
            if c == CMD_PING as i64 {
                let round = userlib::l4_ipc_msg_word(1);
                let crc = round.wrapping_mul(31).wrapping_add(7);
                let _ =
                    userlib::l4_ipc_send_thread(parent_tid as u64, 0, round as u64, crc as u64, 2);
            }
        }

        let blocked = attack_suite(tcb_self, gate_parent, parent_tid as u64);

        // 8. Отчёт и «честная сдача»: exit-уведомление уйдёт на порт
        //    родителя (TASK_SET_EXIT_EP выше), затем домен умрёт.
        let _ = userlib::l4_ipc_send_thread(
            parent_tid as u64,
            0,
            REPORT_MAGIC as u64,
            blocked as u64,
            2,
        );
        puts("rogue: report sent; surrendering (TASK_EXIT 0x5A)");
        userlib::l4_task_exit(0x5A)
    }
}

// ───────────────────────── Каскад атак ─────────────────────────

/// Все попытки выхода/DoS. Возврат — счётчик ЗАБЛОКИРОВАННЫХ операций
/// (по ожиданиям ядра: квоты -122 / права -1 / битые хендлы -9).
unsafe fn attack_suite(tcb_self: u64, _gate_parent: u64, parent_tid: u64) -> u64 {
    let mut blocked = 0u64;

    // edition-2024: unsafe fn неявно unsafe — вложенный блок не нужен.
    {
        puts("rogue: === jailbreak & DoS attempts ===");

        // (a) Флуд потоков: TaskTCB(себя) есть («своя кухня»), но
        //     max_threads=4 в GTCB режет создание (главный уже есть).
        let mut stacks = [0u64; 8];
        let mut made = 0u64;
        for i in 0..8u64 {
            // Стек потока: 1 страница (в пределах page-квоты).
            let st = userlib::l4_mem_alloc(1, 0b011);
            if st <= 0 {
                put_hex("rogue: no page for stack, errno = ", st);
                blocked += 1;
                break;
            }
            let stack_top = st as u64 + 4096;
            let tid = 0x2000_1000u64 + i;
            let r = userlib::l4_thread_create(tcb_self, flood_worker as u64, stack_top, tid);
            if r == 0 {
                made += 1;
                stacks[i as usize] = st as u64;
            } else {
                put_hex("rogue: thread flood BLOCKED, errno = ", r);
                // Стек не нужен — вернуть страницу пулу.
                let _ = userlib::l4_mem_free(st as u64);
                blocked += 1;
                break;
            }
        }
        put_hex("rogue: extra threads created = ", made as i64);

        // (b) Эскалация приоритета: потолок max_prio=100 в GTCB.
        let self_tid = userlib::l4_self_info(2);
        let r = userlib::l4_thread_set_prio(self_tid as u64, 0, 255);
        put_hex("rogue: prio 255 escalation -> errno = ", r);
        if r != 0 {
            blocked += 1;
        }

        // (c) Убить родителя: TASK_KILL требует TaskTCB(родителя) —
        //     такого права у нас нет и не будет (угаданный хендл — EBADF).
        let r = userlib::l4_task_kill(0xDEAD_0000_0000_0001);
        put_hex("rogue: kill parent attempt -> errno = ", r);
        if r != 0 {
            blocked += 1;
        }

        // (d) Породить свой домен: may_spawn=0 в GTCB — «тупиковая
        //     ветвь», даже с TaskTCB(себя) в руках.
        let r = userlib::l4_task_spawn_image(tcb_self, 0x2100_0000, 0, 0x1000, 0x70);
        put_hex("rogue: spawn my own child -> errno = ", r);
        if r != 0 {
            blocked += 1;
        }

        // (e) IOMMU: вся группа 0x80 гейтована IommuAdmin — его выдают
        //     только init'у (kinit). У нас — EPERM.
        let r = userlib::l4_iommu_enum(0xFFFF_FFFF, 0);
        put_hex("rogue: iommu hijack attempt -> errno = ", r);
        if r != 0 {
            blocked += 1;
        }

        // (f) SHM: свои регионы — в пределах квоты; ЧУЖОЙ region (id 1
        //     принадлежит init) разрушить нельзя (owner-гейт).
        let mut shm_made = 0u64;
        for _ in 0..4 {
            let id = userlib::l4_shm_create(1);
            if id > 0 {
                shm_made += 1;
            } else {
                put_hex("rogue: shm flood BLOCKED, errno = ", id);
                blocked += 1;
                break;
            }
        }
        put_hex("rogue: own shm regions = ", shm_made as i64);
        let r = userlib::l4_shm_destroy(1); // чужой (init) регион
        put_hex("rogue: destroy PARENT shm -> errno = ", r);
        if r != 0 {
            blocked += 1;
        }

        // (g) Протолкнуть capability в cspace родителя: CAP_SEND
        //     требует TaskTCB(получателя) — знания TaskId мало.
        let r = userlib::l4_cap_send(_gate_parent, parent_tid, 0);
        put_hex("rogue: cap push to parent -> errno = ", r);
        if r != 0 {
            blocked += 1;
        }

        // (h) Флуд памяти: MEM_ALLOC до упора — max_pages в GTCB режет
        //     задолго до исчерпания машины (DoS-атака глохнет в квоте).
        let mut got = 0u64;
        let mut addr = 0u64;
        loop {
            let v = userlib::l4_mem_alloc(1, 0b011);
            if v <= 0 {
                put_hex("rogue: mem flood BLOCKED, errno = ", v);
                put_hex("rogue: pages drained before block = ", got as i64);
                blocked += 1;
                break;
            }
            got += 1;
            addr = v as u64;
            if got > 512 {
                break; // страховка
            }
        }
        // Вернуть одну страницу: квота refund демонстрируется живым
        // ограничением, а не статикой.
        if addr != 0 {
            let _ = userlib::l4_mem_free(addr);
        }

        // Итог: все «-122» — квоты GTCB; «-1» — capability-модель; «-9»
        // — битые хендлы. Ни одна попытка не прошла.
        put_hex("rogue: total violations BLOCKED = ", blocked as i64);
    }
    blocked
}

// Точка входа — в userlib (_start); паника — тоже там.
