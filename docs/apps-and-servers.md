# rust-l4: приложения и серверы пользователя (v0.9; актуализировано до v0.13)

> Смежные документы: [../README.md](../README.md) — обзор проекта;
> [architecture.md](architecture.md) — внутренности ядра;
> [gtcb-sandbox.md](gtcb-sandbox.md) — песочница GTCB и спавн (включая PIE);
> [cpu-quotas.md](cpu-quotas.md) — CPU-квоты (точность TSC, v0.13);
> [iommu.md](iommu.md) — IOMMU обоих вендоров.

Руководство по написанию пользовательских программ для rust-l4: стартовый
протокол L4, полный syscall-интерфейс, библиотека interop `userlib`
(C-ABI: `_start` + `l4_*`), сборка и загрузка через `boot_cfg.xml`.
Референсы: `crates/user/init` (Rust-сервер) и `examples/capp.c` (C-сервер).

Оглавление:

1. [Модель пользователя и загрузочная цепочка](#1-модель-пользователя-и-загрузочная-цепочка)
2. [Стартовый протокол (L4)](#2-стартовый-протокол-l4)
3. [Syscall-интерфейс (полная таблица)](#3-syscall-интерфейс-полная-таблица)
4. [userlib: C-интероп (l4_* / _start)](#4-userlib-c-интероп-l4-__start)
5. [Сервер на C: пример capp](#5-сервер-на-c-пример-capp)
6. [Сервер на Rust: пример init](#6-сервер-на-rust-пример-init)
7. [Сборка и загрузка (build.sh / boot_cfg.xml)](#7-сборка-и-загрузка-buildsh--boot_cfgxml)
8. [IOMMU-группа: DMA- и IRQ-ремаппинг](#8-iommu-группа-dma--irq-ремаппинг)
9. [Права, ограничения и следующие шаги](#9-права-ограничения-и-следующие-шаги)
10. [Спавн доменов, песочница GTCB и CPU-квоты](#10-v09-спавн-доменов-task_spawn_image-и-песочница-gtcb)

---

## 1. Модель пользователя и загрузочная цепочка

rust-l4 — микроядро L4-архитектуры: всё вне ядра — задачи пользователя
(protection domains): cspace (capability-пространство), адресное
пространство, потоки. Ядро не предоставляет libc, файлов и драйверов —
это серверы пользователя, общающиеся IPC.

Загрузочная цепочка (UEFI):

```
OVMF -> uefi_stub (BOOTX64.EFI, ядро встроено)
     -> boot_cfg.xml (список серверов + boot_state + cmdline ядра)
     -> модули серверов читаются с ESP в память (boot_info v2)
     -> ExitBootServices -> kernel (head.S -> kmain -> startup::kinit)
     -> elfload: модуль [0] парсится, ELF-сегменты копируются в
        адресное пространство задачи, ставится стек и argv-блок
     -> создаётся поток @ ELF entry, паркуется стартовое IPC
     -> диспетчер: сервер [0] (= init) исполняется
```

Первый сервер из `<servers>` boot_cfg.xml — **init-сервер** по
договорённости протокола (модуль [0]): его запускает ядро. Остальные
серверы загружаются в память модулями — их порождает уже init (или
менеджер, который init запустит): v0.8 не содержит exec-сискола,
полная цепочка spawn-серверов — v0.9 (см. раздел 10).

Ключевые свойства среды (v0.8):

- **Статические ELF по фиксированным адресам** — для сервера [0]
  (загрузочная цепочка; юзерский линк-базис `0x40000000`, линк-скрипт
  `crates/user/init/init.ld`, entry `_start`); BSS обнуляет ядро. Для
  доменов, спавниемых через TASK_SPAWN_IMAGE, с v0.11 поддержаны
  PIE-образы (ET_DYN + R_X86_64_RELATIVE, крейт `pie`) — релокации
  накатывает родитель (раздел 10.6).
- **Без libc/рантайма**: сисколы — единственный API. Для Rust это
  `#![no_std] + #[no_main]`, для C — `gcc -ffreestanding -nostdlib`.
- **SSE разрешён** в ring3; с v0.12 FPU-контекст (fxsave/fxrstor)
  сохраняется на каждом переключении потоков (eager, без CR0.TS) —
  float в потоках безопасен (AVX не поддерживается).
- Стек: `USER_STACK_TOP` (ABI платформы), страниц `USER_STACK_PAGES`
  (см. `backend/boot.rs`); argv-блок — на 1 МиБ ниже вершины стека.

## 2. Стартовый протокол (L4)

Ядро (startup/elfload.rs) перед стартом потока паркует в его очередь
**стартовое IPC** от `IPC_KERNEL_FROM` с словами:

```
word0 = argc        — число строк argv
word1 = argv_ptr    — виртуальный адрес argv-блока в вашем пространстве
word2 = argv_bytes  — длина блока, байт
```

Приём — обычный `IPC_RECV_ANY` (open receive): сообщение уже в очереди,
вызов не блокируется. Слова 1..N — `IPC_MSG_WORD(1..=)`.

argv-блок по `argv_ptr` (конвенция совместима с C `char **`):

```
[u64 argc] [u64 ptr[argc]] ... [u64 NULL] [u64 pad] [asciiz-строки]
            ^-- argv = (char **)(argv_ptr + 8);  argv[argc] == NULL
```

Строки (в порядке): имя модуля (`name` из boot_cfg.xml — это argv[0]),
затем `<arg>` сервера из XML, затем boot_state-переменные в виде
`имя=значение`. Ядро их НЕ интерпретирует — конфигурация транзитом из
XML в приложение (политика загрузки — у init).

`_start` из userlib делает всё это за вас (раздел 4); на «голом» Rust
(как init) — принимаете сообщение и читаете блок сами.

Возврат/выход: `TASK_EXIT(код)` — домен умирает (каскад гасит потоки,
локи и IRQ-привязки; exit-endpoint'у уходит ExitPayload). Ядро печатает
`[kernel] all user threads gone — halting (boot chain OK)` и холдит
машину (демо-режим; таймаут QEMU снимает процесс).

## 3. Syscall-интерфейс (полная таблица)

ABI (x86_64): `rax` = номер; аргументы `rdi, rsi, rdx, r10, r8, r9`;
возврат `rax`. 0/положительное — успех; отрицательное — errno-подобный
код: `-ENOSYS(38)` (нет хендлера/сервиса), `-ENOMEM(12)`,
`-EEXIST(17)`, `-EINVAL(22)`, `-ENODEV(19)`, `-EOPNOTSUPP(95)` и др.
(см. `syscall/types.rs`). Номера — плотная таблица (слоты, прямая
индексация); регистрируются ядром по умолчанию (`install_default_table`).

### 0x00 — система

| № | Сискол | ABI (arg1..arg5) | Возврат |
|---|--------|------------------|---------|
| 0x03 | SELF_INFO | индекс слова | см. ниже |
| 0x04 | SYS_TIME | — | нс (TimeSource платформы) |

SELF_INFO-слова: `0` task_id.lo, `1` task_id.hi, `2` thread_id.lo,
`3` thread_id.hi, `4` cpu (текущий CPU потока), `5` cpu_count.

### 0x10 — задачи и потоки

| № | Сискол | ABI | Прим. |
|---|--------|-----|-------|
| 0x01 | TASK_SPAWN | TaskId(lo,hi), prio | легаси, БЕЗ capability-проверки |
| 0x10 | TASK_CREATE | хендл TaskTCB(себя), TaskId(lo,hi), prio | право творца |
| 0x11 | TASK_SET_EXIT_EP | хендл Gate | доставка ExitPayload |
| 0x12 | TASK_EXIT | код | не возвращается |
| 0x13 | TASK_KILL | хендл TaskTCB цели | |
| 0x14 | TASK_EXIT_EXCEPTION | fault_addr, ip, kind, ... | паника рантайма |
| 0x15 | THREAD_CREATE | хендл TaskTCB, entry, stack_top, ThreadId(lo) | entry с нулевыми регистрами |
| 0x16 | THREAD_DESTROY | ThreadId(lo,hi) | TCB завершённого |
| 0x17 | THREAD_TERMINATE | ThreadId(lo,hi) | принудительно в Dead |
| 0x18 | THREAD_SET_PRIO | id(lo,hi), prio | |
| 0x19 | THREAD_SUSPEND | id(lo,hi) | себя — тоже |
| 0x1A | THREAD_RESUME | id(lo,hi) | |
| 0x1B | THREAD_YIELD | — | L4 yield |
| 0x1C | THREAD_EX_REGS | id(lo,hi), entry(-1=keep), stack(-1=keep), what | L4 ex_regs |

### 0x20 — capability

| № | Сискол | ABI | Прим. |
|---|--------|-----|-------|
| 0x21 | CAP_MINT | src, TaskId(lo,hi), perms, badge | производная (полный диапазон IoResource) |
| 0x27 | CAP_MINT_RANGE | src, TaskId(lo,hi), perms, new_base, new_len | v0.15: производная IoResource со СУЖЕННЫМ поддиапазоном (⊆ родителя; иначе RangeNotSubset); шестой аргумент ABI |
| 0x22 | CAP_SEND | src, TaskId(lo,hi) | передача |
| 0x23 | CAP_REVOKE | src | поддерево; возврат = погашено |
| 0x24 | CAP_DELETE | src | один хендл |
| 0x25 | CAP_LIST | индекс слова | 0 = число слотов; далее 2 слова/слот: handle, kind (1 DeviceRef, 2 TaskTCB, 3 Gate, 4 Irq) |
| 0x26 | CAP_INFO | хендл, индекс слова | 0 kind, 1 perms, 2 badge, 3 alive, 4..5 идентификация |

### 0x30 — IPC

| № | Сискол | ABI | Прим. |
|---|--------|-----|-------|
| 0x31 | EP_CREATE | ёмкость (0 = строгий rendezvous) | хендл |
| 0x32 | IPC_SEND | ep, w0..w2, flags(bit0 try) | блокирующая |
| 0x33 | IPC_RECV | ep, flags(bit0 try) | слово 0 сообщения |
| 0x34 | IPC_CALL | ep, reply_ep, w0..w1, flags | L4 ipc_call |
| 0x35 | IPC_SEND_THREAD | ThreadId(lo,hi), w0..w1, слов | fast-path |
| 0x36 | IPC_RECV_ANY | flags | open receive |
| 0x37 | IPC_MSG_WORD | индекс | сквозная индексация |
| 0x38 | IPC_MSG_LEN | — | (status<<32)\|слов |
| 0x39 | IPC_MSG_CLEAR | — | |
| 0x3A | NOTIFY_SIGNAL | ep, слово | doorbell (нужна ёмкость) |

### 0x40 — сырые аппаратные ресурсы (IoResource) и IRQ (v0.14)

Устройств в ядре НЕТ: доступ к физике/портам/линиям гейтован
IoResource-capability (CAP_LIST kinds 6 = Mmio, 7 = IoPort, 8 = Irq;
CAP_INFO слова 4..5 = [base, len|count]). Перечисление ACPI/AML/PCI —
юзерспейс (acpid).

| № | Сискол | ABI | Прим. |
|---|--------|-----|-------|
| 0x02 | — | — | (свободен с v0.14: был DEVICE_INFO) |
| 0x41 | MMIO_MAP | хендл Mmio, байтовый офсет, страницы, flags(0=dev-nocache) | физика → байто-точный vaddr; кадры внешние, снятие MEM_FREE |
| 0x42 | IOP_IN | хендл IoPort, офсет, ширина(1\|2\|4) | чтение порта (исполняет ядро, IOPL=0) |
| 0x43 | IOP_OUT | хендл IoPort, офсет, ширина, значение | запись в порт |
| 0x44–0x45 | — | — | (свободны с v0.14: были DEVICE_ENUM/MAP_REGION) |
| 0x46 | IRQ_ATTACH | хендл Irq, gsi, Gate, flags(bit0 level, bit1 low) | прерывание = signal в ep (word = gsi); gsi обязан лежать в диапазоне cap |
| 0x47 | IRQ_DETACH | gsi | |
| 0x48 | IRQ_ACK | gsi | EOI-семантика L4 |

### 0x50 — память

| № | Сискол | ABI | Прим. |
|---|--------|-----|-------|
| 0x51 | MEM_ALLOC | страниц, MMAPMemoryFlags | vaddr (READ\|WRITE = 0b011) |
| 0x52 | MEM_FREE | vaddr | кадры — пулу |
| 0x53 | MEM_TRANSFER | src_vaddr, страниц, flags(bit0 grant), TaskId(lo,hi) | flexpage-перенос |
| 0x54 | MEM_INFO | vaddr, индекс | 0 vbase, 1 pbase, 2 страниц |

### 0x60 — SHM / io_uring

| № | Сискол | ABI | Прим. |
|---|--------|-----|-------|
| 0x61 | SHM_CREATE | страниц | ShmId |
| 0x62 | SHM_SETUP_RING | ShmId, sq, cq, слов/слот | sq_off |
| 0x63 | SHM_BIND_DOORBELL | ShmId, Gate | |
| 0x64 | SHM_MAP | ShmId, флаги прав | vaddr (zero-copy) |
| 0x65 | SHM_DESTROY | ShmId | |
| 0x66 | RING_DOORBELL | ShmId, слово | после submit |
| 0x67 | SHM_INFO | ShmId, индекс | геометрия/owner |

### 0x70 — отладка

| № | Сискол | ABI | Прим. |
|---|--------|-----|-------|
| 0x71 | DEBUG_WRITE | 5 слов (LE, ≤40 байт) | консоль ядра |
| 0x72 | DEBUG_DUMP_TASKS | индекс слова | |
| 0x73 | DEBUG_TRACE | 0/1 | трассировка сисколов |
| 0x74 | DEBUG_DUMP_THREADS | TaskId(lo,hi), индекс | |

### 0x80 — IOMMU / DMA-ремаппинг

| № | Сискол | ABI | Прим. |
|---|--------|-----|-------|
| 0x80 | IOMMU_ENUM | 0xFFFFFFFF → число контроллеров; иначе ctrl, word(0 флаги, 1 версия) | флаги: bit0 agaw48, bit1 queued_inval, bit2 pass_through, bit3 include_all, bit4 irq_remap, bit5 large_pages, mgaw<<8 |
| 0x81 | IOMMU_ATTACH | ctrl, bus, dev, fn | → DeviceId (идемпотентно) |
| 0x82 | IOMMU_MAP | ctrl, DeviceId, iova, phys, pages\|(prot<<32) | prot bit0 READ, bit1 WRITE; 2 МиБ-выровненные диапазоны кратных 512 стр → huge-лист |
| 0x83 | IOMMU_UNMAP | ctrl, DeviceId, iova, pages | ТОЧНОЕ совпадение с MAP (v0.8) |
| 0x84 | IOMMU_DETACH | ctrl, DeviceId | таблицы домена — в пул |
| 0x85 | IOMMU_IRQ_MAP | ctrl, DeviceId, vector(0x10..0xFE), dest(APIC ID), flags(bit0 level, bit1 logical) | → handle: индекс IRTE; его несёт MSI-адрес устройства |
| 0x86 | IOMMU_IRQ_UNMAP | ctrl, DeviceId, handle | |

## 4. userlib: C-интероп (`l4_*` / `_start`)

`crates/user/userlib` — статическая C-библиотека (staticlib, сборка под
`x86_64-unknown-none`): экспортирует точку входа `_start` и обёртки
всей syscall-таблицы с префиксом `l4_`. Заголовок: `crates/user/userlib/
include/l4.h`. Линкуется в прикладной образ без libc.

Состав:

- **`_start`** (в библиотеке): принимает стартовый IPC, разбирает
  argv-блок, вызывает прикладной `main(argc, argv)` (символ — ваша
  программа), возврат — `TASK_EXIT(код & 0xFF)`.
- **Обёртки**: по одной на сискол, имена `l4_<группа>_<операция>`
  (полный список — l4.h; совпадает с таблицей раздела 3).
- **Хелперы консоли**: `l4_debug_write_bytes`, `l4_puts` (ASCIIZ +
  CRLF порциями ≤ 40 байт), `l4_puthex(prefix, word)` —
  `prefix + 0x%016x + CRLF`.
- **Страховки**: `__stack_chk_fail` (умирает с кодом 13);
  memcpy/memset/memmove/memcmp — из compiler-builtins (бандлится
  rustc в staticlib: gcc-код с -ffreestanding линкуется чисто).

Сборка C-приложения (как в scripts/build.sh):

```bash
gcc -O2 -Wall -Wextra -ffreestanding -fno-stack-protector -fno-pie \
    -I crates/user/userlib/include -c app.c -o app.o
gcc -nostdlib -static -no-pie -Wl,-T,crates/user/init/init.ld \
    -Wl,--build-id=none -o app app.o \
    target/x86_64-unknown-none/release/libuserlib.a
```

Требования к образу (ядро грузит только такие ELF):

- статический `ET_EXEC`, LOAD-сегменты в диапазоне линк-базиса
  `0x40000000` (init.ld: .text RX / .rodata R / .data+.bss RW,
  `ENTRY(_start)`);
- без PIE/динамической секции — только в ЗАГРУЗОЧНОЙ ЦЕПОЧКЕ (elfload
  ядра грузит сервер [0]); домены спавна (раздел 10.6) с v0.11 могут
  быть static-PIE (ET_DYN; разбор и релоки — крейт `pie` у родителя);
- `-znoseparate-code` (init.ld уже
  задаёт) — компактные смежные сегменты (меньше pow2-кадров на
  сегмент в elfload::user_frames);
- никаких внезаголовочных данных после PT_LOAD (argv-хвост дописывает
  ЗАГЛУШКА при сборке ESP, не приложение).

Ограничения: без libc — пишите на «сыром» C (нет printf/malloc);
FPU между потоками не переключается; сегменты грузятся кадрами из
ПОЛЬЗОВАТЕЛЬСКОГО пула — образ megabytes-класса съест пул (QEMU:
512 МиБ, порядок LLfree ограничен 2048 страниц на сегмент).

## 5. Сервер на C: пример capp

`examples/capp.c` — полный референс C-ABI. В `build_image.sh` он не
входит (образ собирает только init): соберите вручную по рецепту
раздела 4, положите в ESP как `capp.elf` и подмените конфиг
(`scripts/boot_cfg_c.xml` — референс). Скелет:

```c
#include "l4.h"

int main(int argc, char **argv)
{
    l4_puts("hello from C");
    l4_puthex("cpu_count = ", (uint64_t)l4_self_info(5));

    /* страничка под рабочие данные */
    int64_t page = l4_mem_alloc(1, 0x3 /* READ|WRITE */);
    if (page > 0) { /* работаем */ }

    /* серверная петля: ждём IPC от клиентов */
    for (;;) {
        int64_t tag = l4_ipc_recv_any(0);
        if (tag < 0) continue;
        uint64_t w0 = (uint64_t)l4_ipc_msg_word(0);
        /* обработать w0..; ответ — l4_ipc_send_thread(...) */
    }
}
```

Идиомы сервера:

- **Конфигурация** — через argv (раздел 2): `<arg>` из boot_cfg.xml и
  boot_state `имя=значение`.
- **Ожидание клиентов** — `l4_ipc_recv_any` (open receive) или своя
  endpoint-дисциплина (`l4_ep_create` + `l4_ipc_recv`).
- **Уведомления/IRQ** — `l4_notify_signal` / `l4_irq_attach`+Gate:
  прерывание = signal-сообщение со словом gsi.
- **Несколько потоков** — `l4_thread_create` по хендлу TaskTCB(себя)
  (грант kinit; найти: `l4_cap_list`, kind = 2), стек — `l4_mem_alloc`.
- **Выход** — `return` из main (или `l4_task_exit`).

## 6. Сервер на Rust: пример init

`crates/user/init` — эталон без userlib (сырые сисколы, `#[no_main]`,
свой `_start`). Скелет:

```rust
#![no_std]
#![no_main]

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! { main_loop() }

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { unsafe { sys_exit(13) } }

// syscall6: asm!("syscall", rax = nr, rdi/rsi/rdx/r10/r8/r9, ...)
```

init демонстрирует: приём стартового IPC и argv-блока, SELF_INFO-топологию,
IOMMU-проход (раздел 8), SMP-стресс (THREAD_CREATE воркеров + yield +
гистограмма CPU), честный TASK_EXIT(0). Для новых серверов предпочтителен
userlib: он снимает бойлерплейт протокола и одинаков для C и Rust.

## 7. Сборка и загрузка (build.sh / boot_cfg.xml)

Сборка всей цепочки (ядро → init → заглушка → ESP-образ):

```bash
bash scripts/build_image.sh           # boot/esp.img (boot_cfg.xml, init)
bash scripts/build.sh                 # то же + kernel.sym/kernel.bin
```

Формат `boot_cfg.xml` (первый сервер = сервер [0], его стартует ядро;
пути — от корня ESP-раздела):

```xml
<boot cmdline="arch=x86_64 console=com1 meltdown=allow">
  <servers>
    <server name="init" path="init.elf">
      <arg>stage=boot-chain</arg>
      <arg>log=full</arg>
    </server>
    <server name="fs" path="servers/fs.elf"/>   <!-- грузится модулем -->
  </servers>
  <boot_state>
    <var name="console" value="com1"/>
  </boot_state>
</boot>
```

- `cmdline` — командная строка ЯДРА (BootInfo.cmdline): `meltdown=allow`
  обязателен под QEMU/TCG (эмулятор не сообщает RDCL_NO); на реальном
  железе без KPTI ядро обязано отказывать в загрузке — флаг не ставьте.
- `boot_state` — транзит в init через argv (`имя=значение`).
- Сборка нового сервера в чейн: положите ELF в `target/esp/`,
  добавьте `mcopy`-строку в build.sh (или расширите список копирования
  из каталога) и запись `<server>` в XML.

Запуск (OVMF+UEFI, serial->stdout, таймаут — машина холдится после
демо, EXIT=124 = норма):

```bash
QEMU_IOMMU=amd  bash scripts/run_qemu.sh   # AMD-Vi (IVRS), intremap=on
QEMU_IOMMU=1    bash scripts/run_qemu.sh   # Intel VT-d (DMAR), intremap=on
QEMU_IOMMU=0    bash scripts/run_qemu.sh   # без IOMMU
```

## 8. IOMMU-группа: DMA- и IRQ-ремаппинг

Ядро v0.8 поднимает IOMMU-подсистему само (DMAR/IVRS из ACPI, все
единицы, до release_aps). Пользовательский порядок работы с устройством
(BDF = сегмент:шина:устройство:функция; демо используют встроенный
ICH9 AHCI `00:1f.2` — есть в IVHD и под INCLUDE_PCI_ALL Intel):

```c
int64_t n   = l4_iommu_enum(0xFFFFFFFFULL, 0);   // контроллеры есть?
uint64_t fl = l4_iommu_enum(0, 0);                // bit4 irq_remap,
                                                  // bit5 large_pages
int64_t dev = l4_iommu_attach(0, 0, 0x1f, 2);     // → DeviceId

/* DMA: карта IOVA→физика (буферы устройства) */
l4_iommu_map(0, dev, iova, phys, pages | (3ULL << 32));   // RW
l4_iommu_unmap(0, dev, iova, pages);

/* крупными кусками: 2 МиБ-выровненно, кратно 512 страниц —
 * ядро положит ОДИН huge-лист (быстрее, таблицы в 512 раз меньше) */

/* IRQ: remapped-MSI устройства (v0.8) */
int64_t h = l4_iommu_irq_map(0, dev, 0x41 /*vector*/, 0 /*APIC 0*/, 0);
/* h = handle: запишите его в MSI-адрес устройства (MSI capability:
 * Address[15:0] = handle, SHV=0 — Intel; AMD — индекс per-device
 * таблицы). Данные MSI (vector) идут обычным полем Data. */
l4_iommu_irq_unmap(0, dev, h);

l4_iommu_detach(0, dev);
```

Правила v0.8:

- UNMAP — ТОЧНОЕ совпадение (iova, pages) с предыдущим MAP; частичное
  снятие — `-EINVAL` (расщепление huge — v0.10).
- IRQ_MAP без включённого IR на контроллере — `-EOPNOTSUPP`; вектор
  0x10..0xFE; handle > 0 (0 — «нет»).
- MSI-ремаппинг ПОЛНЫЙ цикл включает драйвер устройства: ядро даёт
  handle, а кладёт его в MSI-адрес и поднимает MSI уже драйвер.
  Включение IR (IRTA/SIRTP/IEC/IRE у Intel; IntCtl=10b/IRTE у AMD)
  ядро валидирует на этапе init — если контроллер IR не поддержал,
  `irq_remap`-бит ENUM не поднимется и IRQ_MAP откажет.
- Мульти-IOMMU: индекс контроллера — сквозной (сперва все Intel в
  порядке DMAR, затем все AMD в порядке IVRS); BDF должен попадать в
  coverage контроллера (scope DRHD / device-записи IVHD), иначе
  ATTACH — `-ENODEV`.

## 9. Права, ограничения и следующие шаги

Capability-модель: право на операцию над чужой задачей — хендл в
вашем cspace. kinit выдаёт init `TaskTCB(себя)` (право творца):
THREAD_CREATE/TASK_CREATE работают по нему; чужие задачи — после
CAP_SEND/CAP_MINT. IOMMU-группа (v0.9) гейтована мастер-capability
IommuAdmin: её выдает ядро доверенным задачам (kinit — init). Сырые
ресурсы (v0.14) — IoResource-capability: kinit выдаёт init ТРИ
корневых диапазона (физика/порты/линии GSI) + `rsdp=0x…` в boot_state;
перечисление устройств и производные гранты — юзерспейс (acpid,
раздел 10.7; IOMMU-пути устройств разрешаются против ACPI-таблиц
самого IOMMU, реестра в ядре нет).

Ограничения (честный список, состояние v0.14):

- порождение серверов — РЕШЕНО в v0.9 (TASK_SPAWN_IMAGE: init —
  спавн-сервер, спавнит домены из готовых образов; см. §10);
- PIE-спавн на выборных базах — РЕШЕНО в v0.11 (раздел 10.6);
- FPU-контекст между потоками — РЕШЕНО в v0.12 (eager fxsave/fxrstor);
- IOMMU: таблицы в физике < 4 GiB (physmap; QEMU-масштаб);
  доставка remapped-MSI требует драйвера устройства;
  частичный unmap (расщепление huge) — не реализован (v0.13);
- окно перерасхода квоты у IPC-пробуждений — до одного вытесненного
  отрезка (см. [cpu-quotas.md §7](cpu-quotas.md)).

Следующие шаги (roadmap v0.16+): enqueue-проверка квоты
IPC-пробуждённых (закрытие окна перерасхода); pcid — PCI-перечислитель
в юзерспейсе через CF8/CFC за IoPort-cap (суженные гранты
CAP_MINT_RANGE — прямое применение сужения поддиапазонов v0.15);
частичный unmap с расщеплением huge; device-iotlb (AWT/ATC); PASID
(крейты iommu-rs уже несут строители); исключения-фолты как IPC
(pager-протокол demand-paging).

## 10. v0.9: спавн доменов (TASK_SPAWN_IMAGE) и песочница GTCB

### 10.1 Спавн-сервер в юзерспейсе: образ готовит РОДИТЕЛЬ

Ядро НЕ копирует образы и не разбирает ELF в рантайме: сискол
спавна ожидает УЖЕ залинкованный по фиксированным адресам образ,
ПОЛНОСТЬЮ подготовленный родителем (spawn-сервером, init).
Родитель обязан к моменту вызова: (1) разобрать ELF64 (PT_LOAD,
e_entry), (2) выделить себе регионы MEM_ALLOC по сегментам + стек +
argv + дескриптор, (3) скопировать байты сегментов (BSS-хвост —
нулём: кадры из пула несут мусор), (4) собрать дескриптор в СВОЕЙ
памяти. Ядро принимает ТОЛЬКО УКАЗАТЕЛИ и мапит готовые кадры в
новое пространство (external-отображения; собственник — родитель
до MEM_FREE — L4 pager-модель).

TASK_SPAWN_IMAGE (0x1F). ABI:
`l4_task_spawn_image(tcb_self, id_lo, id_hi, desc_ptr, desc_bytes)`
→ хендл TaskTCB(ребёнка). ПРАВА: TaskTCB на себя + may_spawn.

Дескриптор (память родителя, LE, выравнивание 8):
```
+0x00 u64 entry        линк-точка входа ребёнка
+0x08 u64 stack_top     вершина стека (RSP первого контекста)
+0x10 u64 thread_id_lo  ThreadId главного потока
+0x18 u64 thread_id_hi
+0x20 u32 n_segments    1..=16 (образ + стек)
+0x24 u32 argv_pages    0 = без argv
+0x28 u64 argv_src      argv-блок у РОДИТЕЛЯ
+0x30 u64 argv_dst      адрес блока у РЕБЁНКА
+0x38 u64 argv_bytes    длина блока
+0x40 u64 argc          argc стартового IPC
+0x48 u64 limits[0]     max_pages
+0x50 u64 limits[1]     max_threads | max_endpoints << 32
+0x58 u64 limits[2]     max_shm | max_caps << 32
+0x60 u64 limits[3]     max_prio | (may_spawn ? 0x100 : 0)
+0x68 u8  priority      приоритет домена/потока
+0x70 сегменты (32 байта): u64 src(родитель), u64 dst(ребёнок,
     4K-выровнен), u64 pages, u64 flags (MMAPMemoryFlags: RO=1, W=2,
     X=4 — W^X обязателен)
```
Размер дескриптора = 0x70 + 32*n (передаётся в desc_bytes; ядро
сверяет с n_segments). Порядок в ядре: домен → пространство
(фабрика) → ЛИМИТЫ (до первого потока!) → грант TaskTCB(ребёнка)
родителю → сегменты (зарядка квоты ребёнка + map_fixed) → argv →
главный поток → стартовое IPC [argc, argv_dst, argv_bytes] в очередь
потока (как kinit для init). Отказ любого шага — полный откат
домена.

Референс спавн-сервера — crates/user/init/src/main.rs (S4): парсер ELF64
(~60 строк, без библиотек), стейджинг, дескриптор, вызов.

Низкоуровневый путь (если нужен полный контроль): TASK_CREATE
(домен + пространство + грант родителю) → MEM_MAP_AT (0x55, право
TaskTCB на цель: map_fixed своих кадров по линк-адресам ребёнка) →
THREAD_CREATE → IPC_SEND_THREAD (стартовое IPC) → TASK_SET_LIMITS.

### 10.2 Песочница: атрибуты в GTCB

`TaskLimits` живёт в TCB задачи; назначает держатель TaskTCB-права
на цель (родитель — ребёнку). СЕМАНТИКА ТРЕЩОТКИ: значения можно
только УЖЕСТОЧАТЬ (числовые поля — min, may_spawn — только гасится);
задача с TaskTCB на СЕБЯ расширить свою песочницу не может.

| Поле           | Что режет (errno)                                   |
|----------------|-----------------------------------------------------|
| max_pages      | MEM_ALLOC/MEM_TRANSFER/MEM_MAP_AT/SHM_CREATE (-122) |
| max_threads    | THREAD_CREATE (главный поток считается) (-122)      |
| max_endpoints  | EP_CREATE: число живых Gate-capability (-122)        |
| max_shm        | SHM_CREATE (-122)                                    |
| max_caps       | CAP_MINT/CAP_SEND/EP_CREATE в cspace (-122)           |
| max_prio       | THREAD_SET_PRIO/TASK-приоритет цели (-122)           |
| may_spawn      | TASK_CREATE/TASK_SPAWN_IMAGE (-1 EPERM)               |
| cpu_quota      | CPU: троттлинг домена планировщиком (v0.10)           |

Дополнительно к лимитам, песочница — это ОТСУТСТВИЕ capability:
ребёнок не получает IommuAdmin (гейт всей группы 0x80), TaskTCB на
другие домены, DeviceReference. Права появляются только передачей
от родителя (CAP_MINT — копия, CAP_MINT_RANGE — копия со суженным
поддиапазоном IoResource, CAP_SEND — переезд хендла!).

Каждая блокировка печатается ядром: «[kernel: sandbox] …» — аудит
атаки виден в консоли вживую. TASK_LIMITS_INFO (0x1E) — чтение
пределов/usage по праву TaskTCB (аудит родителем).

### 10.3 Смерть домена (контракт v0.9)

TASK_EXIT/kill/fault → Glue::reap: revoke_all cspace домена →
SHM-регионы (кадры в пул) → TCB destroy → destroy_space (фасад под
владением менеджера; owned-кадры возвращаются пулу, external-окна
родителя остаются). Уведомление родителя — exit-endpoint:
TASK_SET_EXIT_EP(gate) регистрирует endpoint ДОБРОВОЛЬНО; ядро
доставляет ExitPayload [tag, task_id, ...]: tag 1 = Exit
(w3 = код, w4 = cpu_used, w5 = cpu_throttle_events — v0.10:
CPU-вердикт песочницы без гонок с reaper'ом), 2 = Exception
(фолт), 3 = Killed (кем).

### 10.4 Демо-сценарий «rogue» (crates/user/rogue)

Полный сценарий из требований: init создаёт дочернюю задачу из
юзерспейса (ELF вшит байтами в исходник), открывает порты и
обменивается информацией; ребёнок ПЫТАЕТСЯ ВЫРВАТЬСЯ и совершает
DoS-атаку (флуд памятью/потоками/эндпоинтами/SHM, эскалация
приоритета, kill родителя, спавн потомков, захват IOMMU,
разрушение SHM родителя, проталкивание капов) — всё гасится
атрибутами GTCB и capability-моделью; после отчёта (9 блокировок)
rogue честно сдаётся (TASK_EXIT 0x5A), init получает
exit-уведомление, возвращает стейджинг пулу и выносит вердикт
«sandbox HELD». Сборка: build.sh (rogue → ROGUE_ELF → init; с v0.11
rogue линкуется static-PIE — rust-lld `--pie` + relocation-model=pic,
контроль `readelf -h`: ET_DYN обязателен; легаси-режим отладки
загрузчика — `ROGUE_PIE=`); прогоны — scripts/run_qemu.sh (без
IOMMU / Intel / AMD — все три зелёные, см. logs/v0.9/).

Rust-приложение-«гость» линкует userlib (rlib): тот же `_start`,
l4_* и стартовый протокол, что у C-серверов (см. §5).

### 10.5 CPU-квоты: троттлинг доменов (v0.10)

`cpu_quota` — предел тиков планировщика за период (rlimit-стиль,
usize::MAX = без лимита). Период — глобальная политика бекенда
x86_64: 100 тиков всех CPU (~1 c при SCHED_HZ=100). Заряд — на
КАЖДОМ конце отрезка исполнения потока: вытеснение (квант/yield/
IPI) и блокировка (IPC/claim); минимум 1 тик за проход (анти-спин:
yield-цикл не дешевле честного кванта) плюс фактически потреблённые
тики отрезка. Домен за пределом квоты уходит в троттлинг: его потоки
паркуются планировщиком до границы периода, затем бюджет
возобновляется. Учёт и вердикт — TASK_LIMITS_INFO: слово 6 =
cpu_quota, 7 = cpu_used (текущий период), 8 = cpu_throttle_events |
(throttled ? 1<<32 : 0).

ABI:
* TASK_SET_LIMITS: arg5[63:16] = квота; 0 — «не трогать» (наследие
  v0.9), все единицы — «без лимита», 1.. — квота (1 ≈ замороз);
* дескриптор TASK_SPAWN_IMAGE: u32 @ 0x6C — квота ребёнка
  (0/0xFFFFFFFF = без лимита; применяется ДО первого потока).

Гранулярность (документированное окно): пробуждённый IPC-поток
домена за пределом квоты отрабатывает до одного вытеснения —
перерасход ограничен (живые_потоки x квант на границу);
синхронный спиннер парковался бы немедленно при каждом вытеснении.

Точность v0.13 (подробнее — [cpu-quotas.md](cpu-quotas.md)): учёт
ведётся в циклах TSC (отрезок = rdtsc на парковке минус rdtsc на
диспетчеризации — субтик, включая ядровые участки); анти-спин-пол —
max(циклов на тик, 1024); граница периода — глобальный TSC-атомик
PERIOD_END, закрытие одним CAS-победителем (refill + дренаж
троттл-листа + resched-IPI); вытеснение — one-shot LAPIC
TSC-deadline на min(квант, остаток бюджета домена, остаток
периода): домен перебирает квоту В МОМЕНТ исчерпания, а не «до
ближайшего тика». QEMU/TCG не эмулирует tsc-deadline — там живёт
периодический фолбэк (заряд циклами и TSC-граница работают в обоих
режимах); дедлайн-путь — KVM/железо. Публичная семантика не
изменилась: квота — тики за период, cpu_used — floor-производное.

### 10.6 PIE-спавн (v0.11)

Дочерние образы могут быть позиционно-независимыми (static-PIE):
линк даёт ET_DYN с релокациями R_X86_64_RELATIVE в .rela.dyn
(символьные релоки не поддерживаются — парсер отказывает,
fail-closed). Загрузчик — крейт `pie` в юзерспейсе родителя:
разбор PT_LOAD (план W^X-сегментов), apply_rela(base) — накат
релокаций под выбранную базу с контрольным readback, затем обычный
дескриптор TASK_SPAWN_IMAGE с сегментами по адресам base+X.

init (S4) спавнит ОДИН образ на ДВУХ базах (0x40000000 и
0x50000000) и сверяет возвращённый ребёнком статический указатель
(PIE_PTR) — накат релокаций проверяется на живом домене; разные
базы = изоляция доменов на уровне адресного пространства.
Полный разбор контракта — [gtcb-sandbox.md §6](gtcb-sandbox.md).

### 10.7 acpid — ACPI-менеджер в юзерспейсе (v0.14)

Самая тяжёлая и рискованная часть ACPI — AML-интерпретатор (крейт
`acpi`) — с v0.14 живёт НЕ в ядре, а здесь: паника AML убивает
acpid, а не ядро. Роль — модель seL4 root-task для железа: init
спавнит образ (static-PIE) с argv ["acpid", "rsdp=0x…"] и копиями
ТРЁХ корневых IoResource-грантов (CAP_MINT: физика 0..4 GiB, порты
0..64 KiB, линии 0..256). Начиная с v0.15 Irq-грант acpid —
СУЖЕННЫЙ (CAP_MINT_RANGE 0..256 → 9..10: менеджеру нужна только
SCI-линия кнопки питания) — живая демонстрация минимальных
привилегий; полный контур: CAP_MINT_RANGE → IRQ_ATTACH(SCI 9) →
PWRBTN_EN → S5.

Поток работы (демо S6):

1. **Таблицы**: `acpi::Handler::map_physical_region` = MMIO_MAP за
   Mmio-cap (байто-точные адреса; refcount-кэш живых мапингов —
   acpi-крейт держит перекрывающиеся снапшоты одной физики: заголовок
   таблицы + полная таблица). Op-regions: SystemMemory — MMIO-страницы,
   SystemIO — IOP_IN/OUT, PCIConfig — CF8/CFC за IoPort-cap.
2. **Перечисление**: namespace-walk (53 узла q35) с исполнением
   AML-методов _HID/_CID/_UID/_ADR/_STA/_CRS — 11 устройств;
   `\_S5_` → SLP_TYPa; FADT → PM1a_EVT/PM1a_CNT, SCI (GSI 9).
3. **События**: EP_CREATE + IRQ_ATTACH(SCI за Irq-cap) + PWRBTN_EN —
   нажатие кнопки питания прибывает L4-сигналом.
4. **Выключение ПК**: IOP_OUT в PM1a_CNT значения SLP_TYPa<<10 |
   SLP_EN — VM завершается из юзерспейса (QEMU exit 0). Демо не
   «нажимает» кнопку: после окна ожидания — fallback self-S5.

Куча acpid — ленивый bump по регионам 1 МиБ (order 8 — большие
непрерывные физические пробеги после бут-фрагментации не гарантированы),
потолок 8 МиБ в пределах квоты спавна.
