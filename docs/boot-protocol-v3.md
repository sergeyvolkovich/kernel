# rust-l4: протокол загрузки v3 (boot-архив RLBA + flat-бутстрап)

Дата: 2026-10 · Статус: реализовано (замена протокола v2 целиком)

## 1. Мотивация

Протокол v2 тянул в **ядро** чужую политику: `kinit` разбирал ELF
(xmas-elf в startup), заглушка читала N отдельных файлов серверов и
дописывала в каждый блоб ARGV-хвост магией `ARGV` (протокол «внутри
модуля»), лимит серверов был вшит в BootInfo (`MAX_MODULES = 8`), а о
целостности образа не знал никто. Идея v3 — довести принцип «ядро =
механизм» до конца на загрузочном пути:

* **пейлоад = конфиг + один boot-архив** (RLBA): cpio (newc) внутри,
  плоский исполняемый файл бутстрапа в заголовке, каталог смещений и
  чексуммы — рядом;
* **ядро больше не знает ELF на boot-пути**: kinit грузит flat-exec по
  тривиальной таблице сегментов и стартует его как первую задачу
  (бутстрап); разбор ELF/cpio/spawn — политика юзерспейса;
* **целостность проверяется при использовании**: CRC32 на файл в
  каталоге; бутстрап проверяет init до спавна, init — файлы до
  использования (verify-then-use), заглушка дублирует CRC32 архива из
  boot_cfg.xml при чтении с ESP (перекрытие I/O и подсчёта).

Границы слоёв после v3:

| Слой | Знает про | Не знает |
|------|-----------|----------|
| `uefi_stub` | «прочитай 2 файла: cfg + blob» | cpio, ELF, flat — ничего |
| ядро (kinit) | RLBA-заголовок, FLAT-сегменты, «map RO архив» | cpio, ELF, имена файлов |
| `bootstrap` (userspace) | каталог RLBA, CRC32, newc-геометрия, pie+spawn | детали UEFI |
| `init` (userspace) | каталог RLBA (через crate boot_archive), pie+spawn | — |

## 2. Формат RLBA (rust-l4 boot archive)

Один файл на ESP (`boot.cpio`), загружается заглушкой как единый blob
и кладётся в BootInfo как **модуль [0]** (больше модулей у протокола
нет). Раскладка (все смещения — от начала образа, LE):

```
+0x00  RlbaHeader (64 байта)
+0x40  FLAT-образ бутстрапа (FLX, несжатый, смещение = flat_off)
+flat_end → выравнивание до 4 КиБ
        каталог: CatalogEntry[catalog_count] (по 40 байт)
        таблица строк имён/argv (ASCIIZ)
        → выравнивание до 4 КиБ
cpio_off  новый cpio-стрим (newc, несжатый), данные файлов — в нём
end       TRAILER!!! (паддинг cpio до 512)
```

Смысл гибрида: данные файлов лежат в **настоящем newc-стриме** —
стандартные утилиты читают образ со смещения (`tail -c +$((cpio_off+1))
boot.cpio | cpio -id`), а каталог даёт O(1)-доступ и чексуммы без
парсинга ASCII-заголовков cpio в ядре/бутстрапе.

### RlbaHeader (repr(C), 64 байта)

| Поле | Тип | Значение |
|------|-----|----------|
| `magic` | u32 | `b"RLBA"` (0x4142_4C52) |
| `version` | u16 | 3 |
| `flags` | u16 | 0 (зарезервировано) |
| `flat_off` | u64 | смещение FLAT-образа бутстрапа (обычно 64) |
| `flat_len` | u64 | длина FLAT-образа, байт |
| `catalog_off` | u64 | смещение массива CatalogEntry (4K-выровнено) |
| `catalog_count` | u32 | число записей (≤ 512) |
| `names_off` | u32 | смещение таблицы строк (после каталога) |
| `cpio_off` | u64 | смещение newc-стрима (4K-выровнено) |
| `archive_len` | u64 | полная длина образа, байт |
| `header_crc` | u32 | CRC32 полей заголовка до этого слова |
| `_pad` | u32 | 0 |

Инварианты (ядро проверяет их ДО какого-либо маппинга): магия/версия;
`flat_off + flat_len ≤ archive_len`; `flat_off + flat_len ≤ catalog_off
≤ names_off ≤ cpio_off ≤ archive_len`; `catalog_count ≤ 512`;
`header_crc` совпадает. Отказ — FATAL на консоль (fail-closed, как
`meltdown` без флага).

### CatalogEntry (repr(C), 40 байт)

| Поле | Тип | Значение |
|------|-----|----------|
| `name_off` | u32 | ASCIIZ-имя в таблице строк (имя cpio-файла, без `/`) |
| `name_len` | u16 | длина имени без нуля (≤ 63) |
| `flags` | u16 | bit0 `INIT` — это init-образ; прочие — 0 |
| `data_off` | u64 | смещение данных файла (внутри newc-стрима, абс.) |
| `data_len` | u64 | длина данных |
| `sum` | u32 | CRC32 данных |
| `args_off` | u32 | ASCIIZ «arg1 arg2…» в таблице строк (0 — нет argv) |
| `_pad` | u32 | 0 |

Имя `INIT`-записи по конвенции — `init`. Ровно одна запись с `INIT`
(валидирует сборщик mkarchive.py и бутстрап).

## 3. FLAT-образ бутстрапа (FLX)

Формат «ELF для бедных»: никаких phoff/entnum — плоская таблица из
≤ 4 сегментов, W^X по сегменту (требование MMAPMemoryFlags ядра).

### FlatExecHeader (repr(C), 64 байта)

| Поле | Тип | Значение |
|------|-----|----------|
| `magic` | u32 | `b"FLX1"` |
| `version` | u16 | 1 |
| `nsegs` | u16 | 1..=4 |
| `entry_off` | u32 | смещение entry от `load_base` |
| `load_base` | u32 | виртуальная база (ABI: `FLAT_BASE = 0x4000_0000`) |
| `mem_top` | u32 | полный размер образа в памяти (байт) |
| `segs_off` | u32 | смещение таблицы сегментов (обычно 64) |
| `image_crc` | u32 | CRC32 образа (поле = 0 при подсчёте) |
| `_pad` | [u32; 8] | 0 |

### FlatSeg (repr(C), 24 байта)

| Поле | Тип | Значение |
|------|-----|----------|
| `vaddr` | u32 | виртуальный адрес сегмента (4K-выровнен) |
| `file_off` | u32 | смещение в FLAT-образе |
| `filesz` | u32 | файловая часть |
| `memsz` | u32 | полная (bss-хвост — нули) |
| `flags` | u32 | 1=RO, 3=RW, 5=RX (биты MMAPMemoryFlags) |
| `_pad` | u32 | 0 |

Загрузка в kinit (механизм, ~50 строк): кадры из пула пользователя,
копирование через physmap, `map_fixed` по сегментам, стек и argv-блок —
как у v2-elfload. Точка входа = `load_base + entry_off`.

Сборка: `bootstrap.ld` линкует ELF на 0x4000_0000
(.text RX / .rodata RO / .data+.bss RW), `mkarchive.py` конвертирует
ELF→FLX (разбор program headers) и вкладывает в RLBA.

## 4. Карта адресов бутстрапа (ABI платформы)

```
0x4000_0000  FLAT_BASE      образ бутстрапа (RX/RO/RW по сегментам)
0x5000_0000  ARCHIVE_BASE   весь RLBA-образ, RO (external-маппинг)
USER_STACK_TOP              стек (как у всех задач: base − 16 МиБ)
stack_top − 1 МиБ           argv-блок (2 стр., протокол v2 без изменений)
```

Ядро мапит архив **external** (кадры — boot-память модуля, никогда не
возвращаются пулу; Modules-регионы карты памяти исключены из LLFree
пулов by construction). init после спавна получает архив **тем же
образом**: бутстрап делает `MEM_MAP_AT` своего RO-окна в пространство
init на тот же `ARCHIVE_BASE` (RO) — init читает каталог и спавнит
серверы из архива без копирования.

## 5. BootInfo v3

Жёсткий разрыв: `BOOTINFO_VERSION = 3`, заглушка v3 не понимает v2 и
наоборот. Изменения:

* `modules[0]` — **boot-архив RLBA** (блоб как есть; имя — имя файла
  из конфига, чисто для диагностики). `module_count` всегда 1;
  `MAX_MODULES` остаётся 8 как запас протокола, семантика «[0] =
  архив» фиксируется версией;
* стартовое IPC и boot_state — без изменений (argc/argv/argv_ptr/
  argv_bytes; boot_state как `k=v` в argv);
* ARGV-хвост (магия `ARGV`) **исчезает из протокола** — argv
  init-сервера теперь задаётся каталогом RLBA (`args_off` INIT-записи)
  и транзитом boot_state, собирает их бутстрап при спавне.

## 6. boot_cfg.xml v3

```xml
<bootloader timeout="0" default="rust-l4">
  <payload id="rust-l4" type="rust-l4" title="rust-l4"
           cmdline="arch=x86_64 console=com1 meltdown=allow"
           archive="boot.cpio">
    <boot_state>
      <var name="console" value="com1"/>
    </boot_state>
  </payload>
</bootloader>
```

Атрибут `archive` (вместо элемента `<servers>`) — путь к RLBA-образу
от корня тома. Легаси-схема `<boot cmdline>` удалена вместе с
`ServerSpec`. Валидация: путь непуст; ровно один `<payload>` может
ссылаться на каждый файл (ядро грузит его целиком).

## 7. Цепочка v3 (что меняется в коде)

```
OVMF → BOOTX64.EFI → boot_cfg.xml → payload.archive → blob в память
     → BootInfo v3 (module[0]=RLBA) → EBS → вход ядра
head.S/kmain — БЕЗ ИЗМЕНЕНИЙ
kinit:
  ... пулы/GCTL/KMAP как раньше ...
  module[0] → boot_archive::RlbaHeader::parse (инварианты)
  → flatload: FLX-сегменты → map_fixed → entry
  → map RO архива на ARCHIVE_BASE (external)
  → стек + argv («bootstrap», boot_state k=v)
  → задача/поток бутстрапа + стартовое IPC → run()
bootstrap (первая задача, userspace):
  S1  стартовое IPC: argc/argv (+boot_state)
  S2  каталог RLBA: CRC32 заголовка/каталога; найти INIT-запись
  S3  CRC32 данных init → pie::Plan::parse (ET_EXEC StaticFixed)
  S4  сегменты: MEM_ALLOC(RW) + копия из RO-архива; стек; argv-блок
      (argv[0]=«init», args из каталога, boot_state k=v транзитом)
  S5  MEM_MAP_AT: архив → init @ ARCHIVE_BASE (RO)
  S6  TASK_SPAWN_IMAGE(init) → TaskTCB(init)
  S7  CAP_SEND → init: TaskTCB(init), IommuAdmin, IoResource{Mmio,
      IoPort, Irq} (гранты kinit теперь выдаются бутстрапу — он
      передаёт их дальше, как seL4 root task)
  S8  ждать TASK_EXIT-уведомление init (exit-эндпоинт) — бутстрап
      живёт вечно (внешние кадры init принадлежат ему: L4 pager)
init:
  стартовое IPC → печать argv (smoke) → ... → TASK_EXIT(0)
```

## 8. Целостность

Угроза — битность (сбой диска/FAT/памяти), не атака (подписи — вне
объёма v3; поле `flags` и 96 байт запаса в заголовке — под Ed25519
в будущем).

* **заглушка**: читает blob с ESP и попутно считает CRC32 всего
  архива; сверяет с `archive_crc32="0x…"` в `<payload>`, если атрибут
  задан (перекрытие I/O и подсчёта — «параллельность» из ТЗ);
* **kinit**: CRC32 заголовка RLBA (поля до `header_crc`) + инварианты
  геометрии — до маппинга;
* **бутстрап**: CRC32 каталога и данных INIT-записи — до спавна;
* **init**: CRC32 файла — до использования (verify-then-use).

CRC32 (IEEE 802.3, полином 0xEDB88320) — 30 строк в boot_archive,
без зависимостей; при несовпадении — честный FATAL в serial.

## 9. Критерии приёмки

1. `cargo test` — новые тесты boot_archive (геометрия, CRC, каталог),
   обновлённые bootcfg/boot_info; ядро 136+ тестов зелёные;
2. `scripts/build_image.sh` — собирает ESP c `boot.cpio` (mkarchive.py);
3. `scripts/run_qemu.sh` (TCG SMP=2) — полный smoke: `[stub]` грузит
   архив, `kinit: flat bootstrap`, `bootstrap: init spawned`, init
   печатает argv и `boot chain OK`, ядро гасится `exit 0`;
4. Порча одного байта `boot.cpio` (в данных init) → FATAL бутстрапа
   на CRC32 (проверено вручную на собранном образе).

## 10. Сознательные упрощения

* init остаётся ET_EXEC на новом линк-базисе `0x6000_0000`
  (StaticFixed в pie); перевод на PIE — отдельно;
* бутстрап не умирает: внешние кадры init принадлежат ему (модель L4
  pager); передача владения (grant-семантика spawn) — вопрос v3.1;
* сжатие отсутствует (флаг не заведён); zstd при появлении — в
  юзерспейс-бутстрапе, заголовок и FLAT остаются несжатыми;
* один `<payload>` = один архив; menu/chainload не меняются.
