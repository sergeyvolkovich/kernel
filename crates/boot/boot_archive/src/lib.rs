// ==== BOOT_ARCHIVE: формат RLBA (протокол загрузки v3) ====
//
// Единая библиотека формата boot-архива для ВСЕХ сторон протокола:
//
//   * uefi_stub  — только CRC32 (инкрементальный подсчёт при чтении
//     blob с ESP; сверка с атрибутом archive_crc32 конфига);
//   * startup    — ядро: разбор RlbaHeader + FLAT-заголовка (rigid
//     инварианты геометрии) и ВЫЧИСЛЕНИЕ смещений для маппинга;
//     ни cpio, ни имена файлов ядро не читает;
//   * bootstrap/init (userspace) — каталог + строки + чексуммы:
//     доступ к файлам образа по имени, verify-then-use.
//
// Дисциплина формата (см. docs/boot-protocol-v3.md):
//   * все структуры repr(C), little-endian, поля НЕ двигаются;
//   * версии: RLBA=3, FLAT=1; любое изменение раскладки — bump;
//   * образ НЕ сжат: данные лежат в честном newc-стриме, каталог
//     RLBA — параллельная структура быстрых смещений поверх него;
//   * целостность: CRC32 (IEEE 802.3) на заголовок/каталог/файлы.
#![cfg_attr(not(test), no_std)]

use core::mem::size_of;

// ───────────────────────────── Константы протокола ─────────────────────────────

/// Магия архива: "RLBA" (rust-l4 boot archive).
pub const RLBA_MAGIC: u32 = u32::from_le_bytes(*b"RLBA");
/// Версия формата архива (привязана к версии протокола загрузки).
pub const RLBA_VERSION: u16 = 3;
/// Магия FLAT-образа: "FLX1".
pub const FLAT_MAGIC: u32 = u32::from_le_bytes(*b"FLX1");
/// Версия FLAT-формата.
pub const FLAT_VERSION: u16 = 1;
/// Максимум записей каталога (образы демо — единицы; запас на будущее).
pub const MAX_CATALOG: usize = 512;
/// Максимум сегментов FLAT (text/rodata/data/bss хватает с запасом).
pub const MAX_FLAT_SEGS: usize = 4;
/// Виртуальная база загрузки бутстрапа (ABI платформы x86_64).
pub const FLAT_BASE: u64 = 0x4000_0000;
/// Виртуальный адрес, куда ядро мапит весь архив (RO) в пространство
/// первой задачи и куда бутстрап повторно мапит его для init.
pub const ARCHIVE_BASE: u64 = 0x5000_0000;
/// Линк-база init-сервера v3 (ET_EXEC, StaticFixed в pie).
pub const INIT_BASE: u64 = 0x6000_0000;
/// Флаг записи каталога: образ init-сервера (ровно один в архиве).
pub const CATALOG_FLAG_INIT: u16 = 0x0001;
/// Имя init-записи по конвенции протокола.
pub const INIT_NAME: &str = "init";

// ───────────────────────────── Структуры ─────────────────────────────

/// Заголовок RLBA-архива (64 байта, смещение 0 образа).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct RlbaHeader {
    /// Всегда [`RLBA_MAGIC`].
    pub magic: u32,
    /// Всегда [`RLBA_VERSION`].
    pub version: u16,
    /// Зарезервировано (bit0..15); читателю игнорировать.
    pub flags: u16,
    /// Смещение FLAT-образа бутстрапа (обычно 64).
    pub flat_off: u64,
    /// Длина FLAT-образа, байт.
    pub flat_len: u64,
    /// Смещение массива [`CatalogEntry`] (4K-выровнено).
    pub catalog_off: u64,
    /// Число записей каталога (≤ [`MAX_CATALOG`]).
    pub catalog_count: u32,
    /// Смещение таблицы строк (ASCIIZ; после каталога).
    pub names_off: u32,
    /// Смещение newc-стрима (4K-выровнено).
    pub cpio_off: u64,
    /// Полная длина образа, байт.
    pub archive_len: u64,
    /// CRC32 полей заголовка ДО этого слова (магия..archive_len).
    pub header_crc: u32,
    /// Выравнивание до 64 байт; 0.
    pub _pad: u32,
}

impl RlbaHeader {
    /// Смещение поля `header_crc` (байты до него покрывает CRC).
    pub const CRC_SPAN: usize = 56;

    /// Нулевой заголовок (заполняет сборщик mkarchive.py).
    pub const EMPTY: RlbaHeader = RlbaHeader {
        magic: RLBA_MAGIC,
        version: RLBA_VERSION,
        flags: 0,
        flat_off: 0,
        flat_len: 0,
        catalog_off: 0,
        catalog_count: 0,
        names_off: 0,
        cpio_off: 0,
        archive_len: 0,
        header_crc: 0,
        _pad: 0,
    };

    /// CRC32 заголовка «как если бы header_crc был нулём».
    pub fn computed_crc(&self) -> u32 {
        let bytes = self as *const _ as *const u8;
        let mut crc = Crc32::new();
        // SAFETY: repr(C) POD-структура; читаем собственные байты.
        unsafe { crc.update(core::slice::from_raw_parts(bytes, Self::CRC_SPAN)) };
        crc.value()
    }
}

/// Запись каталога: файл образа (40 байт).
///
/// `data_off` указывает ВНУТРИ newc-стрима (на данные файла), поэтому
/// стандартные утилиты cpio по-прежнему видят корректный архив
/// (срез с `cpio_off`), а каталог даёт O(1)-доступ без парсинга
/// ASCII-заголовков.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct CatalogEntry {
    /// АБСОЛЮТНОЕ смещение ASCIIZ-имени (в области таблицы строк
    /// [names_off..cpio_off); абсолютное — читателю не нужен базовый
    /// адрес: смещение подставляется в blob напрямую).
    pub name_off: u32,
    /// Длина имени без завершающего нуля.
    pub name_len: u16,
    /// Флаги: bit0 — [`CATALOG_FLAG_INIT`].
    pub flags: u16,
    /// Смещение данных файла (абсолютное, внутри newc-стрима).
    pub data_off: u64,
    /// Длина данных, байт.
    pub data_len: u64,
    /// CRC32 данных файла.
    pub sum: u32,
    /// АБСОЛЮТНОЕ смещение ASCIIZ-строки «arg1 arg2…» (0 — нет argv).
    pub args_off: u32,
    /// Зарезервировано; 0.
    pub _pad: u32,
}

impl CatalogEntry {
    /// Нулевая запись (заполняет сборщик).
    pub const EMPTY: CatalogEntry = CatalogEntry {
        name_off: 0,
        name_len: 0,
        flags: 0,
        data_off: 0,
        data_len: 0,
        sum: 0,
        args_off: 0,
        _pad: 0,
    };

    /// Это образ init-сервера?
    pub fn is_init(&self) -> bool {
        self.flags & CATALOG_FLAG_INIT != 0
    }
}

/// Заголовок FLAT-образа бутстрапа (64 байта, смещение `flat_off`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct FlatExecHeader {
    /// Всегда [`FLAT_MAGIC`].
    pub magic: u32,
    /// Всегда [`FLAT_VERSION`].
    pub version: u16,
    /// Число сегментов (1..=[`MAX_FLAT_SEGS`]).
    pub nsegs: u16,
    /// Смещение точки входа от `load_base`.
    pub entry_off: u32,
    /// Виртуальная база загрузки (ABI: [`FLAT_BASE`]).
    pub load_base: u32,
    /// Полный размер образа в памяти (байт, от load_base).
    pub mem_top: u32,
    /// Смещение таблицы сегментов (обычно 64).
    pub segs_off: u32,
    /// CRC32 образа (поле = 0 при подсчёте; покрывает [0..flat_len)).
    pub image_crc: u32,
    /// Зарезервировано; 0 (паддинг заголовка до 64 байт).
    pub _pad: [u32; 9],
}

/// Сегмент FLAT-образа (24 байта).
///
/// Флаги — биты MMAPMemoryFlags: 1 = RO, 3 = RW, 5 = RX; W^X
/// дисциплина ядра обязательна (W+X-сегмент — ошибка разбора).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct FlatSeg {
    /// Виртуальный адрес сегмента (4K-выровнен, ≥ load_base).
    pub vaddr: u32,
    /// Смещение файловой части в FLAT-образе.
    pub file_off: u32,
    /// Размер файловой части, байт.
    pub filesz: u32,
    /// Полный размер (мем-образ); [filesz..memsz) — нули.
    pub memsz: u32,
    /// Права: 1=RO, 3=RW, 5=RX.
    pub flags: u32,
    /// Зарезервировано; 0.
    pub _pad: u32,
}

/// Права сегмента FLAT → константы флагов ядра/спавна.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegFlags {
    Ro,
    Rw,
    Rx,
}

impl SegFlags {
    /// Биты протокола (MMAPMemoryFlags-совместимые).
    pub fn bits(self) -> u64 {
        match self {
            Self::Ro => 0b001,
            Self::Rw => 0b011,
            Self::Rx => 0b101,
        }
    }

    /// Разбор битов протокола (W^X: RWX/WX/… — отказ).
    pub fn from_bits(v: u32) -> Option<Self> {
        match v {
            0b001 => Some(Self::Ro),
            0b011 => Some(Self::Rw),
            0b101 => Some(Self::Rx),
            _ => None,
        }
    }
}

// ───────────────────────────── Ошибки ─────────────────────────────

/// Отказ разбора: причина (одно слово для консоли FATAL).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveError {
    BadMagic,
    BadVersion,
    BadGeometry,
    BadCrc,
    TooManyEntries,
    TooManySegments,
    NoInitEntry,
    NameOutOfBounds,
    ArgsOutOfBounds,
    SegNotAligned,
    SegFlagsInvalid,
    SegOverlap,
}

impl ArchiveError {
    /// Короткий текст для консоли (без fmt-аллокаций — append вручную).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BadMagic => "bad magic",
            Self::BadVersion => "bad version",
            Self::BadGeometry => "bad geometry",
            Self::BadCrc => "crc mismatch",
            Self::TooManyEntries => "catalog overflow",
            Self::TooManySegments => "segment overflow",
            Self::NoInitEntry => "no init entry",
            Self::NameOutOfBounds => "name out of bounds",
            Self::ArgsOutOfBounds => "args out of bounds",
            Self::SegNotAligned => "segment not aligned",
            Self::SegFlagsInvalid => "segment flags invalid",
            Self::SegOverlap => "segments overlap",
        }
    }
}

// ───────────────────────────── CRC32 ─────────────────────────────

/// CRC32 (IEEE 802.3, полином 0xEDB88320, init/xorout 0xFFFF_FFFF).
///
/// Полный табличный вариант тянет 1 КиБ таблицы в образ; бутстрап
/// и заглушка считают каждый образ ОДИН раз (сотни КБ), ядро — 64
/// байта заголовка: битовый алгоритм без таблицы (8 сдвигов на байт,
/// ~16 тактов/байт) быстрее любой disk-I/O-задержки и не раздувает
/// .rodata образов.
#[derive(Debug, Clone, Copy)]
pub struct Crc32 {
    state: u32,
}

impl Crc32 {
    /// Новый накопитель (init 0xFFFF_FFFF).
    pub const fn new() -> Self {
        Self { state: 0xFFFF_FFFF }
    }

    /// Скармливать байты.
    pub fn update(&mut self, bytes: &[u8]) {
        let mut crc = self.state;
        for &b in bytes {
            crc ^= b as u32;
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
        self.state = crc;
    }

    /// Итоговое значение (xorout).
    pub const fn value(self) -> u32 {
        self.state ^ 0xFFFF_FFFF
    }

    /// Одним вызовом.
    pub fn of(bytes: &[u8]) -> u32 {
        let mut c = Self::new();
        c.update(bytes);
        c.value()
    }
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

// ───────────────────────────── Чтение LE-слов ─────────────────────────────

/// u32 из буфера по смещению (без паник: выход за границы — None).
pub fn read_u32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// u16 из буфера по смещению.
pub fn read_u16(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

/// u64 из буфера по смещению.
pub fn read_u64(b: &[u8], off: usize) -> Option<u64> {
    let lo = read_u32(b, off)? as u64;
    let hi = read_u32(b, off + 4)? as u64;
    Some(hi << 32 | lo)
}

/// Прочитать структуру «по смещению» (все поля — LE-словами; та же
/// раскладка, что у `repr(C)` на LE-машине, но без unsafe-каста).
fn rlba_at(b: &[u8], off: usize) -> Option<RlbaHeader> {
    Some(RlbaHeader {
        magic: read_u32(b, off)?,
        version: read_u16(b, off + 4)?,
        flags: read_u16(b, off + 6)?,
        flat_off: read_u64(b, off + 8)?,
        flat_len: read_u64(b, off + 16)?,
        catalog_off: read_u64(b, off + 24)?,
        catalog_count: read_u32(b, off + 32)?,
        names_off: read_u32(b, off + 36)?,
        cpio_off: read_u64(b, off + 40)?,
        archive_len: read_u64(b, off + 48)?,
        header_crc: read_u32(b, off + 56)?,
        _pad: read_u32(b, off + 60)?,
    })
}

fn flat_hdr_at(b: &[u8], off: usize) -> Option<FlatExecHeader> {
    Some(FlatExecHeader {
        magic: read_u32(b, off)?,
        version: read_u16(b, off + 4)?,
        nsegs: read_u16(b, off + 6)?,
        entry_off: read_u32(b, off + 8)?,
        load_base: read_u32(b, off + 12)?,
        mem_top: read_u32(b, off + 16)?,
        segs_off: read_u32(b, off + 20)?,
        image_crc: read_u32(b, off + 24)?,
        _pad: [0; 9],
    })
}

fn flat_seg_at(b: &[u8], off: usize) -> Option<FlatSeg> {
    Some(FlatSeg {
        vaddr: read_u32(b, off)?,
        file_off: read_u32(b, off + 4)?,
        filesz: read_u32(b, off + 8)?,
        memsz: read_u32(b, off + 12)?,
        flags: read_u32(b, off + 16)?,
        _pad: read_u32(b, off + 20)?,
    })
}

fn catalog_entry_at(b: &[u8], off: usize) -> Option<CatalogEntry> {
    Some(CatalogEntry {
        name_off: read_u32(b, off)?,
        name_len: read_u16(b, off + 4)?,
        flags: read_u16(b, off + 6)?,
        data_off: read_u64(b, off + 8)?,
        data_len: read_u64(b, off + 16)?,
        sum: read_u32(b, off + 24)?,
        args_off: read_u32(b, off + 28)?,
        _pad: read_u32(b, off + 32)?,
    })
}

// ───────────────────────────── Разбор архива ─────────────────────────────

/// Разобранный (НЕПРОВЕРЕННЫЙ по CRC) заголовок + геометрия.
///
/// Проверяются только rigid-инварианты (магия, версия, вложенность
/// окон, выравнивание). CRC32 заголовка проверяется отдельным шагом —
/// ядро делает это ДО маппинга, юзерспейс может пере-проверить.
pub fn parse_header(blob: &[u8]) -> Result<RlbaHeader, ArchiveError> {
    let h = rlba_at(blob, 0).ok_or(ArchiveError::BadGeometry)?;
    if h.magic != RLBA_MAGIC {
        return Err(ArchiveError::BadMagic);
    }
    if h.version != RLBA_VERSION {
        return Err(ArchiveError::BadVersion);
    }
    // Окна образа строго вложены и не выходят за blob.
    let flat_end = h
        .flat_off
        .checked_add(h.flat_len)
        .ok_or(ArchiveError::BadGeometry)?;
    let catalog_end = h
        .catalog_off
        .checked_add((h.catalog_count as u64) * size_of::<CatalogEntry>() as u64)
        .ok_or(ArchiveError::BadGeometry)?;
    if h.flat_off < size_of::<RlbaHeader>() as u64
        || flat_end > h.catalog_off
        || catalog_end > h.names_off as u64
        || h.names_off as u64 > h.cpio_off
        || h.cpio_off > h.archive_len
        || h.archive_len > blob.len() as u64
    {
        return Err(ArchiveError::BadGeometry);
    }
    if h.catalog_count as usize > MAX_CATALOG {
        return Err(ArchiveError::TooManyEntries);
    }
    // 4K-выравнивание окон, которые ядро мапит страницами.
    const PAGE: u64 = 4096;
    if h.catalog_off % PAGE != 0 || h.cpio_off % PAGE != 0 {
        return Err(ArchiveError::BadGeometry);
    }
    Ok(h)
}

/// Проверить CRC32 заголовка (после [`parse_header`]).
pub fn verify_header_crc(blob: &[u8], h: &RlbaHeader) -> Result<(), ArchiveError> {
    let mut crc = Crc32::new();
    crc.update(&blob[..RlbaHeader::CRC_SPAN]);
    if crc.value() == h.header_crc {
        Ok(())
    } else {
        Err(ArchiveError::BadCrc)
    }
}

/// Разбор FLAT-образа: заголовок + таблица сегментов (сегменты
/// отсортированы по vaddr, не перекрываются, W^X, 4K-выравнивание).
///
/// Возвращает entry (виртуальный адрес точки входа), число сегментов
/// и сегменты в порядке возрастания vaddr — ядро мапит их как есть.
pub fn parse_flat(
    blob: &[u8],
    h: &RlbaHeader,
) -> Result<(u64, usize, [FlatSeg; MAX_FLAT_SEGS]), ArchiveError> {
    let flat = blob
        .get(h.flat_off as usize..(h.flat_off + h.flat_len) as usize)
        .ok_or(ArchiveError::BadGeometry)?;
    let f = flat_hdr_at(flat, 0).ok_or(ArchiveError::BadGeometry)?;
    if f.magic != FLAT_MAGIC {
        return Err(ArchiveError::BadMagic);
    }
    if f.version != FLAT_VERSION {
        return Err(ArchiveError::BadVersion);
    }
    if f.nsegs == 0 || f.nsegs as usize > MAX_FLAT_SEGS {
        return Err(ArchiveError::TooManySegments);
    }
    if f.load_base != FLAT_BASE as u32 {
        return Err(ArchiveError::BadGeometry);
    }
    let mut segs = [FlatSeg {
        vaddr: 0,
        file_off: 0,
        filesz: 0,
        memsz: 0,
        flags: 0,
        _pad: 0,
    }; MAX_FLAT_SEGS];
    let mut prev_end: u64 = 0;
    for i in 0..f.nsegs as usize {
        let s = flat_seg_at(flat, f.segs_off as usize + i * size_of::<FlatSeg>())
            .ok_or(ArchiveError::BadGeometry)?;
        // Геометрия сегмента: 4K-выравнивание vaddr, вложенность файла,
        // права из разрешённого набора (W^X).
        if (s.vaddr as u64) < f.load_base as u64
            || s.vaddr % 4096 != 0
            || s.memsz == 0
            || s.filesz > s.memsz
            || s.file_off as u64 + s.filesz as u64 > h.flat_len
            || s.vaddr as u64 + s.memsz as u64 > f.load_base as u64 + f.mem_top as u64
        {
            return Err(ArchiveError::BadGeometry);
        }
        if SegFlags::from_bits(s.flags).is_none() {
            return Err(ArchiveError::SegFlagsInvalid);
        }
        // Отсортированность/неперекрытие (после выравнивания вниз).
        let start = s.vaddr as u64;
        let end = (s.vaddr as u64 + s.memsz as u64 + 4095) & !4095;
        if start < prev_end {
            return Err(ArchiveError::SegOverlap);
        }
        prev_end = end;
        segs[i] = s;
    }
    // Точка входа — внутри образа и в исполняемом смысле (внутри
    // какого-то сегмента; RX-проверку делает загрузчик по флагам).
    let entry = f.load_base as u64 + f.entry_off as u64;
    if f.entry_off as u64 >= f.mem_top as u64 {
        return Err(ArchiveError::BadGeometry);
    }
    Ok((entry, f.nsegs as usize, segs))
}

// ───────────────────────────── Каталог (userspace) ─────────────────────────────

/// Запись каталога по индексу (границы — по заголовку).
pub fn catalog_entry(
    blob: &[u8],
    h: &RlbaHeader,
    index: usize,
) -> Result<CatalogEntry, ArchiveError> {
    if index >= h.catalog_count as usize {
        return Err(ArchiveError::TooManyEntries);
    }
    catalog_entry_at(
        blob,
        h.catalog_off as usize + index * size_of::<CatalogEntry>(),
    )
    .ok_or(ArchiveError::BadGeometry)
}

/// Имя записи (ASCIIZ-отрез таблицы строк; окно [names_off..cpio_off)).
pub fn entry_name<'a>(
    blob: &'a [u8],
    h: &RlbaHeader,
    e: &CatalogEntry,
) -> Result<&'a str, ArchiveError> {
    let start = e.name_off as usize;
    let end = start
        .checked_add(e.name_len as usize)
        .ok_or(ArchiveError::NameOutOfBounds)?;
    // Имя обязано лежать в области таблицы строк (fail-closed: запись
    // с именем из чужой области образа — порча каталога, не «странность»).
    if start < h.names_off as usize || end > h.cpio_off as usize {
        return Err(ArchiveError::NameOutOfBounds);
    }
    let name = blob.get(start..end).ok_or(ArchiveError::NameOutOfBounds)?;
    core::str::from_utf8(name).map_err(|_| ArchiveError::NameOutOfBounds)
}

/// argv-строка записи («arg1 arg2…»), если задана.
pub fn entry_args<'a>(
    blob: &'a [u8],
    h: &RlbaHeader,
    e: &CatalogEntry,
) -> Result<Option<&'a str>, ArchiveError> {
    if e.args_off == 0 {
        return Ok(None);
    }
    // ASCIIZ до нуля или конца таблицы строк (cpio_off — верхняя
    // граница области строк).
    let start = e.args_off as usize;
    let limit = h.cpio_off as usize;
    if start < h.names_off as usize || start >= limit {
        return Err(ArchiveError::ArgsOutOfBounds);
    }
    let slice = &blob[start..limit];
    let len = slice
        .iter()
        .position(|&b| b == 0)
        .ok_or(ArchiveError::ArgsOutOfBounds)?;
    core::str::from_utf8(&slice[..len])
        .map(Some)
        .map_err(|_| ArchiveError::ArgsOutOfBounds)
}

/// Данные файла записи (срез внутри образа).
pub fn entry_data<'a>(blob: &'a [u8], e: &CatalogEntry) -> Result<&'a [u8], ArchiveError> {
    let start = e.data_off as usize;
    let end = start
        .checked_add(e.data_len as usize)
        .ok_or(ArchiveError::BadGeometry)?;
    blob.get(start..end).ok_or(ArchiveError::BadGeometry)
}

/// Проверить CRC32 данных записи (verify-then-use).
pub fn entry_verify(blob: &[u8], e: &CatalogEntry) -> Result<(), ArchiveError> {
    let data = entry_data(blob, e)?;
    if Crc32::of(data) == e.sum {
        Ok(())
    } else {
        Err(ArchiveError::BadCrc)
    }
}

/// Найти INIT-запись (первая с [`CATALOG_FLAG_INIT`]).
pub fn find_init(blob: &[u8], h: &RlbaHeader) -> Result<CatalogEntry, ArchiveError> {
    for i in 0..h.catalog_count as usize {
        let e = catalog_entry(blob, h, i)?;
        if e.is_init() {
            return Ok(e);
        }
    }
    Err(ArchiveError::NoInitEntry)
}

/// Найти запись по имени (линейный проход; имена уникальны по
/// построению — сборщик отклоняет дубли).
pub fn find_by_name(blob: &[u8], h: &RlbaHeader, name: &str) -> Option<CatalogEntry> {
    for i in 0..h.catalog_count as usize {
        let e = catalog_entry(blob, h, i).ok()?;
        if entry_name(blob, h, &e).ok() == Some(name) {
            return Some(e);
        }
    }
    None
}

// ───────────────────────────── Тесты ─────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn u64b(v: u64) -> [u8; 8] {
        v.to_le_bytes()
    }

    /// Мини-образ: заголовок + flat + каталог(1: init) + строки + cpio.
    fn make_archive(flat: &[u8], init_data: &[u8]) -> Vec<u8> {
        let mut blob = vec![0u8; 64];
        blob.extend_from_slice(flat);
        // каталог — 4K-выровнен.
        while blob.len() % 4096 != 0 {
            blob.push(0);
        }
        let catalog_off = blob.len();
        let entry = CatalogEntry {
            name_off: 0, // пересчитаем после вставки строк
            name_len: 4,
            flags: CATALOG_FLAG_INIT,
            data_off: 0, // пересчитаем
            data_len: init_data.len() as u64,
            sum: Crc32::of(init_data),
            args_off: 0,
            _pad: 0,
        };
        blob.extend_from_slice(unsafe {
            core::slice::from_raw_parts(
                (&entry as *const CatalogEntry) as *const u8,
                size_of::<CatalogEntry>(),
            )
        });
        let names_off = blob.len() as u32;
        blob.extend_from_slice(b"init\0--ro --verbose\0");
        // cpio — 4K-выровнен.
        while blob.len() % 4096 != 0 {
            blob.push(0);
        }
        let cpio_off = blob.len() as u64;
        let data_off = cpio_off; // данные сразу «в cpio»
        blob.extend_from_slice(init_data);
        while blob.len() % 512 != 0 {
            blob.push(0);
        }
        // Заголовок.
        let archive_len = blob.len() as u64;
        let mut hdr = RlbaHeader {
            magic: RLBA_MAGIC,
            version: RLBA_VERSION,
            flags: 0,
            flat_off: 64,
            flat_len: flat.len() as u64,
            catalog_off: catalog_off as u64,
            catalog_count: 1,
            names_off,
            cpio_off,
            archive_len,
            header_crc: 0,
            _pad: 0,
        };
        // Починить ссылку имени: имя лежит в names_off+0; данные — data_off.
        let e = catalog_entry_at(&blob, catalog_off).unwrap();
        let mut e2 = e;
        e2.name_off = names_off;
        e2.args_off = names_off + 5;
        e2.data_off = data_off;
        blob[catalog_off..catalog_off + size_of::<CatalogEntry>()].copy_from_slice(unsafe {
            core::slice::from_raw_parts(
                (&e2 as *const CatalogEntry) as *const u8,
                size_of::<CatalogEntry>(),
            )
        });
        hdr.header_crc = {
            let mut crc = Crc32::new();
            let bytes = unsafe {
                core::slice::from_raw_parts((&hdr as *const RlbaHeader) as *const u8, 56)
            };
            crc.update(bytes);
            crc.value()
        };
        blob[..64].copy_from_slice(unsafe {
            core::slice::from_raw_parts((&hdr as *const RlbaHeader) as *const u8, 64)
        });
        blob
    }

    /// Мини-FLAT: заголовок + один RX-сегмент.
    fn make_flat() -> Vec<u8> {
        let seg = FlatSeg {
            vaddr: FLAT_BASE as u32,
            file_off: 64 + 24,
            filesz: 16,
            memsz: 16,
            flags: 0b101,
            _pad: 0,
        };
        let hdr = FlatExecHeader {
            magic: FLAT_MAGIC,
            version: FLAT_VERSION,
            nsegs: 1,
            entry_off: 0,
            load_base: FLAT_BASE as u32,
            mem_top: 4096,
            segs_off: 64,
            image_crc: 0,
            _pad: [0; 9],
        };
        let mut f = Vec::new();
        f.extend_from_slice(unsafe {
            core::slice::from_raw_parts((&hdr as *const FlatExecHeader) as *const u8, 64)
        });
        f.extend_from_slice(unsafe {
            core::slice::from_raw_parts((&seg as *const FlatSeg) as *const u8, 24)
        });
        f.extend_from_slice(&[0x90u8; 16]); // «код»
        f
    }

    #[test]
    fn crc32_known_vectors() {
        // Стандартные контрольные значения IEEE CRC-32.
        assert_eq!(Crc32::of(b""), 0);
        assert_eq!(Crc32::of(b"123456789"), 0xCBF4_3926);
        assert_eq!(
            Crc32::of(b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
        // Инкрементальность = одному вызову.
        let mut c = Crc32::new();
        c.update(b"1234");
        c.update(b"56789");
        assert_eq!(c.value(), 0xCBF4_3926);
    }

    #[test]
    fn header_layout_is_frozen() {
        // Раскладка протокола: заголовок 64, запись 40, сегмент 24.
        assert_eq!(size_of::<RlbaHeader>(), 64);
        assert_eq!(size_of::<CatalogEntry>(), 40);
        assert_eq!(size_of::<FlatExecHeader>(), 64);
        assert_eq!(size_of::<FlatSeg>(), 24);
        assert_eq!(RlbaHeader::CRC_SPAN, 56);
    }

    #[test]
    fn parse_and_verify_roundtrip() {
        let flat = make_flat();
        let blob = make_archive(&flat, b"ELF-INIT-IMAGE");
        let h = parse_header(&blob).expect("header");
        assert_eq!(h.catalog_count, 1);
        assert_eq!(verify_header_crc(&blob, &h), Ok(()));

        // FLAT-разбор.
        let (entry, nsegs, segs) = parse_flat(&blob, &h).expect("flat");
        assert_eq!(entry, FLAT_BASE);
        assert_eq!(nsegs, 1);
        assert_eq!(segs[0].vaddr as u64, FLAT_BASE);
        assert_eq!(SegFlags::from_bits(segs[0].flags), Some(SegFlags::Rx));

        // Каталог: init найден, имя/argv/данные/CRC.
        let e = find_init(&blob, &h).expect("init entry");
        assert_eq!(entry_name(&blob, &h, &e).unwrap(), "init");
        assert_eq!(entry_args(&blob, &h, &e).unwrap(), Some("--ro --verbose"));
        assert_eq!(entry_data(&blob, &e).unwrap(), b"ELF-INIT-IMAGE");
        assert_eq!(entry_verify(&blob, &e), Ok(()));
        assert!(find_by_name(&blob, &h, "init").is_some());
        assert!(find_by_name(&blob, &h, "missing").is_none());
    }

    #[test]
    fn rejects_bad_magic_version_and_geometry() {
        let flat = make_flat();
        let mut blob = make_archive(&flat, b"DATA");
        // Магия.
        blob[0] = b'X';
        assert_eq!(parse_header(&blob), Err(ArchiveError::BadMagic));
        let mut blob = make_archive(&flat, b"DATA");
        blob[4] = 9; // version
        assert_eq!(parse_header(&blob), Err(ArchiveError::BadVersion));
        // Геометрия: cpio_off за archive_len.
        let mut blob = make_archive(&flat, b"DATA");
        blob[40..48].copy_from_slice(&u64b(1 << 40));
        assert_eq!(parse_header(&blob), Err(ArchiveError::BadGeometry));
        // Геометрия: flat заезжает на каталог.
        let mut blob = make_archive(&flat, b"DATA");
        blob[16..24].copy_from_slice(&u64b(1 << 30));
        assert_eq!(parse_header(&blob), Err(ArchiveError::BadGeometry));
    }

    #[test]
    fn rejects_header_crc_mismatch() {
        let flat = make_flat();
        let mut blob = make_archive(&flat, b"DATA");
        blob[8] ^= 0xFF; // портим flat_off
        let h = parse_header(&blob).expect("geometry still valid");
        assert_eq!(verify_header_crc(&blob, &h), Err(ArchiveError::BadCrc));
    }

    #[test]
    fn rejects_data_crc_mismatch() {
        let flat = make_flat();
        let mut blob = make_archive(&flat, b"ORIGINAL-DATA");
        let h = parse_header(&blob).unwrap();
        let e = find_init(&blob, &h).unwrap();
        // Порчим один байт данных.
        blob[e.data_off as usize] ^= 0x01;
        assert_eq!(entry_verify(&blob, &e), Err(ArchiveError::BadCrc));
    }

    #[test]
    fn rejects_flat_abuse() {
        let flat = make_flat();
        // W+X-флаг сегмента.
        let mut bad = flat.clone();
        bad[64 + 16..64 + 20].copy_from_slice(&7u32.to_le_bytes()); // RWX
        let blob = make_archive(&bad, b"DATA");
        let h = parse_header(&blob).unwrap();
        assert_eq!(parse_flat(&blob, &h), Err(ArchiveError::SegFlagsInvalid));
        // Нулевой load_base (чужая база).
        let mut bad = flat.clone();
        bad[12..16].copy_from_slice(&0x1000_0000u32.to_le_bytes());
        let blob = make_archive(&bad, b"DATA");
        let h = parse_header(&blob).unwrap();
        assert_eq!(parse_flat(&blob, &h), Err(ArchiveError::BadGeometry));
        // entry за mem_top.
        let mut bad = flat.clone();
        bad[8..12].copy_from_slice(&0x8000_0000u32.to_le_bytes());
        let blob = make_archive(&bad, b"DATA");
        let h = parse_header(&blob).unwrap();
        assert_eq!(parse_flat(&blob, &h), Err(ArchiveError::BadGeometry));
    }

    #[test]
    fn no_init_entry_is_rejected() {
        let flat = make_flat();
        let mut blob = make_archive(&flat, b"DATA");
        let h = parse_header(&blob).unwrap();
        // Снять INIT-флаг (поле flags записи: смещение 6 внутри записи).
        let c = h.catalog_off as usize;
        let mut fl = [0u8; 2];
        fl.copy_from_slice(&blob[c + 6..c + 8]);
        fl[0] = 0;
        blob[c + 6..c + 8].copy_from_slice(&fl);
        let h2 = parse_header(&blob).unwrap();
        assert_eq!(find_init(&blob, &h2), Err(ArchiveError::NoInitEntry));
    }
}
