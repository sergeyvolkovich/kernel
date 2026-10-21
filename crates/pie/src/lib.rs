// ==== pie: минимальный PIE-загрузчик для спавна по готовому образу ====
//
// v0.11 решает открытый пункт «спавн PIE (динамический релок)». Контракт
// спавна v0.9 сохранён: ЯДРО принимает УЖЕ залинкованный образ — ядро не
// знает про ELF и релокации, юзерспейс-родитель готовит память. Значит,
// позиционная независимость — это работа ЗАГРУЗЧИКА в юзерспейсе (init):
// разбор PT_DYNAMIC, выбор базы и накат R_X86_64_RELATIVE в собственные
// staging-регионы ДО системного вызова TASK_SPAWN_IMAGE.
//
// Что здесь:
//   * `Plan::parse(blob)` — полный разбор ELF64 без аллокаций: точка
//     входа, план PT_LOAD-сегментов (страницы, флаги W^X) и таблица
//     RELA-релокаций (только R_X86_64_RELATIVE — иначе отказ: честный
//     fail-closed против образов с символным релокированием, которое
//     freestanding-домен разрешать не умеет);
//   * `Plan::apply_rela(base, store)` — применение релокаций к образу
//     со смещением `base` через колбэк записи (загрузчик мапит
//     линк-адрес X -> base + X; колбэк — собственная память родителя);
//   * ET_EXEC-образы поддержаны как `StaticFixed` (легаси-режим v0.9:
//     фиксированные адреса, релокаций нет) — один парсер для обоих.
//
// Переносимость: парсер — чистые срезы байтов, хост-тесты гоняются без
// цели (smoke загрузчика в QEMU — в демонстрации init S4: один и тот же
// образ спавнится на ДВУХ разных базах).

#![no_std]

/// Страница (ABI спавна: dst-адреса 4K-выровнены).
pub const PAGE: u64 = 4096;
/// Максимум PT_LOAD-сегментов в плане (ABI спавна: SPAWN_MAX_SEGMENTS).
pub const MAX_SEGS: usize = 16;
/// Максимум R_X86_64_RELATIVE-релокаций (образы демо — единицы;
/// freestanding-PIE без символных ссылок даёт десятки, не тысячи).
pub const MAX_RELAS: usize = 256;
/// Максимум записей .dynamic, которые просматривает парсер.
pub const MAX_DYN: usize = 64;

// ───────────────────── Константы ELF64 ─────────────────────

pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const DT_NULL: i64 = 0;
pub const DT_RELA: i64 = 7;
pub const DT_RELASZ: i64 = 8;
pub const DT_RELAENT: i64 = 9;
pub const DT_REL: i64 = 17;
/// Единственный поддерживаемый тип релокации: *(base + r_offset) =
/// base + r_addend (адрес внутри образа; символной части нет).
pub const R_X86_64_RELATIVE: u32 = 8;

// ───────────────────── Типы ─────────────────────

/// Одна релокация образа (R_X86_64_RELATIVE, символ — локальный).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rela {
    /// Линк-адрес слова, которое нужно патчить (в образе).
    pub offset: u64,
    /// Линк-адрес цели, который должен оказаться в слове (+ base).
    pub addend: u64,
}

/// План одного PT_LOAD-сегмента (страницы — единица маппинга спавна).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SegPlan {
    /// Начало региона (p_vaddr, выровненное вниз до страницы).
    pub vstart: u64,
    /// Страниц в регионе (покрывает memsz, округлённый вверх).
    pub pages: u64,
    /// Смещение p_vaddr внутри региона (файл ложится сюда).
    pub in_seg: u64,
    /// Файловое смещение сегмента (p_offset).
    pub file_off: u64,
    /// Размер файловой части (p_filesz).
    pub filesz: u64,
    /// Флаги протокола спавна (MMAPMemoryFlags-совместимые: W^X —
    /// RW=0b011 / RX=0b101 / RO=0b001).
    pub flags: u64,
}

impl SegPlan {
    /// Конец региона (страница после последней).
    pub fn vend(&self) -> u64 {
        self.vstart + self.pages * PAGE
    }

    /// Лежит ли линк-адрес внутри региона (для релокаций).
    pub fn contains(&self, vaddr: u64, len: u64) -> bool {
        vaddr >= self.vstart && vaddr + len <= self.vend()
    }
}

/// Вид образа: фиксированные адреса (легаси v0.9) или PIE.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ImageKind {
    /// ET_EXEC: все адреса абсолютные, релокаций нет.
    StaticFixed,
    /// ET_DYN: образ грузится на выбранную родителем базу.
    Pie,
}

/// Ошибка разбора (fail-closed: спавн-сервер отказывается от образа,
/// а не спавнит «как получится»).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PlanError {
    /// Нет магии ELF64 / не ELF64.
    NotElf,
    /// Таблица/сегмент/динамическая запись обрезаны.
    Truncated,
    /// PT_LOAD-сегментов нет (грузить нечего).
    NoLoadSegments,
    /// Сегментов больше MAX_SEGS (ABI спавна).
    TooManySegments,
    /// phentsize не 56 (заголовок программы не ELF64-стандартный).
    BadPhentSize,
    /// Точка входа нулевая или вне сегментов.
    BadEntry,
    /// ET_DYN без PT_DYNAMIC — PIE обязан описать свои релокации.
    BadDynamic,
    /// .dynamic содержит DT_REL: поддержан только RELA (x86-64-конвенция).
    HasRel,
    /// DT_RELAENT отличен от 24.
    BadRelaEntSize,
    /// RELASZ не кратен 24 или больше доступных байтов.
    BadRelaSize,
    /// Релокаций больше MAX_RELAS.
    TooManyRelas,
    /// Неподдержанный тип релокации (всё, кроме R_X86_64_RELATIVE).
    UnsupportedReloc(u32),
    /// R_X86_64_RELATIVE с ненулевым символом (спекой запрещено).
    RelocWithSymbol,
    /// r_offset вне PT_LOAD-регионов.
    RelocOutsideSegments(u64),
    /// r_offset не выровнен на 8.
    UnalignedReloc(u64),
}

/// Разобранный план загрузки образа.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Plan {
    /// Точка входа (линк-адрес; для PIE родитель прибавит базу).
    pub entry: u64,
    /// Статический (ET_EXEC) или PIE (ET_DYN).
    pub kind: ImageKind,
    /// Сегменты, в порядке заголовков.
    pub segs: [SegPlan; MAX_SEGS],
    pub n_segs: usize,
    /// Релокации PIE (для StaticFixed — пусто).
    pub relas: [Rela; MAX_RELAS],
    pub n_relas: usize,
}

impl Plan {
    /// Разобрать образ (файл-срез: сегменты читаются с file_off).
    pub fn parse(blob: &[u8]) -> Result<Plan, PlanError> {
        let r8 = |o: usize| -> u64 {
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
        if blob.len() < 0x38 || &blob[0..4] != b"\x7fELF" || blob[4] != 2 {
            return Err(PlanError::NotElf);
        }
        let etype = r16(0x10) as u16;
        let entry = r8(0x18);
        let phoff = r8(0x20) as usize;
        let phentsize = r16(0x36) as usize;
        let phnum = r16(0x38) as usize;
        if phentsize != 56 {
            return Err(PlanError::BadPhentSize);
        }
        let ph_end = phoff
            .checked_add(phnum.saturating_mul(phentsize))
            .ok_or(PlanError::Truncated)?;
        if ph_end > blob.len() {
            return Err(PlanError::Truncated);
        }
        if entry == 0 {
            return Err(PlanError::BadEntry);
        }

        // ---- PT_LOAD-план + адрес PT_DYNAMIC ----
        let mut segs = [SegPlan {
            vstart: 0,
            pages: 0,
            in_seg: 0,
            file_off: 0,
            filesz: 0,
            flags: 0,
        }; MAX_SEGS];
        let mut n = 0usize;
        let mut dyn_off = 0usize;
        let mut dyn_filesz = 0usize;
        for i in 0..phnum {
            let ph = phoff + i * phentsize;
            let ptype = r32(ph) as u32;
            if ptype == PT_DYNAMIC {
                dyn_off = r8(ph + 0x08) as usize;
                dyn_filesz = r8(ph + 0x20) as usize;
                continue;
            }
            if ptype != PT_LOAD {
                continue;
            }
            let p_flags = r32(ph + 4) as u8;
            let offset = r8(ph + 0x08);
            let vaddr = r8(ph + 0x10);
            let filesz = r8(ph + 0x20);
            let memsz = r8(ph + 0x28);
            if memsz == 0 {
                continue;
            }
            if n == segs.len() {
                return Err(PlanError::TooManySegments);
            }
            if offset.checked_add(filesz).ok_or(PlanError::Truncated)? > blob.len() as u64 {
                return Err(PlanError::Truncated);
            }
            let vstart = vaddr & !(PAGE - 1);
            let vend = (vaddr + memsz + PAGE - 1) & !(PAGE - 1);
            segs[n] = SegPlan {
                vstart,
                pages: (vend - vstart) / PAGE,
                in_seg: vaddr - vstart,
                file_off: offset,
                filesz,
                // W^X-перевод (тот же протокол, что у elfload ядра).
                flags: if p_flags & 0x2 != 0 {
                    0b011 // RW
                } else if p_flags & 0x1 != 0 {
                    0b101 // RX
                } else {
                    0b001 // RO
                },
            };
            n += 1;
        }
        if n == 0 {
            return Err(PlanError::NoLoadSegments);
        }
        let segs_ok = |v: u64, len: u64| segs[..n].iter().any(|s| s.contains(v, len));
        if !segs_ok(entry, 1) {
            return Err(PlanError::BadEntry);
        }

        let (kind, relas, n_relas) = match etype {
            ET_EXEC => (
                ImageKind::StaticFixed,
                [Rela {
                    offset: 0,
                    addend: 0,
                }; MAX_RELAS],
                0,
            ),
            ET_DYN => {
                // PIE: релокации обязательны к ЯВНОМУ описанию — PT_DYNAMIC
                // с DT_RELA/DT_RELASZ (DT_REL — отказ: x86-64 использует RELA).
                if dyn_off == 0 || dyn_filesz == 0 {
                    return Err(PlanError::BadDynamic);
                }
                let dyn_end = dyn_off
                    .checked_add(dyn_filesz)
                    .ok_or(PlanError::Truncated)?;
                if dyn_end > blob.len() {
                    return Err(PlanError::Truncated);
                }
                let mut rela_vaddr = None;
                let mut rela_sz = 0usize;
                let mut has_rel = false;
                for i in 0..MAX_DYN {
                    let off = dyn_off + i * 16;
                    if off + 16 > dyn_end {
                        break;
                    }
                    let tag = r8(off) as i64;
                    let val = r8(off + 8);
                    if tag == DT_NULL {
                        break;
                    }
                    match tag {
                        DT_RELA => rela_vaddr = Some(val),
                        DT_RELASZ => rela_sz = val as usize,
                        // RELAENT — размер записи: x86-64-спека, 24 байта.
                        DT_RELAENT if val != 24 => return Err(PlanError::BadRelaEntSize),
                        DT_REL => has_rel = true,
                        _ => {}
                    }
                }
                if has_rel {
                    return Err(PlanError::HasRel);
                }
                let rela_vaddr = rela_vaddr.ok_or(PlanError::BadDynamic)?;
                if rela_sz == 0 {
                    return Err(PlanError::BadRelaSize);
                }
                if rela_sz % 24 != 0 {
                    return Err(PlanError::BadRelaSize);
                }
                let count = rela_sz / 24;
                if count > MAX_RELAS {
                    return Err(PlanError::TooManyRelas);
                }
                // DT_RELA — линк-адрес: через содержащий PT_LOAD переводим
                // в файловое смещение (статический PIE: p_offset == p_vaddr
                // у rust-lld, но парсер не полагается на это).
                let rela_off = vaddr_to_file(&segs[..n], rela_vaddr, rela_sz as u64)
                    .ok_or(PlanError::RelocOutsideSegments(rela_vaddr))?;
                let mut relas = [Rela {
                    offset: 0,
                    addend: 0,
                }; MAX_RELAS];
                for i in 0..count {
                    let off = rela_off + i * 24;
                    let r_offset = r8(off);
                    let r_info = r8(off + 8);
                    let r_addend = r8(off + 16);
                    let rtype = (r_info & 0xFFFF_FFFF) as u32;
                    let rsym = r_info >> 32;
                    if rtype != R_X86_64_RELATIVE {
                        return Err(PlanError::UnsupportedReloc(rtype));
                    }
                    if rsym != 0 {
                        return Err(PlanError::RelocWithSymbol);
                    }
                    if r_offset % 8 != 0 {
                        return Err(PlanError::UnalignedReloc(r_offset));
                    }
                    if !segs_ok(r_offset, 8) {
                        return Err(PlanError::RelocOutsideSegments(r_offset));
                    }
                    relas[i] = Rela {
                        offset: r_offset,
                        addend: r_addend,
                    };
                }
                (ImageKind::Pie, relas, count)
            }
            _ => return Err(PlanError::NotElf),
        };

        Ok(Plan {
            entry,
            kind,
            segs,
            n_segs: n,
            relas,
            n_relas,
        })
    }

    /// Конец образа по линк-адресам (вершина последнего региона).
    pub fn image_end(&self) -> u64 {
        self.segs[..self.n_segs]
            .iter()
            .map(|s| s.vend())
            .max()
            .unwrap_or(0)
    }

    /// Найти регион линк-адреса (для колбэка родителя).
    pub fn seg_of(&self, vaddr: u64) -> Option<(usize, &SegPlan)> {
        self.segs[..self.n_segs]
            .iter()
            .enumerate()
            .find(|(_, s)| s.contains(vaddr, 1))
    }

    /// Применить релокации: для каждой — записать `base + addend` по
    /// линк-адресу `offset` через `store(vaddr, value)`. Возврат — число
    /// применённых записей. Для StaticFixed — 0 (семантика: образ уже
    /// готов, база не нужна).
    ///
    /// `store` пишет 8 байт little-endian в СТЭЙДЖИНГ-регионы родителя,
    /// мапя линк-адрес образа (валидация offset/покрытия уже сделана
    /// парсером — колбэк обязан только транслировать адрес).
    pub fn apply_rela(&self, base: u64, mut store: impl FnMut(u64, u64)) -> usize {
        if self.kind != ImageKind::Pie {
            return 0;
        }
        for r in &self.relas[..self.n_relas] {
            store(r.offset, base.wrapping_add(r.addend));
        }
        self.n_relas
    }
}

/// Линк-адрес -> файловое смещение через содержащий PT_LOAD
/// (vaddr внутри [p_vaddr, p_vaddr+p_filesz) файловой части).
fn vaddr_to_file(segs: &[SegPlan], vaddr: u64, len: u64) -> Option<usize> {
    for s in segs {
        let vbase = s.vstart + s.in_seg;
        if vaddr >= vbase && vaddr + len <= vbase + s.filesz {
            return Some((s.file_off + (vaddr - vbase)) as usize);
        }
    }
    None
}

// ───────────────────── Хост-тесты ─────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec::Vec;

    // ── Сборка синтетического PIE (ehdr + phdrs + сегменты + dynamic + rela) ──

    fn push64(v: &mut Vec<u8>, w: u64) {
        v.extend_from_slice(&w.to_le_bytes());
    }

    // Правильная раскладка (эмулирует rust-lld static-pie):
    //   ehdr+phdr (0xB0)
    //   LOAD 0 RX: file [0x1000..0x2000) @ vaddr 0x1000
    //   LOAD 1 RW: file [0x2000..0x2400) @ vaddr 0x2000 (memsz 0x800 — BSS)
    //   PT_DYNAMIC: file/vaddr 0x1800 (внутри LOAD 0)
    //   .rela.dyn:  file/vaddr 0x1900 (внутри LOAD 0)
    fn build_pie(relas: &[(u64, u64)], extra_dyn: &[(i64, u64)]) -> (Vec<u8>, usize, usize) {
        let mut v: Vec<u8> = Vec::new();
        v.resize(0xB0, 0);
        v[0..4].copy_from_slice(b"\x7fELF");
        v[4] = 2;
        v[0x10..0x12].copy_from_slice(&ET_DYN.to_le_bytes());
        v[0x18..0x20].copy_from_slice(&0x1234u64.to_le_bytes()); // entry
        v[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes());
        v[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        v[0x38..0x3A].copy_from_slice(&3u16.to_le_bytes()); // 2 LOAD + DYNAMIC
        v.resize(0x40 + 3 * 56, 0);
        let mut set = |v: &mut Vec<u8>,
                       ph: usize,
                       t: u32,
                       flags: u32,
                       off: u64,
                       va: u64,
                       fsz: u64,
                       msz: u64| {
            v[ph..ph + 4].copy_from_slice(&t.to_le_bytes());
            v[ph + 4..ph + 8].copy_from_slice(&flags.to_le_bytes());
            v[ph + 8..ph + 16].copy_from_slice(&off.to_le_bytes());
            v[ph + 16..ph + 24].copy_from_slice(&va.to_le_bytes());
            v[ph + 32..ph + 40].copy_from_slice(&fsz.to_le_bytes());
            v[ph + 40..ph + 48].copy_from_slice(&msz.to_le_bytes());
        };
        // LOAD 0: file [0x1000..0x2000) @ vaddr 0x1000, RX.
        set(&mut v, 0x40, PT_LOAD, 5, 0x1000, 0x1000, 0x1000, 0x1000);
        // LOAD 1: file [0x2000..0x2400) @ vaddr 0x2000, RW (BSS хвост).
        set(&mut v, 0x40 + 56, PT_LOAD, 6, 0x2000, 0x2000, 0x400, 0x800);
        // PT_DYNAMIC: file [0x2C00..) @ vaddr 0x2C00 (внутри LOAD 1 memsz —
        // но файловая часть LOAD 1 кончается на 0x2400 → кладём dynamic
        // СРАЗУ после rela внутри LOAD 0: vaddr 0x1800, file 0x1800.
        let dyn_file = 0x1800usize;
        set(
            &mut v,
            0x40 + 2 * 56,
            PT_DYNAMIC,
            6,
            dyn_file as u64,
            dyn_file as u64,
            16 * 6,
            16 * 6,
        );
        v.resize(0x2C00, 0);
        // RELA-таблица: file/vaddr 0x1900.
        let rela_off = 0x1900usize;
        v.resize((rela_off + relas.len() * 24).max(0x2C00), 0);
        for (i, &(r_off, r_add)) in relas.iter().enumerate() {
            let o = rela_off + i * 24;
            v[o..o + 8].copy_from_slice(&r_off.to_le_bytes());
            v[o + 8..o + 16].copy_from_slice(&8u64.to_le_bytes());
            v[o + 16..o + 24].copy_from_slice(&r_add.to_le_bytes());
        }
        // Dynamic: RELA=0x1900, RELASZ, RELAENT=24, доп-теги, NULL.
        let mut d = Vec::new();
        push64(&mut d, DT_RELA as u64);
        push64(&mut d, 0x1900);
        push64(&mut d, DT_RELASZ as u64);
        push64(&mut d, (relas.len() * 24) as u64);
        push64(&mut d, DT_RELAENT as u64);
        push64(&mut d, 24);
        for &(t, x) in extra_dyn {
            push64(&mut d, t as u64);
            push64(&mut d, x);
        }
        push64(&mut d, DT_NULL as u64);
        push64(&mut d, 0);
        v[dyn_file..dyn_file + d.len()].copy_from_slice(&d);
        (v, dyn_file, rela_off)
    }

    #[test]
    fn pie_parse_and_apply_two_bases() {
        // Две релокации в RW-сегменте (vaddr 0x2000+).
        let relas = [(0x2008u64, 0x1234u64), (0x2100u64, 0x1000u64)];
        let (v, _d, _r) = build_pie(&relas, &[]);
        let plan = Plan::parse(&v).expect("valid pie");
        assert_eq!(plan.kind, ImageKind::Pie);
        assert_eq!(plan.entry, 0x1234);
        assert_eq!(plan.n_segs, 2);
        assert_eq!(plan.n_relas, 2);
        assert_eq!(plan.segs[0].vstart, 0x1000);
        assert_eq!(plan.segs[1].vstart, 0x2000);
        assert_eq!(plan.segs[1].pages, 1);
        assert_eq!(plan.segs[1].in_seg, 0);
        assert_eq!(plan.image_end(), 0x3000);

        // apply на базу 0x40000000: store получает base+addend по offset.
        let base = 0x4000_0000u64;
        let mut written = Vec::new();
        let n = plan.apply_rela(base, |vaddr, val| written.push((vaddr, val)));
        assert_eq!(n, 2);
        assert_eq!(written[0], (0x2008, base + 0x1234));
        assert_eq!(written[1], (0x2100, base + 0x1000));

        // Вторая база — те же релоки, другое смещение (суть PIE).
        let base2 = 0x5000_0000u64;
        let mut written2 = Vec::new();
        plan.apply_rela(base2, |vaddr, val| written2.push((vaddr, val)));
        assert_eq!(written2[0], (0x2008, base2 + 0x1234));
    }

    #[test]
    fn static_fixed_has_no_relocs() {
        let mut v: Vec<u8> = Vec::new();
        v.resize(0x40 + 56, 0);
        v[0..4].copy_from_slice(b"\x7fELF");
        v[4] = 2;
        v[0x10..0x12].copy_from_slice(&ET_EXEC.to_le_bytes());
        v[0x18..0x20].copy_from_slice(&0x4000_0040u64.to_le_bytes());
        v[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes());
        v[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        v[0x38..0x3A].copy_from_slice(&1u16.to_le_bytes());
        // LOAD @ 0x40000000 (file [0x40..0x1000)).
        v.resize(0x1000, 0);
        v[0x40..0x44].copy_from_slice(&PT_LOAD.to_le_bytes());
        v[0x44..0x48].copy_from_slice(&5u32.to_le_bytes());
        v[0x48..0x50].copy_from_slice(&0x40u64.to_le_bytes());
        v[0x50..0x58].copy_from_slice(&0x4000_0000u64.to_le_bytes());
        v[0x60..0x68].copy_from_slice(&0xFC0u64.to_le_bytes());
        v[0x68..0x70].copy_from_slice(&0xFC0u64.to_le_bytes());
        let plan = Plan::parse(&v).expect("static elf");
        assert_eq!(plan.kind, ImageKind::StaticFixed);
        assert_eq!(plan.n_relas, 0);
        assert_eq!(plan.apply_rela(0x5000_0000, |_, _| panic!("no store")), 0);
    }

    #[test]
    fn unsupported_reloc_types_rejected() {
        // GLOB_DAT (6) и релокация с символом — fail-closed.
        let relas = [(0x2008u64, 0x10u64)];
        let (v, _d, _r) = build_pie(&relas, &[]);
        // Подменим тип у записи 0 на R_X86_64_GLOB_DAT.
        let mut v = v.clone();
        let info_off = 0x1900 + 8;
        v[info_off..info_off + 8].copy_from_slice(&6u64.to_le_bytes());
        assert_eq!(Plan::parse(&v), Err(PlanError::UnsupportedReloc(6)));
        let mut v2 = v.clone();
        v2[info_off..info_off + 8].copy_from_slice(&((1u64 << 32) | 8).to_le_bytes());
        assert_eq!(Plan::parse(&v2), Err(PlanError::RelocWithSymbol));
    }

    #[test]
    fn reloc_bounds_and_alignment_enforced() {
        let relas = [(0x9000u64, 0x1u64)]; // выровнено, но вне сегментов
        let (v, _d, _r) = build_pie(&relas, &[]);
        assert_eq!(
            Plan::parse(&v),
            Err(PlanError::RelocOutsideSegments(0x9000))
        );
        let relas = [(0x2004u64, 0x1u64)]; // не выровнено на 8
        let (v, _d, _r) = build_pie(&relas, &[]);
        assert_eq!(Plan::parse(&v), Err(PlanError::UnalignedReloc(0x2004)));
    }

    #[test]
    fn dt_rel_rejected() {
        let (v, _d, _r) = build_pie(&[(0x2008, 1)], &[(DT_REL, 0x77)]);
        assert_eq!(Plan::parse(&v), Err(PlanError::HasRel));
    }

    #[test]
    fn truncated_and_blobs_rejected() {
        assert_eq!(Plan::parse(&[0u8; 64]), Err(PlanError::NotElf));
        // Обрезанный файл: LOAD 1 заявляет байты до 0x2400.
        let (v, _d, _r) = build_pie(&[(0x2008, 1)], &[]);
        let mut v = v.clone();
        v.truncate(0x2100);
        assert_eq!(Plan::parse(&v), Err(PlanError::Truncated));
    }

    #[test]
    fn empty_rela_size_rejected() {
        // RELASZ=0 — PIE без релокаций не описан динамикой корректно.
        let (v, _d, _r) = build_pie(&[], &[]);
        assert_eq!(Plan::parse(&v), Err(PlanError::BadRelaSize));
    }

    #[test]
    fn entry_outside_segments_rejected() {
        let relas = [(0x2008u64, 0x10u64)];
        let (mut v, _d, _r) = build_pie(&relas, &[]);
        // entry вне [0x1000..0x3000).
        v[0x18..0x20].copy_from_slice(&0x8000_0000u64.to_le_bytes());
        assert_eq!(Plan::parse(&v), Err(PlanError::BadEntry));
    }
}

// ───────────────────── Диагностика (консоль демо) ─────────────────────

impl PlanError {
    /// Код ошибки для вывода в отладочную консоль (no_std без fmt).
    pub fn code(&self) -> u64 {
        match self {
            PlanError::NotElf => 1,
            PlanError::Truncated => 2,
            PlanError::NoLoadSegments => 3,
            PlanError::TooManySegments => 4,
            PlanError::BadPhentSize => 5,
            PlanError::BadEntry => 6,
            PlanError::BadDynamic => 7,
            PlanError::HasRel => 8,
            PlanError::BadRelaEntSize => 9,
            PlanError::BadRelaSize => 10,
            PlanError::TooManyRelas => 11,
            PlanError::UnsupportedReloc(t) => 0x100 + *t as u64,
            PlanError::RelocWithSymbol => 0x110,
            PlanError::RelocOutsideSegments(_) => 0x120,
            PlanError::UnalignedReloc(_) => 0x130,
        }
    }
}
