// ==== Разделяемая память в стиле io_uring: регионы + SQ/CQ-кольца + doorbell ====
//
// Протокол (выбор «кольца между задачами» при проектировании):
//
// ```text
//   ShmManager
//   ├─ регионы: физические кадры из общего пула (zero-copy: ядро НЕ
//   │  копирует данные — только раздаёт отображения задачам);
//   ├─ RingLayout: раскладка колец ВНУТРИ региона (io_uring-совместимая
//   │  геометрия: заголовок head/tail/mask + массив SQE + массив CQE);
//   └─ doorbell: endpoint (notification) — сигнал производителем после
//      submit'а SQE; потребитель будится по IPC, данные читает из колец
//      напрямую (мимо ядра).
// ```
//
// РАСКЛАДКА региона с кольцом (слова u64, little-endian):
// ```text
//   +0x00  sq_head    — потребительский индекс SQ (сколько SQE обработано)
//   +0x08  sq_tail    — индекс продюсера SQ (сколько отправлено)
//   +0x10  sq_mask    = sq_entries - 1
//   +0x18  cq_head    — потребительский индекс CQ
//   +0x20  cq_tail    — индекс продюсера CQ (готовых CQE)
//   +0x28  cq_mask    = cq_entries - 1
//   +0x30  flags      — протокольные флаги пользователя
//   +0x38  reserved
//   +sq_off: массив SQE (sq_entries * entry_words слов)
//   +cq_off: массив CQE (cq_entries * entry_words слов)
// ```
//
// Инициализация heads/tails — юзерспейс-библиотека после отображения
// (микроядро не пишет в данные региона); ядро отвечает за ГЕОМЕТРИЮ,
// физику и doorbell-события. Производитель после записи SQE делает
// сискол `RING_DOORBELL` (signal словом = новый sq_tail) — потребитель
// получает async-IPC и читает кольца без копий.

use alloc::{collections::BTreeMap, vec::Vec};
use core::cell::{Cell, RefCell};

use llfree::{Alloc, Classing, Request};

use core::fmt;

use heapless::pool::arc::Arc;

use crate::mem::ARCPool;

use thiserror::Error;

use crate::capability::ObjId;
use crate::hal::traits::mmap::{MMAPMemoryFlags, MemErrorCode, PhysADDR};
use crate::ipc::IpcManager;
use crate::mem::MemRouter;
use crate::task::{TaskId, TcbManager};

/// Идентификатор SHM-региона.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShmId(pub u64);

impl ShmId {
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ShmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "shm({})", self.0)
    }
}

/// Ошибка подсистемы SHM.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ShmError {
    /// Регион не найден.
    #[error("shm region {0} not found")]
    NotFound(ShmId),
    /// Регион уже разрушен/не существует.
    #[error("shm region {0} is gone")]
    Gone(ShmId),
    /// Кольцо уже настроено (повторная настройка запрещена).
    #[error("shm region {0} already has a ring")]
    RingExists(ShmId),
    /// Геометрия кольца некорректна (entries — степень двойки, не влезает).
    #[error("invalid ring geometry: {0}")]
    BadGeometry(&'static str),
    /// Нет памяти под кадры региона.
    #[error("out of memory for shm frames")]
    OutOfMemory,
    /// Ошибка памяти (отображение в задачу).
    #[error("memory subsystem error: {0}")]
    Mem(#[from] MemErrorCode),
    /// Doorbell не привязан.
    #[error("doorbell endpoint is not bound")]
    NoDoorbell,
    /// Ошибка IPC (signal doorbell).
    #[error("ipc error: {0}")]
    Ipc(#[from] crate::ipc::IpcError),
}

impl From<ShmError> for crate::syscall::SyscallError {
    fn from(e: ShmError) -> Self {
        use crate::syscall::SyscallError;
        match e {
            ShmError::NotFound(_) | ShmError::Gone(_) => SyscallError::NotFound,
            ShmError::RingExists(_) => SyscallError::AlreadyExists,
            ShmError::BadGeometry(_) => SyscallError::InvalidArgument,
            ShmError::OutOfMemory => SyscallError::OutOfMemory,
            ShmError::Mem(m) => m.into(),
            ShmError::NoDoorbell => SyscallError::InvalidArgument,
            ShmError::Ipc(i) => i.into(),
            #[allow(unreachable_patterns)]
            _ => SyscallError::Internal,
        }
    }
}

/// Слов в заголовке кольца (io_uring-совместимая шапка).
pub const RING_HEADER_WORDS: usize = 8;
/// Минимум слов на слот (SQE/CQE).
pub const RING_MIN_ENTRY_WORDS: usize = 1;
/// Максимум слов на слот (8 слов = 64 байта, как io_uring SQE).
pub const RING_MAX_ENTRY_WORDS: usize = 8;

/// Раскладка колец внутри региона (результат `setup_ring`).
///
/// Все смещения — в СЛОВАХ от начала региона; адрес в пространстве задачи =
/// база отображения + смещение * 8. Инициализация заголовка — юзерспейс.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingLayout {
    /// Смещение массива SQE (слов).
    pub sq_off: usize,
    /// Число SQE-слотов (степень двойки).
    pub sq_entries: usize,
    /// Смещение массива CQE (слов).
    pub cq_off: usize,
    /// Число CQE-слотов (степень двойки).
    pub cq_entries: usize,
    /// Слов на слот (SQE и CQE одинаковой ширины).
    pub entry_words: usize,
    /// Полный размер колец в словах (включая заголовок).
    pub total_words: usize,
}

impl RingLayout {
    /// Геометрия кольца: entries — степени двойки, слот 1..=8 слов,
    /// всё влезает в `region_words`.
    pub fn validate(
        sq_entries: usize,
        cq_entries: usize,
        entry_words: usize,
        region_words: usize,
    ) -> Result<Self, ShmError> {
        if sq_entries == 0 || cq_entries == 0 {
            return Err(ShmError::BadGeometry("entries must be > 0"));
        }
        if !sq_entries.is_power_of_two() || !cq_entries.is_power_of_two() {
            return Err(ShmError::BadGeometry("entries must be a power of two"));
        }
        if !(RING_MIN_ENTRY_WORDS..=RING_MAX_ENTRY_WORDS).contains(&entry_words) {
            return Err(ShmError::BadGeometry("entry_words must be 1..=8"));
        }
        let sq_off = RING_HEADER_WORDS;
        let cq_off = sq_off + sq_entries * entry_words;
        let total_words = cq_off + cq_entries * entry_words;
        if total_words > region_words {
            return Err(ShmError::BadGeometry("ring does not fit the region"));
        }
        Ok(Self {
            sq_off,
            sq_entries,
            cq_off,
            cq_entries,
            entry_words,
            total_words,
        })
    }
}

/// Снимок региона для пользователя (сисколы SHM_*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShmInfo {
    pub id: ShmId,
    /// База физики региона.
    pub base: PhysADDR,
    /// Страниц в регионе.
    pub pages: usize,
    /// Настроенное кольцо (если есть).
    pub ring: Option<RingLayout>,
    /// Привязанный doorbell-endpoint.
    pub doorbell: Option<ObjId>,
    /// Создатель.
    pub owner: TaskId,
}

/// Регион разделяемой памяти.
struct ShmRegion {
    id: ShmId,
    /// База физических кадров (выделены из общего пула).
    base: PhysADDR,
    pages: usize,
    /// Класс выдачи кадров (для честного возврата пулу при destroy).
    class: llfree::Class,
    owner: TaskId,
    ring: Option<RingLayout>,
    doorbell: Option<ObjId>,
}

/// Менеджер SHM-регионов: физика + геометрия колец + doorbell-и.
///
/// Данные через ядро НЕ ходят (zero-copy): после `map` задача работает с
/// кольцами напрямую; ядро участвует только в трёх точках — создание
/// региона, настройка геометрии и doorbell-сигналы.
pub struct ShmManager {
    regions: RefCell<BTreeMap<ShmId, ShmRegion>>,
    next_id: Cell<u64>,
    /// Общий физический пул (разделяется с MemoryManager).
    p_allocator: Arc<ARCPool>,
    /// Класс запросов кадров (дефолт класса Classing::simple).
    alloc_class: llfree::Class,
}

impl ShmManager {
    /// Менеджер поверх общего физического пула.
    pub fn new(p_allocator: Arc<ARCPool>) -> Self {
        let (cl, _) = Classing::simple(1);
        Self {
            regions: RefCell::new(BTreeMap::new()),
            next_id: Cell::new(1),
            p_allocator,
            alloc_class: cl.default,
        }
    }

    /// Число живых регионов (аудит).
    pub fn count(&self) -> usize {
        self.regions.borrow().len()
    }

    /// Создать регион из `pages` физических кадров (zero-copy: кадры
    /// раздаются отображениями, данные не копируются).
    pub fn create(&self, owner: TaskId, pages: usize) -> Result<ShmId, ShmError> {
        if pages == 0 {
            return Err(ShmError::BadGeometry("pages must be > 0"));
        }
        let order = pages
            .checked_next_power_of_two()
            .map(|n| n.ilog2() as usize)
            .ok_or(ShmError::BadGeometry("pages is too large"))?;
        let req = Request::new(order, self.alloc_class, None);
        let (frame, class) = self
            .p_allocator
            .as_ref()
            .get(None, req)
            .map_err(|_| ShmError::OutOfMemory)?;

        let id = ShmId(self.next_id.get());
        self.next_id.set(self.next_id.get() + 1);
        self.regions.borrow_mut().insert(
            id,
            ShmRegion {
                id,
                base: PhysADDR(frame.0 * llfree::FRAME_SIZE),
                pages,
                class,
                owner,
                ring: None,
                doorbell: None,
            },
        );
        Ok(id)
    }

    /// Снимок региона (сисколы SHM_*: геометрия, doorbell, база).
    pub fn info(&self, id: ShmId) -> Option<ShmInfo> {
        let regions = self.regions.borrow();
        regions.get(&id).map(|r| ShmInfo {
            id: r.id,
            base: r.base,
            pages: r.pages,
            ring: r.ring,
            doorbell: r.doorbell,
            owner: r.owner,
        })
    }

    /// Настроить кольца SQ/CQ в регионе (io_uring-геометрия). Повторная
    /// настройка запрещена: кольца строятся один раз при создании канала.
    pub fn setup_ring(
        &self,
        id: ShmId,
        sq_entries: usize,
        cq_entries: usize,
        entry_words: usize,
    ) -> Result<RingLayout, ShmError> {
        let mut regions = self.regions.borrow_mut();
        let region = regions.get_mut(&id).ok_or(ShmError::NotFound(id))?;
        if region.ring.is_some() {
            return Err(ShmError::RingExists(id));
        }
        let region_words = region.pages * (llfree::FRAME_SIZE / 8);
        let layout = RingLayout::validate(sq_entries, cq_entries, entry_words, region_words)?;
        region.ring = Some(layout);
        Ok(layout)
    }

    /// Привязать doorbell-endpoint (signal при submit — RING_DOORBELL).
    pub fn bind_doorbell(&self, id: ShmId, gate: ObjId) -> Result<(), ShmError> {
        let mut regions = self.regions.borrow_mut();
        let region = regions.get_mut(&id).ok_or(ShmError::NotFound(id))?;
        region.doorbell = Some(gate);
        Ok(())
    }

    /// Doorbell-endpoint региона (сискол RING_DOORBELL резолвит signal).
    pub fn doorbell_gate(&self, id: ShmId) -> Option<ObjId> {
        self.regions.borrow().get(&id).and_then(|r| r.doorbell)
    }

    /// Сигнал doorbell: производитель сабмитит SQE и звенит в колокол
    /// (слово — например, новый sq_tail; потребитель спит на endpoint'е).
    pub fn doorbell(
        &self,
        ipc: &IpcManager,
        tasks: &TcbManager,
        caps: &crate::capability::CapabilityManager,
        id: ShmId,
        word: u64,
    ) -> Result<crate::ipc::SendOutcome, ShmError> {
        let gate = self.doorbell_gate(id).ok_or(ShmError::NoDoorbell)?;
        Ok(ipc.signal(tasks, caps, gate, word)?)
    }

    /// Отобразить регион в адресное пространство задачи (внешние кадры:
    /// снятие отображения не возвращает физику пулу — она принадлежит
    /// региону до `destroy`). Возвращает виртуальный адрес.
    pub fn map_into(
        &self,
        router: &dyn MemRouter,
        task: TaskId,
        id: ShmId,
        flags: MMAPMemoryFlags,
    ) -> Result<usize, ShmError> {
        let regions = self.regions.borrow();
        let region = regions.get(&id).ok_or(ShmError::NotFound(id))?;
        let vaddr = router.map_external(task, region.base, region.pages, flags)?;
        Ok(vaddr.0)
    }

    /// Разрушить регион: кадры возвращаются пулу. Отображения у задач —
    /// ответственность платформы (сначала unmap у всех пользователей).
    pub fn destroy(&self, id: ShmId) -> Result<(), ShmError> {
        let region = self
            .regions
            .borrow_mut()
            .remove(&id)
            .ok_or(ShmError::NotFound(id))?;
        let order = region
            .pages
            .checked_next_power_of_two()
            .map(|n| n.ilog2() as usize)
            .expect("pages > 0 при создании");
        let req = Request::new(order, region.class, None);
        let frame = llfree::FrameId(region.base.0 / llfree::FRAME_SIZE);
        let _ = self.p_allocator.as_ref().put(frame, req);
        Ok(())
    }

    /// Регионы задачи (аудит/разрушение домена).
    pub fn regions_of(&self, owner: &TaskId) -> Vec<ShmId> {
        self.regions
            .borrow()
            .values()
            .filter(|r| &r.owner == owner)
            .map(|r| r.id)
            .collect()
    }
}

// ==== Тесты (host) ====

#[cfg(test)]
mod tests {
    use super::*;

    fn make_allocator(frames: usize) -> Arc<ARCPool> {
        crate::mem::install_p_allocator(make_llfree(frames))
    }

    fn make_llfree(frames: usize) -> llfree::LLFree<'static> {
        use llfree::{Classing, MetaData};
        let (cl, _) = Classing::simple(1);
        let sizes = llfree::LLFree::metadata_size(&cl, frames);
        let mut local = aligned_box::AlignedBox::slice_from_value(64, sizes.local, 0u8).unwrap();
        let mut trees = aligned_box::AlignedBox::slice_from_value(64, sizes.trees, 0u8).unwrap();
        let mut lower = aligned_box::AlignedBox::slice_from_value(64, sizes.lower, 0u8).unwrap();
        let meta = unsafe {
            MetaData {
                local: core::slice::from_raw_parts_mut(local.as_mut_ptr(), local.len()),
                trees: core::slice::from_raw_parts_mut(trees.as_mut_ptr(), trees.len()),
                lower: core::slice::from_raw_parts_mut(lower.as_mut_ptr(), lower.len()),
            }
        };
        core::mem::forget((local, trees, lower));
        llfree::LLFree::new(frames, llfree::Init::FreeAll, &cl, meta).unwrap()
    }

    #[test]
    fn ring_layout_geometry() {
        // Валидная геометрия.
        let l = RingLayout::validate(8, 16, 2, 512).unwrap();
        assert_eq!(l.sq_off, RING_HEADER_WORDS);
        assert_eq!(l.cq_off, RING_HEADER_WORDS + 8 * 2);
        assert_eq!(l.total_words, RING_HEADER_WORDS + 8 * 2 + 16 * 2);

        // Не степень двойки.
        assert!(matches!(
            RingLayout::validate(7, 16, 2, 512),
            Err(ShmError::BadGeometry(_))
        ));
        // Нулевые entries.
        assert!(matches!(
            RingLayout::validate(0, 16, 2, 512),
            Err(ShmError::BadGeometry(_))
        ));
        // Слот вне 1..=8.
        assert!(matches!(
            RingLayout::validate(8, 16, 0, 512),
            Err(ShmError::BadGeometry(_))
        ));
        assert!(matches!(
            RingLayout::validate(8, 16, 9, 512),
            Err(ShmError::BadGeometry(_))
        ));
        // Не влезает: страница = 512 слов; 256+256 слотов по 8 слов + шапка.
        assert!(matches!(
            RingLayout::validate(256, 256, 8, 512),
            Err(ShmError::BadGeometry(_))
        ));
        // Влезает ровно.
        RingLayout::validate(16, 16, 8, 512).unwrap();
    }

    #[test]
    fn region_lifecycle_and_ring_setup() {
        let owner = uuid::Uuid::from_u128(1);
        let shm = ShmManager::new(make_allocator(64));

        // Создание: 2 страницы.
        let id = shm.create(owner, 2).unwrap();
        assert_eq!(shm.count(), 1);
        let info = shm.info(id).unwrap();
        assert_eq!(info.pages, 2);
        assert_eq!(info.owner, owner);
        assert!(info.ring.is_none());
        assert!(info.doorbell.is_none());

        // Кольцо: SQ 8, CQ 16, слот 2 слова (влезает в 2*512 слов).
        let layout = shm.setup_ring(id, 8, 16, 2).unwrap();
        assert_eq!(shm.info(id).unwrap().ring, Some(layout));

        // Повторная настройка — отказ.
        assert!(matches!(
            shm.setup_ring(id, 4, 4, 1),
            Err(ShmError::RingExists(_))
        ));

        // Doorbell.
        let gate = crate::capability::ObjId::new(1, 1);
        shm.bind_doorbell(id, gate).unwrap();
        assert_eq!(shm.doorbell_gate(id), Some(gate));

        // Регион задачи.
        assert_eq!(shm.regions_of(&owner), alloc::vec![id]);

        // Разрушение.
        shm.destroy(id).unwrap();
        assert_eq!(shm.count(), 0);
        assert!(shm.info(id).is_none());
        assert!(matches!(shm.destroy(id), Err(ShmError::NotFound(_))));

        // Нулевой размер.
        assert!(matches!(
            shm.create(owner, 0),
            Err(ShmError::BadGeometry(_))
        ));
    }
}
