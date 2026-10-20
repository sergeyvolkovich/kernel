// ==== MMAP: управление регионами памяти ====

use aligned_box::AlignedBoxError;
use attachable_slab_allocator::SlabError;
use bitflags::bitflags;
use core::fmt;
use llfree::{FRAME_SIZE, LLFree};
use thiserror::Error;

use crate::hal::traits::asid::{ASIDError, TlbOp};

/// Размер страницы в байтах (совпадает с размером фрейма LLFree).
pub const PAGE_SIZE: usize = FRAME_SIZE;

// ───────────────────────────── Ошибки ─────────────────────────────

#[derive(Error, Debug)]
pub enum MemErrorCode {
    #[error("Internal error")]
    InternalError,
    #[error("No memory left")]
    NoMemoryLeft,

    #[error("Invalid address")]
    InvalADDR,
    #[error("Invalid argument: {0}")]
    InvalidArgument(&'static str),

    /// Запись/регион не найден (используется в `UFacade::shrink_memory_wiev`).
    #[error("Record or mapping not found")]
    NotFound,
    #[error("Address is not page aligned")]
    Unaligned,

    #[error("Region is already mapped")]
    AlreadyMapped,

    #[error("Region is not mapped")]
    NotMapped,
    // Было `{}` с `self` -> Display вызывал сам себя (бесконечная рекурсия).
    #[error("Page allocator error: {0:?}")]
    PageAllocator(llfree::Error),
    #[error("Internal slab error")]
    SlabError(#[from] SlabError),

    #[error("Aligned box error{0}")]
    AlignBoxError(AlignedBoxError),

    /// Пул тегов ASID/PCID исчерпан или не поддержан бекендом.
    #[error("ASID/PCID error: {0:?}")]
    Asid(ASIDError),
}

impl From<llfree::Error> for MemErrorCode {
    fn from(e: llfree::Error) -> Self {
        MemErrorCode::PageAllocator(e)
    }
}

impl From<ASIDError> for MemErrorCode {
    fn from(e: ASIDError) -> Self {
        MemErrorCode::Asid(e)
    }
}

// ───────────────────────────── Адреса ─────────────────────────────

/// Общие методы для обёрток над адресами.
macro_rules! addr_impl {
    ($t:ident) => {
        impl $t {
            #[inline]
            pub const fn new(addr: usize) -> Self {
                Self(addr)
            }

            #[inline]
            pub const fn as_usize(self) -> usize {
                self.0
            }

            #[inline]
            pub const fn is_aligned(self) -> bool {
                self.0 % PAGE_SIZE == 0
            }

            #[inline]
            pub const fn align_down(self) -> Self {
                Self(self.0 - self.0 % PAGE_SIZE)
            }

            /// Округление вверх; `None` при переполнении.
            #[inline]
            pub const fn align_up(self) -> Option<Self> {
                match self.0.checked_add(PAGE_SIZE - 1) {
                    Some(v) => Some(Self(v - v % PAGE_SIZE)),
                    None => None,
                }
            }

            /// Сдвиг на `bytes` байт; `None` при переполнении.
            #[inline]
            pub const fn offset(self, bytes: usize) -> Option<Self> {
                match self.0.checked_add(bytes) {
                    Some(v) => Some(Self(v)),
                    None => None,
                }
            }

            /// Номер страницы относительно `base`; `None`, если адрес ниже `base`.
            #[inline]
            pub const fn page_index_from(self, base: Self) -> Option<usize> {
                if self.0 < base.0 {
                    None
                } else {
                    Some((self.0 - base.0) / PAGE_SIZE)
                }
            }
        }

        impl From<usize> for $t {
            #[inline]
            fn from(v: usize) -> Self {
                Self(v)
            }
        }

        impl fmt::LowerHex for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::LowerHex::fmt(&self.0, f)
            }
        }

        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{:#x}", self.0)
            }
        }
    };
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct VirtualADDR(pub usize);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct PhysADDR(pub usize);

addr_impl!(VirtualADDR);
addr_impl!(PhysADDR);

// ───────────────────────────── PageInfo ─────────────────────────────

/// Непрерывный физический регион: база и количество страниц.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageInfo {
    pub p: PhysADDR,
    pub pages_count: usize,
}

impl PageInfo {
    #[inline]
    pub const fn new(p: PhysADDR, pages_count: usize) -> Self {
        Self { p, pages_count }
    }

    /// Размер региона в байтах; `None` при переполнении.
    #[inline]
    pub const fn size_bytes(&self) -> Option<usize> {
        self.pages_count.checked_mul(PAGE_SIZE)
    }

    /// Первый адрес за регионом; `None` при переполнении.
    #[inline]
    pub fn end(&self) -> Option<PhysADDR> {
        self.p.offset(self.size_bytes()?)
    }

    /// Попадает ли физический адрес в регион.
    #[inline]
    pub fn contains(&self, addr: PhysADDR) -> bool {
        match self.end() {
            Some(end) => addr >= self.p && addr < end,
            None => false,
        }
    }
}

// ───────────────────────────── Флаги ─────────────────────────────

// Написано под bitflags 2.x (там derive обязателен).
// Для bitflags 1.x убери строку #[derive(...)] внутри макроса.
bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct MMAPMemoryFlags: u8 {
        const READABLE   = 1 << 0;
        const WRITABLE   = 1 << 1;
        const EXECUTABLE = 1 << 2;
        const CACHEABLE  = 1 << 3;
        /// Страница может жить в TLB глобально (x86 PTE.PGD/ARM nG=0):
        /// запись переживает переключение адресных пространств и теги
        /// ASID/PCID. Разрешён ТОЛЬКО для отображений, идентичных во всех
        /// адресных пространствах (образ ядра в таблицах ядра при
        /// MapFullKernel; см. `KernelRegion`). Запись в бит НЕ даёт прав
        /// доступа и не проходит `validate()` без R/W/X.
        const GLOBAL     = 1 << 4;
    }
}

impl MMAPMemoryFlags {
    pub const RO: Self = Self::READABLE;
    pub const RW: Self = Self::READABLE.union(Self::WRITABLE);
    pub const RX: Self = Self::READABLE.union(Self::EXECUTABLE);

    /// Проверка набора флагов:
    /// - должно быть выдано хотя бы одно право (R/W/X);
    /// - W и X одновременно запрещены (политика W^X).
    pub fn validate(self) -> Result<(), MemErrorCode> {
        let perms = Self::READABLE | Self::WRITABLE | Self::EXECUTABLE;
        if !self.intersects(perms) {
            return Err(MemErrorCode::InvalidArgument(
                "flags must grant at least one of READABLE/WRITABLE/EXECUTABLE",
            ));
        }
        if self.contains(Self::WRITABLE | Self::EXECUTABLE) {
            return Err(MemErrorCode::InvalidArgument(
                "WRITABLE and EXECUTABLE together violate W^X",
            ));
        }
        Ok(())
    }
}

// ───────────────────────────── Трейты ─────────────────────────────

pub trait FrameAllocator {
    fn allocate_pages(&self, pages: usize) -> Result<PageInfo, MemErrorCode>;
    fn deallocate_pages(&self, pi: PageInfo);
}

pub trait MMAPInterface {
    /// Отобразить `pages` страниц: `v_base` -> `p_base` с флагами `mmap`.
    fn extend_region(
        &mut self,
        allocator: &LLFree<'static>,
        v_base: VirtualADDR,
        p_base: PhysADDR,
        pages: usize,
        mmap: MMAPMemoryFlags,
    ) -> Result<PageInfo, MemErrorCode>;

    /// Снять отображение `pages` страниц, начиная с `allocation`.
    fn shrink_region(
        &mut self,
        phys_page_allocator: &LLFree<'static>,
        allocation: VirtualADDR,
        pages: usize,
    ) -> Result<(), MemErrorCode>;

    /// `extend_region` с предварительной проверкой аргументов
    /// (ненулевой размер, выравнивание, флаги).
    fn extend_region_checked(
        &mut self,
        allocator: &LLFree<'static>,
        v_base: VirtualADDR,
        p_base: PhysADDR,
        pages: usize,
        mmap: MMAPMemoryFlags,
    ) -> Result<PageInfo, MemErrorCode> {
        if pages == 0 {
            return Err(MemErrorCode::InvalidArgument("pages must be > 0"));
        }
        if !v_base.is_aligned() || !p_base.is_aligned() {
            return Err(MemErrorCode::Unaligned);
        }
        mmap.validate()?;
        self.extend_region(allocator, v_base, p_base, pages, mmap)
    }

    /// `shrink_region` с предварительной проверкой аргументов.
    fn shrink_region_checked(
        &mut self,
        phys_page_allocator: &LLFree<'static>,
        allocation: VirtualADDR,
        pages: usize,
    ) -> Result<(), MemErrorCode> {
        if pages == 0 {
            return Err(MemErrorCode::InvalidArgument("pages must be > 0"));
        }
        if !allocation.is_aligned() {
            return Err(MemErrorCode::Unaligned);
        }
        self.shrink_region(phys_page_allocator, allocation, pages)
    }

    /// Точечная инвалидация TLB с учётом тегов ASID/PCID.
    ///
    /// Дефолт — отказ [`MemErrorCode::InvalidArgument`]: бекенд, не
    /// реализующий тегированные TLB-операции, ОБЯЗАН сбрасывать TLB
    /// самостоятельно внутри `shrink_region` / `unmap_kernel_region`
    /// (нетегированное переключение/запись CR3 сбрасывает не-глобальные
    /// записи целиком). Громкий отказ вместо тихого no-op — сознательная
    /// политика крейта: забытая инвалидация при живых тегах — дыра
    /// безопасности, а не потеря производительности.
    ///
    /// Переопределяется бекендами с поддержкой PCID/ASID (INVPCID на x86,
    /// TLBI ASID на ARM): только они получают от фасадов пары тегов
    /// ([`crate::hal::traits::asid::ASIDInterface`]).
    fn invalidate_tlb(&mut self, _op: TlbOp) -> Result<(), MemErrorCode> {
        Err(MemErrorCode::InvalidArgument(
            "backend: tagged TLB invalidation not implemented",
        ))
    }
}
