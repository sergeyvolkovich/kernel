use core::{alloc::Layout, ptr::NonNull};

use alloc::alloc::{alloc_zeroed, dealloc};
use bitflags::bitflags;

use crate::hal::{
    traits::iommu::IommuError,
    types::{DeviceInfo, PAGE_SIZE, PhysAddr},
};

// ==== Trait: DMA Platform (platform-specific hooks) ====
//
// Implement this trait for platform-specific address translation and cache
// maintenance operations. Generic DMA wrappers depend on this trait rather
// than on concrete platform types.

pub trait DmaPlatform {
    /// Виртуальный адрес ядра -> физический.
    fn virt_to_phys(&self, ptr: *const u8) -> PhysAddr;

    /// Сбросить (clean) кэш перед чтением устройством.
    fn cache_clean(&self, _addr: DmaAddr, _len: usize) {}

    /// Инвалидировать кэш перед чтением CPU данных, записанных устройством.
    fn cache_invalidate(&self, _addr: DmaAddr, _len: usize) {}

    /// Сделать область некэшируемой (для не-когерентных устройств).
    fn make_uncached(&self, _ptr: *mut u8, _size: usize) {}
}

// ==== Trait: DMA Operations (generic, object-safe) ====
//
// Implement this trait for DMA backend wrappers. All DMA subsystems depend
// on this trait rather than on concrete implementations.

pub trait DmaOps {
    /// Выделить когерентный DMA-буфер.
    fn alloc_coherent(&self, dev: &DeviceInfo, size: usize) -> Result<CoherentBuf, DmaError>;
    /// Отобразить одиночный буфер в DMA-адресное пространство.
    fn map_single(&self, dev: &DeviceInfo, buf: &[u8], dir: Direction)
    -> Result<DmaAddr, DmaError>;
    /// Снять отображение одиночного буфера.
    fn unmap_single(&self, dev: &DeviceInfo, addr: DmaAddr, len: usize, dir: Direction);
    /// Синхронизировать данные для CPU (устройство уже закончило запись).
    fn sync_for_cpu(&self, addr: DmaAddr, len: usize, dir: Direction);
    /// Синхронизировать данные для устройства (CPU уже закончило запись).
    fn sync_for_device(&self, addr: DmaAddr, len: usize, dir: Direction);
}

// ==== Ошибки DMA ====

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaError {
    OutOfMemory,
    InvalidArgument,
    NotMapped,
    AddressOutOfRange,
    NotSupported,
    Iommu(IommuError),
}

impl From<IommuError> for DmaError {
    fn from(e: IommuError) -> Self {
        DmaError::Iommu(e)
    }
}

// ==== Направление передачи DMA ====

bitflags! {
    /// Направление передачи данных относительно устройства.
    /// Пустой набор флагов (`Direction::empty()`) означает «без передачи данных».
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Direction: u8 {
        /// CPU -> устройство (устройство читает память).
        const TO_DEVICE = 1 << 0;
        /// Устройство -> CPU (устройство пишет в память).
        const FROM_DEVICE = 1 << 1;
        /// В обе стороны.
        const BIDIRECTIONAL = Self::TO_DEVICE.bits() | Self::FROM_DEVICE.bits();
    }
}

impl Direction {
    pub fn device_reads(self) -> bool {
        self.contains(Direction::TO_DEVICE)
    }

    pub fn device_writes(self) -> bool {
        self.contains(Direction::FROM_DEVICE)
    }
}

// ==== DMA-адрес ====

#[derive(Clone, Copy)]
pub struct DmaAddr(u64);

impl DmaAddr {
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    pub const fn offset(self, off: u64) -> Self {
        Self(self.0 + off)
    }

    pub const fn align_down(self, align: u64) -> Self {
        Self(self.0 & !(align - 1))
    }

    pub const fn align_up(self, align: u64) -> Self {
        Self((self.0 + align - 1) & !(align - 1))
    }

    pub const fn is_aligned(self, align: u64) -> bool {
        self.0 & (align - 1) == 0
    }
}

// ==== Когерентный DMA-буфер ====

/// Когерентный DMA-буфер: выделенная память + адрес для устройства.
/// Память освобождается при `Drop`.
pub struct CoherentBuf {
    cpu_ptr: NonNull<u8>,
    dma_addr: DmaAddr,
    size: usize,
    layout: Layout,
}

unsafe impl Send for CoherentBuf {}
unsafe impl Sync for CoherentBuf {}

impl CoherentBuf {
    /// # Safety
    /// `ptr` должен быть получен из `alloc::alloc::alloc*` с тем же `layout`,
    /// а `size <= layout.size()`.
    pub unsafe fn from_raw(
        ptr: NonNull<u8>,
        dma_addr: DmaAddr,
        size: usize,
        layout: Layout,
    ) -> Self {
        Self {
            cpu_ptr: ptr,
            dma_addr,
            size,
            layout,
        }
    }

    pub fn dma_addr(&self) -> DmaAddr {
        self.dma_addr
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.cpu_ptr.as_ptr()
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.cpu_ptr.as_ptr()
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// # Safety
    /// Устройство не должно писать в буфер во время жизни среза.
    pub unsafe fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.cpu_ptr.as_ptr(), self.size) }
    }

    /// # Safety
    /// Устройство не должно обращаться к буферу во время жизни среза.
    pub unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.cpu_ptr.as_ptr(), self.size) }
    }
}

impl Drop for CoherentBuf {
    fn drop(&mut self) {
        unsafe { dealloc(self.cpu_ptr.as_ptr(), self.layout) }
    }
}

// ==== Обёртка: DirectDmaOps — прямое отображение (без IOMMU) ====
//
// Обёртка над `DmaPlatform`, реализующая `DmaOps` через identity-отображение:
// DMA-адрес совпадает с физическим. Используется на платформах без IOMMU,
// либо как fallback, когда IOMMU недоступен.

pub struct DirectDmaOps<P: DmaPlatform> {
    platform: P,
}

impl<P: DmaPlatform> DirectDmaOps<P> {
    pub fn new(platform: P) -> Self {
        Self { platform }
    }
}

impl<P: DmaPlatform> DmaOps for DirectDmaOps<P> {
    fn alloc_coherent(&self, dev: &DeviceInfo, size: usize) -> Result<CoherentBuf, DmaError> {
        if size == 0 {
            return Err(DmaError::InvalidArgument);
        }

        let aligned = size
            .checked_add(PAGE_SIZE - 1)
            .ok_or(DmaError::InvalidArgument)?
            & !(PAGE_SIZE - 1);
        let layout =
            Layout::from_size_align(aligned, PAGE_SIZE).map_err(|_| DmaError::InvalidArgument)?;

        let raw = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(raw).ok_or(DmaError::OutOfMemory)?;

        if !dev.coherent {
            self.platform.make_uncached(ptr.as_ptr(), aligned);
        }

        let phys = self.platform.virt_to_phys(ptr.as_ptr());
        Ok(unsafe { CoherentBuf::from_raw(ptr, DmaAddr(phys.0), size, layout) })
    }

    fn map_single(
        &self,
        dev: &DeviceInfo,
        buf: &[u8],
        dir: Direction,
    ) -> Result<DmaAddr, DmaError> {
        if buf.is_empty() || dir.is_empty() {
            return Err(DmaError::InvalidArgument);
        }

        let phys = self.platform.virt_to_phys(buf.as_ptr());
        let addr = DmaAddr(phys.0);

        if !dev.coherent {
            if dir.device_reads() {
                self.platform.cache_clean(addr, buf.len());
            } else {
                self.platform.cache_invalidate(addr, buf.len());
            }
        }

        Ok(addr)
    }

    fn unmap_single(&self, dev: &DeviceInfo, addr: DmaAddr, len: usize, dir: Direction) {
        if !dev.coherent && dir.device_writes() {
            self.platform.cache_invalidate(addr, len);
        }
    }

    fn sync_for_cpu(&self, addr: DmaAddr, len: usize, dir: Direction) {
        if dir.device_writes() {
            self.platform.cache_invalidate(addr, len);
        }
    }

    fn sync_for_device(&self, addr: DmaAddr, len: usize, dir: Direction) {
        if dir.device_reads() {
            self.platform.cache_clean(addr, len);
        } else if dir.device_writes() {
            self.platform.cache_invalidate(addr, len);
        }
    }
}
