// ==== HAL Trait Wrapper Architecture ====
//
// This module reorganizes the trait hierarchy around wrapper types to provide:
// 1. Clear abstraction boundaries between platform abstraction and generic operations
// 2. Improved modularity and composability of trait implementations
// 3. Better trait object safety for runtime polymorphism
// 4. More intuitive ownership semantics for wrapper types
//
// Pattern: Trait -> Platform Trait -> Wrapper Struct that Implements Trait
//
// Example Dma flow:
// DmaPlatform (platform-specific) + DirectDmaOps (wrapper) -> DmaOps (generic)
//
// Example Iommu flow:
// ANIOMMUInterface (agnostic) + LIOMMUInterface (backend-specific with Processor) -> Combined operation
//
// Example Device:
// HWInterface (backend) + BusInterface (bus) + DeviceRecord (device data) + DeviceManager (collection)

pub mod asid;
pub mod cpu;
pub mod dma;
pub mod iommu;
pub mod irq;
pub mod kmap;
pub mod mmap;
