// ==== BACKEND: платформенный крейт x86_64 ====
//
// Исполнитель контрактов ядра (`pkg_generic_interface::hal::traits`,
// `task::SchedulerInterface`, `startup::Platform`) на x86_64-железе:
//
//   * console  — COM1 (DebugSink + kprint!; SMP-спин лок с v0.6);
//   * memory   — UserTables (MMAP/KMAP/ASID: страницы задач, перенос
//     ядра MapFullKernel, CR3-активация), physmap-хелперы;
//   * cpu      — GDT/TSS/IDT, per-CPU (GS), syscall-MSR (SMP: массивы);
//   * lapic    — xAPIC + таймер (периодический тик ИЛИ TSC-deadline
//     one-shot с v0.13; PIT-калибровка TSC) + IPI (INIT-SIPI-SIPI /
//     resched / shootdown / halt);
//   * sched    — планировщик-бекенд (lock-free MPMC-кольцо готовности
//     + per-CPU текущий/квант/флаг/кэш контекстов, block-очереди,
//     троттл-лист CPU-квот);
//   * ctxswitch — asm-граница режимов (syscall/tick/faults/enter/IPI);
//   * gate     — rust-часть границы (диспетчеризация сисколов, тик,
//     фолты, idle; v0.12+: без BKL — IF-дисциплина ядровых локов
//     kernel::sync, хуки wait/wake/depth устанавливает здесь до
//     старта SMP);
//   * smp      — топология (MADT), SIPI-трамплин, bring-up AP, IPI,
//     TLB shootdown, halt-all;
//   * vtd      — Intel VT-d (DMAR/DRHD, QI, second-stage, IommuService);
//   * amd      — AMD-Vi (IVRS/IVHD, Device Table, командный буфер, v1);
//   * iommu    — общие хелперы (MMIO/кадры) + агрегатор сервиса vtd|amd;
//   * platform — X86Platform (startup::Platform);
//   * bin/kernel.rs — образ ядра: head.S -> kmain -> startup::kinit.
//
// Порядок от startup (kinit): head.S уже построил ядерные таблицы
// (high-half + physmap) и переключил CR3; kmain делает платформенную
// инициализацию (включая SMP bring-up до kinit — без кучи) и зовёт
// арх-НЕЗАВИСИМУЮ startup::kinit; X86Platform::run отпускает APы в
// планировщик и стартует VT-d.
#![no_std]

extern crate alloc;

pub mod amd;
pub mod console;
pub mod cpu;
pub mod ctxswitch;
pub mod gate;
pub mod ioapic;
pub mod iommu;
pub mod lapic;
pub mod memory;
pub mod platform;
pub mod sched;
pub mod smp;
pub mod vtd;

pub use platform::X86Platform;
