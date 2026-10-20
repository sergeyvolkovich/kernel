// ==== Хендлеры памяти: аллокация/освобождение/flexpage + SHM io_uring ====
//
// Память задачи доступна через `MemRouter` (type-erased доступ к фасаду
// адресного пространства). Сисколы:
//   * MEM_ALLOC/MEM_FREE — эластичное расширение (región = страницы +
//     отображение; адрес выбирает фасад);
//   * MEM_TRANSFER — flexpage map/grant между задачами (L4);
//   * SHM_CREATE/SETUP_RING/BIND_DOORBELL/MAP/DESTROY/INFO + RING_DOORBELL
//     — разделяемая память io_uring (zero-copy, кольца SQ/CQ, doorbell
//     через notification-endpoint).

use crate::capability::{CapHandle, ContainerACCCapability};
use crate::hal::traits::mmap::{MMAPMemoryFlags, VirtualADDR};
use crate::ipc::shm::{RingLayout, ShmId};
use crate::syscall::nums;
use crate::task::TaskId;

use super::SyscallHandler;
use super::types::{SyscallArgs, SyscallCtx, SyscallError, SyscallNumber, SyscallRet};

fn task_id_from(lo: usize, hi: usize) -> TaskId {
    uuid::Uuid::from_u128(((hi as u128) << 64) | lo as u128)
}

// ==== MEM_ALLOC / MEM_FREE ====

pub struct MemAllocHandler;

impl MemAllocHandler {
    pub const SYSCALL: SyscallNumber = nums::MEM_ALLOC;
}

impl SyscallHandler for MemAllocHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let router = ctx.memory.ok_or(SyscallError::NotSupported)?;
        let pages = args.arg(1);
        let flags = MMAPMemoryFlags::from_bits_retain(args.arg(2) as u8);
        let vaddr = router.alloc_region(ctx.task, pages, flags)?;
        Ok(vaddr.0)
    }
}

pub struct MemFreeHandler;

impl MemFreeHandler {
    pub const SYSCALL: SyscallNumber = nums::MEM_FREE;
}

impl SyscallHandler for MemFreeHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let router = ctx.memory.ok_or(SyscallError::NotSupported)?;
        router.free_region(ctx.task, VirtualADDR(args.arg(1)))?;
        Ok(0)
    }
}

// ==== MEM_TRANSFER (flexpage map/grant) ====

pub struct MemTransferHandler;

impl MemTransferHandler {
    pub const SYSCALL: SyscallNumber = nums::MEM_TRANSFER;
}

impl SyscallHandler for MemTransferHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let router = ctx.memory.ok_or(SyscallError::NotSupported)?;
        let src_vaddr = args.arg(1);
        let pages = args.arg(2);
        let grant = args.arg(3) & 1 != 0;
        let dst = task_id_from(args.arg(4), args.arg(5));
        // Права отображения: RW по умолчанию (сужение — будущие флаги ABI).
        let flags = MMAPMemoryFlags::RW;
        let at = router.transfer(dst, 0, ctx.task, src_vaddr, pages, grant, flags)?;
        Ok(at)
    }
}

// ==== MEM_INFO (регион по адресу) ====

/// Регион задачи, содержащий адрес (аудит рантайма, pager'ы).
///
/// Слова по индексу: 0 = база виртуальная, 1 = база физики,
/// 2 = страниц, 3 = 0 (зарезервировано). Адрес вне регионов — ENOENT.
/// ABI: arg1 = адрес, arg2 = индекс слова.
pub struct MemInfoHandler;

impl MemInfoHandler {
    pub const SYSCALL: SyscallNumber = nums::MEM_INFO;
}

impl SyscallHandler for MemInfoHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let router = ctx.memory.ok_or(SyscallError::NotSupported)?;
        let Some((vbase, pbase, pages)) = router.region_at(ctx.task, VirtualADDR(args.arg(1)))
        else {
            return Err(SyscallError::NotFound);
        };
        let words = [vbase.0, pbase.0, pages, 0];
        let idx = args.arg(2);
        words
            .get(idx)
            .map(|w| Ok(*w))
            .unwrap_or(Err(SyscallError::InvalidArgument))
    }
}

// ==== SHM_CREATE / SETUP_RING / BIND_DOORBELL / MAP / DESTROY / INFO ====

pub struct ShmCreateHandler;

impl ShmCreateHandler {
    pub const SYSCALL: SyscallNumber = nums::SHM_CREATE;
}

impl SyscallHandler for ShmCreateHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let shm = ctx.shm.ok_or(SyscallError::NotSupported)?;
        let pages = args.arg(1);
        let id = shm.create(ctx.task, pages)?;
        Ok(id.as_u64() as usize)
    }
}

pub struct ShmSetupRingHandler;

impl ShmSetupRingHandler {
    pub const SYSCALL: SyscallNumber = nums::SHM_SETUP_RING;
}

impl SyscallHandler for ShmSetupRingHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let shm = ctx.shm.ok_or(SyscallError::NotSupported)?;
        let id = ShmId(args.arg(1) as u64);
        let sq_entries = args.arg(2);
        let cq_entries = args.arg(3);
        let entry_words = args.arg(4);
        let layout: RingLayout = shm.setup_ring(id, sq_entries, cq_entries, entry_words)?;
        Ok(layout.sq_off)
    }
}

pub struct ShmBindDoorbellHandler;

impl ShmBindDoorbellHandler {
    pub const SYSCALL: SyscallNumber = nums::SHM_BIND_DOORBELL;
}

impl SyscallHandler for ShmBindDoorbellHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let shm = ctx.shm.ok_or(SyscallError::NotSupported)?;
        let id = ShmId(args.arg(1) as u64);
        let ep = CapHandle(args.arg(2) as u64);
        // Резолв Gate-capability вызывающего -> ObjId.
        let view = ctx.resolve(ep)?;
        let ContainerACCCapability::Gate { gate_id } = view.cap_ref else {
            return Err(SyscallError::InvalidArgument);
        };
        shm.bind_doorbell(id, gate_id)?;
        Ok(0)
    }
}

pub struct ShmMapHandler;

impl ShmMapHandler {
    pub const SYSCALL: SyscallNumber = nums::SHM_MAP;
}

impl SyscallHandler for ShmMapHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let shm = ctx.shm.ok_or(SyscallError::NotSupported)?;
        let router = ctx.memory.ok_or(SyscallError::NotSupported)?;
        let id = ShmId(args.arg(1) as u64);
        let flags = MMAPMemoryFlags::from_bits_retain(args.arg(2) as u8);
        shm.map_into(router, ctx.task, id, flags)
            .map_err(|e| e.into())
    }
}

pub struct ShmDestroyHandler;

impl ShmDestroyHandler {
    pub const SYSCALL: SyscallNumber = nums::SHM_DESTROY;
}

impl SyscallHandler for ShmDestroyHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let shm = ctx.shm.ok_or(SyscallError::NotSupported)?;
        shm.destroy(ShmId(args.arg(1) as u64))?;
        Ok(0)
    }
}

pub struct ShmInfoHandler;

impl ShmInfoHandler {
    pub const SYSCALL: SyscallNumber = nums::SHM_INFO;
}

impl SyscallHandler for ShmInfoHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let shm = ctx.shm.ok_or(SyscallError::NotSupported)?;
        let id = ShmId(args.arg(1) as u64);
        let index = args.arg(2);
        let info = shm.info(id).ok_or(SyscallError::NotFound)?;

        // Словарь слов (см. документацию номера SHM_INFO в nums.rs).
        let ring = info.ring;
        let words: [u64; 11] = [
            info.pages as u64,
            info.base.0 as u64,
            ring.map(|r| r.sq_off as u64).unwrap_or(0),
            ring.map(|r| r.sq_entries as u64).unwrap_or(0),
            ring.map(|r| r.cq_off as u64).unwrap_or(0),
            ring.map(|r| r.cq_entries as u64).unwrap_or(0),
            ring.map(|r| r.entry_words as u64).unwrap_or(0),
            ring.map(|r| r.total_words as u64).unwrap_or(0),
            info.doorbell.map(|g| g.bits()).unwrap_or(0),
            info.owner.as_u128() as u64,
            (info.owner.as_u128() >> 64) as u64,
        ];
        words
            .get(index)
            .map(|w| *w as usize)
            .ok_or(SyscallError::NotFound)
    }
}

// ==== RING_DOORBELL ====

pub struct RingDoorbellHandler;

impl RingDoorbellHandler {
    pub const SYSCALL: SyscallNumber = nums::RING_DOORBELL;
}

impl SyscallHandler for RingDoorbellHandler {
    fn invoke(&self, ctx: &mut SyscallCtx<'_>, args: &SyscallArgs) -> SyscallRet {
        let shm = ctx.shm.ok_or(SyscallError::NotSupported)?;
        let ipc = ctx.ipc.ok_or(SyscallError::NotSupported)?;
        let id = ShmId(args.arg(1) as u64);
        let word = args.arg(2) as u64;
        shm.doorbell(ipc, ctx.tasks, ctx.caps, id, word)?;
        Ok(0)
    }
}

// ==== Тесты (host) ====

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::CapabilityManager;
    use crate::ipc::ShmManager;
    use crate::mem::{MemRouterImpl, MemoryManager, install_p_allocator};
    use crate::syscall::SyscallRegistry;
    use crate::task::{TaskId, TaskPriority, TcbManager};

    fn uuid_next() -> uuid::Uuid {
        use core::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0x4000);
        uuid::Uuid::from_u128(NEXT.fetch_add(1, Ordering::Relaxed) as u128)
    }

    fn make_llfree(frames: usize) -> llfree::LLFree<'static> {
        use llfree::{Alloc, Classing, MetaData};
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

    /// Мок MMAP-бекенда (журнала не нужен: корректность отображений
    /// проверяет фасад своими записями).
    #[derive(Clone)]
    struct MockMmap;

    impl crate::hal::traits::mmap::MMAPInterface for MockMmap {
        fn extend_region(
            &mut self,
            _alloc: &llfree::LLFree<'static>,
            _vaddr: VirtualADDR,
            paddr: crate::hal::traits::mmap::PhysADDR,
            pages: usize,
            _flags: MMAPMemoryFlags,
        ) -> Result<crate::hal::traits::mmap::PageInfo, crate::hal::traits::mmap::MemErrorCode>
        {
            Ok(crate::hal::traits::mmap::PageInfo::new(paddr, pages))
        }

        fn shrink_region(
            &mut self,
            _alloc: &llfree::LLFree<'static>,
            _vaddr: VirtualADDR,
            _pages: usize,
        ) -> Result<(), crate::hal::traits::mmap::MemErrorCode> {
            Ok(())
        }
    }

    struct Fixture {
        tasks: &'static TcbManager,
        caps: &'static CapabilityManager,
        shm: &'static ShmManager,
        reg: &'static SyscallRegistry,
        mm: &'static MemoryManager<MockMmap, crate::mem::ARCPool>,
        task: TaskId,
        /// Вторая задача с фасадом @ 0x2000_0000 (получатель transfer).
        peer: TaskId,
    }

    fn fixture() -> Fixture {
        let tasks: &'static TcbManager =
            alloc::boxed::Box::leak(alloc::boxed::Box::new(TcbManager::new().unwrap()));
        let caps: &'static CapabilityManager =
            alloc::boxed::Box::leak(alloc::boxed::Box::new(CapabilityManager::new().unwrap()));
        let p_alloc = install_p_allocator(make_llfree(512));
        let shm: &'static ShmManager =
            alloc::boxed::Box::leak(alloc::boxed::Box::new(ShmManager::new(p_alloc.clone())));
        // Менеджер — во владении (создание фасадов требует &mut), затем
        // leak: сисколы идут через &self-методы (bind/with_facade).
        let mut mm_box =
            alloc::boxed::Box::new(MemoryManager::<MockMmap, _>::new(p_alloc).unwrap());
        let reg: &'static SyscallRegistry =
            alloc::boxed::Box::leak(alloc::boxed::Box::new(SyscallRegistry::new()));

        reg.register(MemAllocHandler::SYSCALL, &MemAllocHandler)
            .unwrap();
        reg.register(MemFreeHandler::SYSCALL, &MemFreeHandler)
            .unwrap();
        reg.register(MemTransferHandler::SYSCALL, &MemTransferHandler)
            .unwrap();
        reg.register(ShmCreateHandler::SYSCALL, &ShmCreateHandler)
            .unwrap();
        reg.register(ShmSetupRingHandler::SYSCALL, &ShmSetupRingHandler)
            .unwrap();
        reg.register(ShmMapHandler::SYSCALL, &ShmMapHandler)
            .unwrap();
        reg.register(ShmDestroyHandler::SYSCALL, &ShmDestroyHandler)
            .unwrap();
        reg.register(ShmInfoHandler::SYSCALL, &ShmInfoHandler)
            .unwrap();
        reg.register(MemInfoHandler::SYSCALL, &MemInfoHandler)
            .unwrap();

        // Обе задачи и фасады — в ОДНОМ менеджере (как в GCTL: сисколы
        // идут через единственный роутер).
        let task = uuid_next();
        tasks.create(task, TaskPriority::DEFAULT).unwrap();
        let facade = mm_box
            .create_facade(MockMmap, 64, 1, VirtualADDR(0x1000_0000))
            .unwrap();
        mm_box.bind_facade(task, &facade);
        core::mem::forget(facade); // фикстура живёт до конца процесса

        let peer = uuid_next();
        tasks.create(peer, TaskPriority::DEFAULT).unwrap();
        let peer_facade = mm_box
            .create_facade(MockMmap, 64, 1, VirtualADDR(0x2000_0000))
            .unwrap();
        mm_box.bind_facade(peer, &peer_facade);
        core::mem::forget(peer_facade);

        let mm: &'static MemoryManager<MockMmap, crate::mem::ARCPool> =
            alloc::boxed::Box::leak(mm_box);

        Fixture {
            tasks,
            caps,
            shm,
            reg,
            mm,
            task,
            peer,
        }
    }

    /// Диспетчеризация в одной области видимости: роутер — стековая
    /// обёртка над менеджером, живёт ровно на время вызова.
    fn dispatch(f: &Fixture, args: &SyscallArgs) -> crate::syscall::SyscallRet {
        let router = MemRouterImpl::new(f.mm);
        let mut c = SyscallCtx::core(0, f.task, f.tasks, f.caps)
            .with_shm(f.shm)
            .with_memory(&router);
        f.reg.dispatch(&mut c, args)
    }

    fn a(num: SyscallNumber, rest: [usize; 5]) -> SyscallArgs {
        let mut words = [num.as_u64() as usize, 0, 0, 0, 0, 0];
        words[1..].copy_from_slice(&rest);
        SyscallArgs::new(words)
    }

    #[test]
    fn alloc_free_roundtrip() {
        let f = fixture();
        // MEM_ALLOC: 4 страницы RW.
        let vaddr = dispatch(
            &f,
            &a(
                MemAllocHandler::SYSCALL,
                [4, MMAPMemoryFlags::RW.bits() as usize, 0, 0, 0],
            ),
        )
        .unwrap();
        assert_eq!(vaddr, 0x1000_0000); // первый регион фасада — база.

        // MEM_FREE по адресу.
        dispatch(&f, &a(MemFreeHandler::SYSCALL, [vaddr, 0, 0, 0, 0])).unwrap();

        // Повторный free — NotMapped (NotFound).
        assert_eq!(
            dispatch(&f, &a(MemFreeHandler::SYSCALL, [vaddr, 0, 0, 0, 0])),
            Err(SyscallError::NotFound)
        );
    }

    #[test]
    fn shm_full_io_uring_flow() {
        let f = fixture();

        // SHM_CREATE: 2 страницы.
        let id = dispatch(&f, &a(ShmCreateHandler::SYSCALL, [2, 0, 0, 0, 0])).unwrap() as u64;

        // SHM_SETUP_RING: SQ 8, CQ 16, слот 2 слова.
        let sq_off = dispatch(
            &f,
            &a(ShmSetupRingHandler::SYSCALL, [id as usize, 8, 16, 2, 0]),
        )
        .unwrap();
        assert_eq!(sq_off, crate::ipc::shm::RING_HEADER_WORDS);

        // SHM_INFO: слова 3 и 5 — sq_entries и cq_entries.
        let sq_entries =
            dispatch(&f, &a(ShmInfoHandler::SYSCALL, [id as usize, 3, 0, 0, 0])).unwrap();
        let cq_entries =
            dispatch(&f, &a(ShmInfoHandler::SYSCALL, [id as usize, 5, 0, 0, 0])).unwrap();
        assert_eq!(sq_entries, 8);
        assert_eq!(cq_entries, 16);

        // SHM_MAP: отобразить в задачу (zero-copy).
        let vaddr = dispatch(
            &f,
            &a(
                ShmMapHandler::SYSCALL,
                [id as usize, MMAPMemoryFlags::RW.bits() as usize, 0, 0, 0],
            ),
        )
        .unwrap();
        assert_eq!(vaddr, 0x1000_0000);

        // SHM_DESTROY.
        dispatch(
            &f,
            &a(ShmDestroyHandler::SYSCALL, [id as usize, 0, 0, 0, 0]),
        )
        .unwrap();
        assert_eq!(f.shm.count(), 0);
    }

    #[test]
    fn mem_transfer_maps_window_to_peer() {
        let f = fixture();

        // Задача-получатель с собственным фасадом.
        let peer = f.peer;
        assert!(f.mm.has_facade(&peer));

        // Отправитель аллоцирует 4 страницы и передаёт окно получателю.
        let vaddr = dispatch(
            &f,
            &a(
                MemAllocHandler::SYSCALL,
                [4, MMAPMemoryFlags::RW.bits() as usize, 0, 0, 0],
            ),
        )
        .unwrap();
        let pv = peer.as_u128();
        let at = dispatch(
            &f,
            &a(
                MemTransferHandler::SYSCALL,
                [vaddr, 2, 0, pv as usize, (pv >> 64) as usize],
            ),
        )
        .unwrap();
        assert_eq!(at, 0x2000_0000);

        // Map — разделяемое отображение: окно живёт у обоих.
        assert!(
            f.mm.with_facade(&f.task, |fl| fl.region_at(VirtualADDR(vaddr)))
                .is_some()
        );
        assert!(
            f.mm.with_facade(&peer, |fl| fl.region_at(VirtualADDR(at)))
                .is_some()
        );
    }
    #[test]
    fn mem_info_reports_region() {
        let f = fixture();
        // Аллокация 3 страниц RW.
        let vaddr = dispatch(
            &f,
            &a(
                MemAllocHandler::SYSCALL,
                [3, MMAPMemoryFlags::RW.bits() as usize, 0, 0, 0],
            ),
        )
        .unwrap();

        // MEM_INFO: база виртуальная / база физики / страниц.
        let word =
            |i: usize| dispatch(&f, &a(MemInfoHandler::SYSCALL, [vaddr, i, 0, 0, 0])).unwrap();
        let vbase = word(0);
        let pbase = word(1);
        let pages = word(2);
        assert_eq!(vbase, 0x1000_0000, "первый регион задачи");
        assert_eq!(pages, 3);
        // Физика — та же, что отдаёт прямой запрос роутера (пул вправе
        // выдать любой кадр, включая нулевой).
        let direct =
            crate::mem::MemRouter::region_at(&MemRouterImpl::new(f.mm), f.task, VirtualADDR(vaddr));
        assert_eq!(
            direct,
            Some((
                VirtualADDR(vbase),
                crate::hal::traits::mmap::PhysADDR(pbase),
                3
            ))
        );

        // Адрес внутри региона — тот же регион (окно flexpage).
        let inside = word_at(&f, vaddr + 0x1000);
        assert_eq!(inside, vbase);
        fn word_at(f: &Fixture, addr: usize) -> usize {
            dispatch(&f, &a(MemInfoHandler::SYSCALL, [addr, 0, 0, 0, 0])).unwrap()
        }

        // Адрес вне регионов — ENOENT; индекс слов за пределами — EINVAL.
        assert_eq!(
            dispatch(&f, &a(MemInfoHandler::SYSCALL, [0x9000_0000, 0, 0, 0, 0])),
            Err(SyscallError::NotFound)
        );
        assert_eq!(
            dispatch(&f, &a(MemInfoHandler::SYSCALL, [vaddr, 4, 0, 0, 0])),
            Err(SyscallError::InvalidArgument)
        );
    }
}
