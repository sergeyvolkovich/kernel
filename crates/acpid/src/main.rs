// ==== ACPID: ACPI-менеджер в ЮЗЕРСПЕЙСЕ (v0.14) ====
//
// Самая тяжёлая и рискованная часть ACPI — AML-интерпретатор — живёт
// теперь ЗДЕСЬ, не в ядре (v0.14: реестр устройств и крейт `acpi` из
// ядра удалены). Паника AML убивает acpid, а не ядро.
//
// Дизайн — модель seL4: ядро раздало init ТРИ IoResource-capability
// (физика 0..4 GiB, порты 0..64 KiB, GSI 0..256); init переслал их
// сюда (CAP_MINT). Ядро НЕ знает ни одного устройства: оно лишь
// медитирует сырые диапазоны за capability:
//
//   * MMIO_MAP  — таблицы прошивки (RSDP/XSDT/DSDT/SSDT) мапятся в
//     пространство процесса: acpi::Handler строится поверх сискола;
//   * IOP_IN/OUT — PM1a_EVT/PM1a_CNT (FADT: SystemIO на q35) —
//     фиксированные события ACPI и выключение S5;
//   * IRQ_ATTACH — SCI (FADT sci_interrupt, q35: GSI 9): нажатие
//     кнопки питания прибывает как L4-уведомление в endpoint.
//
// Протокол запуска: init спавнит ЭТОТ образ (TASK_SPAWN_IMAGE, PIE)
// с argv ["acpid", "rsdp=0x..."] — физический адрес RSDP init получил
// от kinit в собственном boot_state (ядро передаёт ФАКТ, не таблицу).
//
// Поток (демо v0.14):
//   1. argv -> rsdp; CAP_LIST -> mmio/io/irq caps;
//   2. AcpiTables::from_rsdp -> AcpiPlatform -> Interpreter (DSDT/SSDT
//      в namespace, БЕЗ initialize_namespace: _INI/_REG не вызываем);
//   3. namespace walk: _HID/_CID/_UID/_ADR/_STA/_CRS каждого устройства —
//      перечисление целиком в юзерспейсе, ядро не участвует;
//   4. FADT: PM1a_EVT/PM1a_CNT, sci_interrupt; \_S5_ -> SLP_TYPa;
//   5. кнопка питания: IRQ_ATTACH(sci) + PWRBTN_EN; ждём событие
//      (таймаут-фолбэк: демо не зависит от нажатия);
//   6. ВЫКЛЮЧЕНИЕ ПК ИЗ ЮЗЕРСПЕЙСА: PM1a_CNT <- SLP_TYPa<<10 | SLP_EN
//      (IOP_OUT за IoPort-cap) — QEMU завершает VM.

#![no_std]
#![no_main]
#![allow(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use core::ffi::CStr;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use acpi::address::AddressSpace;
use acpi::aml::Interpreter;
use acpi::aml::namespace::{AmlName, NamespaceLevelKind};
use acpi::aml::object::Object;
use acpi::aml::resource as amlres;
use acpi::aml::resource::resource_descriptor_list;
use acpi::platform::AcpiPlatform;
use acpi::sdt::fadt::Fadt;
use acpi::{AcpiTables, Handle, Handler, PciAddress, PhysicalMapping};

use userlib::l4_syscall6;

// ───────────────────────── Номера сисколов (nums.rs ядра) ─────────────────────────

const SYS_SYS_TIME: u64 = 0x04;
const SYS_THREAD_YIELD: u64 = 0x1B;
const SYS_CAP_LIST: u64 = 0x25;
const SYS_EP_CREATE: u64 = 0x31;
const SYS_IPC_RECV: u64 = 0x33;
const SYS_IPC_MSG_WORD: u64 = 0x37;
const SYS_MMIO_MAP: u64 = 0x41;
const SYS_IOP_IN: u64 = 0x42;
const SYS_IOP_OUT: u64 = 0x43;
const SYS_IRQ_ATTACH: u64 = 0x46;
const SYS_IRQ_ACK: u64 = 0x48;
const SYS_MEM_ALLOC: u64 = 0x51;
const SYS_MEM_FREE: u64 = 0x52;

/// Флаги IRQ_ATTACH: level + active_low (SCI по спеке — level/low).
const IRQ_LEVEL_LOW: u64 = 0x3;
/// IPC_RECV в try-режиме (без блокировки).
const IPC_TRY: u64 = 0x1;

// ───────────────────────── Консоль ─────────────────────────

/// Строка в консоль (DEBUG_WRITE порциями по 40 байт — через userlib).
fn puts(s: &str) {
    let mut buf = [0u8; 256];
    let n = s.len().min(255);
    buf[..n].copy_from_slice(&s.as_bytes()[..n]);
    userlib::l4_puts(buf.as_ptr() as *const i8);
}

/// Число в консоль с префиксом.
fn puthex(prefix: &str, v: u64) {
    let mut buf = [0u8; 96];
    let n = prefix.len().min(95);
    buf[..n].copy_from_slice(&prefix.as_bytes()[..n]);
    userlib::l4_puthex(buf.as_ptr() as *const i8, v);
}

fn putdec(prefix: &str, v: u64) {
    puthex(prefix, v); // hex достаточно для демо-отчёта
}

// ───────────────────────── Куча (bump over MEM_ALLOC) ─────────────────────────

/// Регион кучи: непрерывный пробег страниц из MEM_ALLOC (лениво; малый
/// размер — большие непрерывные физические пробеги не водятся после
/// бут-фрагментации пула, а куча растёт ДОМИКАМИ по мере надобности).
#[derive(Clone, Copy)]
struct HeapRegion {
    base: usize,
    cursor: usize,
    end: usize,
}

/// Страниц в одном регионе кучи (1 МиБ: order 8 — щадящий запрос к
/// физическому пулу, не требует huge-выровненных пробегов).
const HEAP_REGION_PAGES: u64 = 256;
/// Максимум регионов (потолок кучи 8 МиБ — квота спавна 2560+ стр).
const HEAP_REGIONS_MAX: usize = 8;

struct HeapState {
    regions: [HeapRegion; HEAP_REGIONS_MAX],
    count: usize,
}

impl HeapState {
    /// Выделить в существующем регионе или None (курсоры растут вверх).
    fn bump_from(&mut self, size: usize, align: usize) -> Option<usize> {
        for i in 0..self.count {
            let cur = self.regions[i].cursor;
            let aligned = (cur + align - 1) & !(align - 1);
            if let Some(next) = aligned.checked_add(size) {
                if next <= self.regions[i].end {
                    self.regions[i].cursor = next;
                    return Some(aligned);
                }
            }
        }
        None
    }
}

/// Bump-куча поверх регионов фасада (MEM_ALLOC): ленивая инициализация
/// первым alloc-ом, рост по исчерпании региона; dealloc — no-op
/// (утечка до смерти процесса: acpid живёт один «прогон»).
pub struct BumpHeap {
    state: spin::Mutex<HeapState>,
}

#[global_allocator]
static HEAP: BumpHeap = BumpHeap {
    state: spin::Mutex::new(HeapState {
        regions: [HeapRegion {
            base: 0,
            cursor: 0,
            end: 0,
        }; HEAP_REGIONS_MAX],
        count: 0,
    }),
};

unsafe impl core::alloc::GlobalAlloc for BumpHeap {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let size = layout.size();
        let align = layout.align().max(16);
        if size == 0 {
            return core::ptr::null_mut();
        }
        let mut st = self.state.lock();
        // 1) Сначала — место в существующих регионах.
        if let Some(p) = st.bump_from(size, align) {
            return p as *mut u8;
        }
        // 2) Новый регион (MEM_ALLOC отказ — честный null: аллокатор
        // рантайма превратит его в панику/abort acpid, не ядра).
        if st.count < HEAP_REGIONS_MAX {
            let v = l4_syscall6(SYS_MEM_ALLOC, HEAP_REGION_PAGES, 0x3, 0, 0, 0, 0);
            if v > 0 {
                let base = v as usize;
                let end = base + ((HEAP_REGION_PAGES as usize) << 12);
                let idx = st.count;
                st.regions[idx] = HeapRegion {
                    base,
                    cursor: base,
                    end,
                };
                st.count += 1;
                if let Some(p) = st.bump_from(size, align) {
                    return p as *mut u8;
                }
            } else {
                puthex("acpid: FATAL heap MEM_ALLOC ret = ", v as u64);
            }
        }
        core::ptr::null_mut()
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {
        // no-op: bump-куча без освобождения (потолок — квота страниц).
    }
}

// ───────────────────────── IoResource-капы ─────────────────────────

/// Найденные IoResource-хендлы (гранты init, пересланные сюда).
struct Caps {
    /// IoResource(Mmio): физика 0..4 GiB (kinit-грант init).
    mmio: u64,
    /// IoResource(IoPort): порты 0..64 KiB.
    io: u64,
    /// IoResource(Irq): линии 0..256.
    irq: u64,
}

/// Обход cspace: kinds 6/7/8 -> mmio/io/irq (не найдено — 0).
fn find_caps() -> Option<Caps> {
    let n = unsafe { l4_syscall6(SYS_CAP_LIST, 0, 0, 0, 0, 0, 0) };
    if n <= 0 {
        return None;
    }
    let mut c = Caps {
        mmio: 0,
        io: 0,
        irq: 0,
    };
    let mut idx = 1u64;
    let mut found = 0u32;
    for _ in 0..n {
        // CAP_LIST: ПО ДВА слова на слот ([idx] = handle, [idx+1] = kind).
        let handle = unsafe { l4_syscall6(SYS_CAP_LIST, idx, 0, 0, 0, 0, 0) } as u64;
        let kind = unsafe { l4_syscall6(SYS_CAP_LIST, idx + 1, 0, 0, 0, 0, 0) } as u64;
        match kind {
            6 if c.mmio == 0 => {
                c.mmio = handle;
                found += 1;
            }
            7 if c.io == 0 => {
                c.io = handle;
                found += 1;
            }
            8 if c.irq == 0 => {
                c.irq = handle;
                found += 1;
            }
            _ => {}
        }
        idx += 2;
    }
    (found == 3).then_some(c)
}

// ───────────────────────── acpi::Handler поверх MMIO_MAP ─────────────────────────

/// Обработчик физики крейта `acpi`: карты таблиц через MMIO_MAP за
/// IoResource(Mmio)-cap. Идентичен интерфейсу физмапа, которым ядро
/// пользовалось до v0.14 — только теперь в юзерспейсе.
/// Живой мапинг страницы (refcount): acpi-крейт держит ПЕРЕКРЫВАЮЩИЕСЯ
/// PhysicalMapping одной физики (заголовок таблицы + полная таблица) и
/// роняет их в произвольном порядке — кэш даёт каждой копии ссылку на
/// ОДИН kernel-мапинг (MMIO_MAP один, снятие по нулевому refs).
struct LiveMapping {
    /// Виртуальная база страницы (то, что вернул MMIO_MAP).
    vaddr_page: usize,
    /// Физическая база страницы.
    page_phys: usize,
    /// Размер мапинга, страниц.
    pages: usize,
    /// Живые ссылки (PhysicalMapping, построенные поверх).
    refs: usize,
}

#[derive(Clone)]
struct AcpidHandler {
    /// IoResource(Mmio): физика (мапинг таблиц и op-region SystemMemory).
    mmio_cap: u64,
    /// IoResource(IoPort): порты (op-region SystemIO + PCI CF8/CFC).
    io_cap: u64,
    /// Кэш живых мапингов (общий для клонов хендлера: acpi хранит копию
    /// в каждой PhysicalMapping; процесс однопоточен — spin от acpi-крейта).
    cache: alloc::sync::Arc<spin::Mutex<alloc::vec::Vec<LiveMapping>>>,
}

impl AcpidHandler {
    /// Смещение порта от базы cap (база init-гранта = 0) — единственный
    /// контакт с ABI: весь доступ медитирован ядром.
    #[inline]
    fn iop_in(&self, port: u16, width: u8) -> u32 {
        let r = unsafe { l4_syscall6(SYS_IOP_IN, self.io_cap, port as u64, width as u64, 0, 0, 0) };
        if r < 0 {
            panic!("acpid: IOP_IN refused for port {port:#x}");
        }
        r as u32
    }

    #[inline]
    fn iop_out(&self, port: u16, width: u8, value: u32) {
        let r = unsafe {
            l4_syscall6(
                SYS_IOP_OUT,
                self.io_cap,
                port as u64,
                width as u64,
                value as u64,
                0,
                0,
            )
        };
        if r != 0 {
            panic!("acpid: IOP_OUT refused for port {port:#x}");
        }
    }

    /// PCI config (CF8/CFC) — та же механика, что у любого юзерспейс-
    /// драйвера PCI: порты выданы IoPort-cap, ядро про PCI не знает.
    #[inline]
    fn pci_config(
        &self,
        address: PciAddress,
        offset: u16,
        is_read: bool,
        width: u8,
        value: u32,
    ) -> u32 {
        let addr = 0x8000_0000u32
            | ((address.bus() as u32) << 16)
            | ((address.device() as u32) << 11)
            | ((address.function() as u32) << 8)
            | ((offset & 0xFC) as u32);
        self.iop_out(0xCF8, 4, addr);
        let data_port = 0xCFC + (offset & 3) as u16;
        if is_read {
            self.iop_in(data_port, width)
        } else {
            self.iop_out(data_port, width, value);
            0
        }
    }

    /// MMIO-доступ op-region SystemMemory: PhysicalMapping поверх кэша
    /// (refcount) -> volatile -> drop (unmap = decrement). AML читает
    /// op-regions порциями — кэш экономит MMIO_MAP/MEM_FREE на каждый чих.
    fn mmio_access(&self, address: usize, width: u8, is_read: bool, value: u64) -> u64 {
        let region: PhysicalMapping<Self, u8> = unsafe { self.map_physical_region(address, 8) };
        let ptr = region.virtual_start.as_ptr();
        let out = if is_read {
            unsafe {
                match width {
                    1 => ptr.read_volatile() as u64,
                    2 => (ptr as *const u16).read_volatile() as u64,
                    4 => (ptr as *const u32).read_volatile() as u64,
                    _ => (ptr as *const u64).read_volatile(),
                }
            }
        } else {
            unsafe {
                match width {
                    1 => ptr.write_volatile(value as u8),
                    2 => (ptr as *mut u16).write_volatile(value as u16),
                    4 => (ptr as *mut u32).write_volatile(value as u32),
                    _ => (ptr as *mut u64).write_volatile(value),
                }
            }
            0
        };
        drop(region); // unmap_physical_region: refcount кэша
        out
    }
}

impl Handler for AcpidHandler {
    unsafe fn map_physical_region<T>(
        &self,
        physical_address: usize,
        size: usize,
    ) -> PhysicalMapping<Self, T> {
        // Геометрия: MMIO_MAP байто-точен (возврат указывает на
        // physical_address); страницы = ceil((rem+size)/4K).
        let rem = physical_address & 0xFFF;
        let pages = (rem + size + 0xFFF) >> 12;
        let page_phys = physical_address - rem;

        // Кэш: перекрывающий мапинг страницы уже жив — добавить ссылку.
        {
            let mut cache = self.cache.lock();
            if let Some(e) = cache
                .iter_mut()
                .find(|e| e.page_phys == page_phys && e.pages >= pages)
            {
                e.refs += 1;
                let v = e.vaddr_page + rem;
                return PhysicalMapping {
                    physical_start: physical_address,
                    virtual_start: NonNull::new_unchecked(v as *mut T),
                    region_length: size,
                    mapped_length: e.pages << 12,
                    handler: self.clone(),
                };
            }
        }

        let vaddr = l4_syscall6(
            SYS_MMIO_MAP,
            self.mmio_cap,
            page_phys as u64,
            pages as u64,
            0,
            0,
            0,
        );
        if vaddr <= 0 {
            // Отказ маппинга не переживается: таблица обязана читаться
            // (kinit-грант покрывает 0..4 GiB). Паника userlib глушит
            // сообщение — печатаем сами и выходим с кодом 0xAC.
            puthex("acpid: FATAL MMIO_MAP phys = ", page_phys as u64);
            puthex("acpid: FATAL MMIO_MAP ret   = ", vaddr as u64);
            userlib::l4_task_exit(0xAC);
        }
        self.cache.lock().push(LiveMapping {
            vaddr_page: vaddr as usize,
            page_phys,
            pages,
            refs: 1,
        });
        PhysicalMapping {
            physical_start: physical_address,
            virtual_start: NonNull::new_unchecked((vaddr as usize + rem) as *mut T),
            region_length: size,
            mapped_length: pages << 12,
            handler: self.clone(),
        }
    }

    fn unmap_physical_region<T>(region: &PhysicalMapping<Self, T>) {
        // Refcount: одна страница может стоять под несколькими
        // PhysicalMapping — MEM_FREE только по последней ссылке.
        let lead = region.physical_start & 0xFFF;
        let vaddr_page = region.virtual_start.as_ptr() as usize - lead;
        let handler = region.handler.clone();
        let mut cache = handler.cache.lock();
        if let Some(i) = cache.iter().position(|e| e.vaddr_page == vaddr_page) {
            cache[i].refs -= 1;
            if cache[i].refs == 0 {
                cache.swap_remove(i);
                let _ = unsafe { l4_syscall6(SYS_MEM_FREE, vaddr_page as u64, 0, 0, 0, 0, 0) };
            }
        }
        // Промах — no-op: перекрывающие снапшоты могли быть заменены
        // большим мапингом той же страницы (снятие уже прошло).
    }

    // ==== op-region SystemMemory: MMIO за Mmio-cap ====

    fn read_u8(&self, address: usize) -> u8 {
        self.mmio_access(address, 1, true, 0) as u8
    }
    fn read_u16(&self, address: usize) -> u16 {
        self.mmio_access(address, 2, true, 0) as u16
    }
    fn read_u32(&self, address: usize) -> u32 {
        self.mmio_access(address, 4, true, 0) as u32
    }
    fn read_u64(&self, address: usize) -> u64 {
        self.mmio_access(address, 8, true, 0)
    }
    fn write_u8(&self, address: usize, value: u8) {
        self.mmio_access(address, 1, false, value as u64);
    }
    fn write_u16(&self, address: usize, value: u16) {
        self.mmio_access(address, 2, false, value as u64);
    }
    fn write_u32(&self, address: usize, value: u32) {
        self.mmio_access(address, 4, false, value as u64);
    }
    fn write_u64(&self, address: usize, value: u64) {
        self.mmio_access(address, 8, false, value);
    }

    // ==== op-region SystemIO: порты за IoPort-cap (IOP_IN/OUT) ====

    fn read_io_u8(&self, port: u16) -> u8 {
        self.iop_in(port, 1) as u8
    }
    fn read_io_u16(&self, port: u16) -> u16 {
        self.iop_in(port, 2) as u16
    }
    fn read_io_u32(&self, port: u16) -> u32 {
        self.iop_in(port, 4)
    }
    fn write_io_u8(&self, port: u16, value: u8) {
        self.iop_out(port, 1, value as u32);
    }
    fn write_io_u16(&self, port: u16, value: u16) {
        self.iop_out(port, 2, value as u32);
    }
    fn write_io_u32(&self, port: u16, value: u32) {
        self.iop_out(port, 4, value);
    }

    // ==== op-region PCIConfig: CF8/CFC за IoPort-cap ====

    fn read_pci_u8(&self, address: PciAddress, offset: u16) -> u8 {
        self.pci_config(address, offset, true, 1, 0) as u8
    }
    fn read_pci_u16(&self, address: PciAddress, offset: u16) -> u16 {
        self.pci_config(address, offset, true, 2, 0) as u16
    }
    fn read_pci_u32(&self, address: PciAddress, offset: u16) -> u32 {
        self.pci_config(address, offset, true, 4, 0)
    }
    fn write_pci_u8(&self, address: PciAddress, offset: u16, value: u8) {
        self.pci_config(address, offset, false, 1, value as u32);
    }
    fn write_pci_u16(&self, address: PciAddress, offset: u16, value: u16) {
        self.pci_config(address, offset, false, 2, value as u32);
    }
    fn write_pci_u32(&self, address: PciAddress, offset: u16, value: u32) {
        self.pci_config(address, offset, false, 4, value);
    }

    // ==== время (LAPIC TimeSource ядра: SYS_TIME = наносекунды) ====

    fn nanos_since_boot(&self) -> u64 {
        unsafe { l4_syscall6(SYS_SYS_TIME, 0, 0, 0, 0, 0, 0) as u64 }
    }

    fn stall(&self, microseconds: u64) {
        // Спека: без отдачи процессора, короткие (<100 мкс) задержки.
        let until = self.nanos_since_boot() + microseconds * 1000;
        while self.nanos_since_boot() < until {
            core::hint::spin_loop();
        }
    }

    fn sleep(&self, milliseconds: u64) {
        // Отдаём процессор (THREAD_YIELD) до дедлайна.
        let until = self.nanos_since_boot() + milliseconds * 1_000_000;
        while self.nanos_since_boot() < until {
            let _ = unsafe { l4_syscall6(SYS_THREAD_YIELD, 0, 0, 0, 0, 0, 0) };
        }
    }

    // ==== AML-мьютексы: acpid однопоточен — тривиальная реализация ====

    fn create_mutex(&self) -> Handle {
        Handle(1)
    }

    fn acquire(&self, _mutex: Handle, _timeout: u16) -> Result<(), acpi::aml::AmlError> {
        Ok(())
    }

    fn release(&self, _mutex: Handle) {}
}

// ───────────────────────── AML: перечисление устройств ─────────────────────────

/// Расжать числовой EisaId в "PNPxxxx" (кодирование ACPI: буквы по 5 бит).
fn eisa_id_to_string(raw: u64) -> Option<String> {
    let letter = |bits: u64| -> Option<char> {
        let b = bits as u8;
        if (1..=26).contains(&b) {
            Some((b - 1 + b'A') as char)
        } else {
            None
        }
    };
    let digits = raw & 0xFFFF;
    Some(format!(
        "{}{}{}{:04X}",
        letter((raw >> 26) & 0x1F)?,
        letter((raw >> 21) & 0x1F)?,
        letter((raw >> 16) & 0x1F)?,
        digits
    ))
}

/// Сводка одного устройства namespace (снимок для отчёта).
struct DevSummary {
    path: String,
    hid: Option<String>,
    sta: Option<u32>,
    /// Ресурсы _CRS: (mmio_base, mmio_len) / (io_base, io_len) / gsi.
    mmio: Vec<(u64, u64)>,
    io: Vec<(u64, u64)>,
    irqs: Vec<u32>,
}

/// Walk: traverse читает только структуру дерева; методы (_HID/_CRS)
/// вычисляются «по требованию» ниже — ВЕСЬ AML исполняется в ЭТОМ
/// процессе, ядро не участвует.
fn collect_device_paths(interp: &Interpreter<AcpidHandler>) -> Vec<String> {
    let mut paths = Vec::new();
    let mut ns = interp.namespace.lock();
    let _ = ns.traverse(|name, level| {
        if level.kind == NamespaceLevelKind::Device {
            paths.push(name.as_string());
        }
        Ok(true)
    });
    paths
}

fn eval(
    interp: &Interpreter<AcpidHandler>,
    path: &str,
    method: &str,
) -> Option<acpi::aml::object::WrappedObject> {
    let name: AmlName = format!("{path}.{method}").parse().ok()?;
    interp.evaluate_if_present(name, Vec::new()).ok().flatten()
}

fn eval_integer(interp: &Interpreter<AcpidHandler>, path: &str, m: &str) -> Option<u64> {
    match &*eval(interp, path, m)? {
        Object::Integer(v) => Some(*v),
        _ => None,
    }
}

fn eval_hid(interp: &Interpreter<AcpidHandler>, path: &str) -> Option<String> {
    match &*eval(interp, path, "_HID")? {
        Object::String(s) => Some(s.clone()),
        Object::Integer(eisa) => eisa_id_to_string(*eisa),
        _ => None,
    }
}

fn probe_device(interp: &Interpreter<AcpidHandler>, path: &str) -> Option<DevSummary> {
    let hid = eval_hid(interp, path);
    // Контейнеры/мосты без _HID/_CID — не «устройства» для демо-отчёта.
    hid.as_ref()?;
    let mut s = DevSummary {
        path: String::from(path),
        hid,
        sta: eval_integer(interp, path, "_STA").map(|v| v as u32),
        mmio: Vec::new(),
        io: Vec::new(),
        irqs: Vec::new(),
    };
    if let Some(obj) = eval(interp, path, "_CRS") {
        if let Ok(list) = resource_descriptor_list(obj) {
            for r in list {
                match r {
                    amlres::Resource::AddressSpace(d) => match d.resource_type {
                        amlres::AddressSpaceResourceType::MemoryRange => {
                            s.mmio.push((d.address_range.0, d.length));
                        }
                        amlres::AddressSpaceResourceType::IORange => {
                            s.io.push((d.address_range.0, d.length));
                        }
                        _ => {}
                    },
                    amlres::Resource::MemoryRange(
                        amlres::MemoryRangeDescriptor::FixedLocation {
                            base_address,
                            range_length,
                            ..
                        },
                    ) => s.mmio.push((base_address as u64, range_length as u64)),
                    amlres::Resource::IOPort(d) => {
                        s.io.push((d.memory_range.0 as u64, d.range_length as u64))
                    }
                    amlres::Resource::Irq(d) => s.irqs.push(d.irq),
                    _ => {}
                }
            }
        }
    }
    Some(s)
}

// ───────────────────────── FADT/PM: выключение и события ─────────────────────────

/// Ключевые поля FADT для менеджера (SystemIO на q35).
struct PmInfo {
    /// SCI: GSI фиксированного события.
    sci: u16,
    /// PM1a_EVT (SystemIO): статус/enable кнопки питания.
    evt: u64,
    /// Смещение enable-регистра внутри EVT-блока (PM1_EVT_LEN / 2).
    en_off: u64,
    /// PM1a_CNT (SystemIO): SLP_TYP/SLP_EN.
    cnt: u64,
    /// Регистры в пространстве портов (true) — иначе MMIO (q35: true).
    system_io: bool,
}

/// SLP_TYPa для S5 из пакета \_S5_ (Integer [a, b]).
fn s5_slp_typa(interp: &Interpreter<AcpidHandler>) -> Option<u64> {
    let name: AmlName = "\\_S5_".parse().ok()?;
    let obj = interp.evaluate(name, Vec::new()).ok()?;
    match &*obj {
        Object::Package(items) => match items.first().map(|w| &**w) {
            Some(Object::Integer(v)) => Some(*v),
            _ => None,
        },
        _ => None,
    }
}

// ───────────────────────── main ─────────────────────────

/// main: L4-старт (argc/argv от init: ["acpid", "rsdp=0x..."]).
fn acpid_main(argc: i32, argv: *const *const i8) -> i32 {
    puts("=== acpid: userspace ACPI manager (AML out of kernel, v0.14) ===");

    // 1. rsdp из argv.
    let mut rsdp: Option<u64> = None;
    for i in 0..argc as usize {
        let p = unsafe { *argv.add(i) };
        let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap_or("");
        if let Some(hex) = s.strip_prefix("rsdp=0x") {
            rsdp = u64::from_str_radix(hex, 16).ok();
        }
    }
    let Some(rsdp) = rsdp else {
        puts("acpid: no rsdp= in argv (kinit->init transit broken?) — exit");
        return 1;
    };
    puthex("acpid: rsdp phys = ", rsdp);

    // 2. IoResource-капы (гранты init через CAP_MINT).
    let Some(caps) = find_caps() else {
        puts("acpid: IoResource caps missing (init grant?) — exit");
        return 1;
    };
    puts("acpid: IoResource caps found (mmio/io/irq)");

    // 3. Таблицы + интерпретатор (весь AML — здесь, не в ядре).
    let handler = AcpidHandler {
        mmio_cap: caps.mmio,
        io_cap: caps.io,
        cache: alloc::sync::Arc::new(spin::Mutex::new(alloc::vec::Vec::new())),
    };
    puts("acpid: AcpiTables::from_rsdp...");
    let tables = match unsafe { AcpiTables::from_rsdp(handler.clone(), rsdp as usize) } {
        Ok(t) => t,
        Err(e) => {
            puts(&format!("acpid: AcpiTables::from_rsdp failed: {e:?}"));
            return 1;
        }
    };
    let platform = match AcpiPlatform::new(tables, handler.clone()) {
        Ok(p) => p,
        Err(e) => {
            puts(&format!("acpid: AcpiPlatform::new failed: {e:?}"));
            return 1;
        }
    };
    let interp = match Interpreter::new_from_platform(&platform) {
        Ok(i) => i,
        Err(e) => {
            puts(&format!("acpid: AML interpreter init failed: {e:?}"));
            return 1;
        }
    };
    puts("acpid: tables+platform+interpreter up");
    puts("acpid: DSDT/SSDT loaded into namespace (userspace AML)");

    // 4. Перечисление: namespace walk (только юзерспейс).
    let paths = collect_device_paths(&interp);
    putdec("acpid: namespace device nodes = ", paths.len() as u64);
    let mut devices = 0u64;
    for path in &paths {
        let Some(s) = probe_device(&interp, path) else {
            continue;
        };
        devices += 1;
        let mut line = format!(
            "acpid: [{}] hid={}",
            s.path,
            s.hid.as_deref().unwrap_or("?")
        );
        if let Some(sta) = s.sta {
            line.push_str(&format!(" sta={sta:#x}"));
        }
        for (b, l) in s.mmio.iter().take(2) {
            line.push_str(&format!(" mmio={b:#x}+{l:#x}"));
        }
        for (b, l) in s.io.iter().take(2) {
            line.push_str(&format!(" io={b:#x}+{l:#x}"));
        }
        for &g in s.irqs.iter().take(2) {
            line.push_str(&format!(" irq={g}"));
        }
        puts(&line);
    }
    putdec("acpid: enumerated devices = ", devices);
    puts("acpid: VERDICT: ACPI/AML enumeration done entirely in userspace");

    // 5. FADT: PM-регистры и SCI.
    let fadt = platform
        .tables
        .find_table::<Fadt>()
        .expect("acpid: no FADT");
    let evt = fadt.pm1a_event_block().expect("acpid: no PM1a_EVT");
    let cnt = fadt.pm1a_control_block().expect("acpid: no PM1a_CNT");
    let pm = PmInfo {
        sci: fadt.sci_interrupt,
        evt: evt.address,
        en_off: (fadt.pm1_event_length as u64) / 2,
        cnt: cnt.address,
        system_io: matches!(evt.address_space, AddressSpace::SystemIo),
    };
    puthex("acpid: PM1a_EVT  = ", pm.evt);
    puthex("acpid: PM1a_CNT  = ", pm.cnt);
    putdec("acpid: SCI (GSI) = ", pm.sci as u64);

    let Some(slp_typa) = s5_slp_typa(&interp) else {
        puts("acpid: \\_S5_ package missing — no S5 shutdown");
        return 1;
    };
    puthex("acpid: S5 SLP_TYPa = ", slp_typa);

    // 6. Кнопка питания: SCI-линия за Irq-cap + enable PWRBTN (bit 8).
    let gate = unsafe { l4_syscall6(SYS_EP_CREATE, 4, 0, 0, 0, 0, 0) };
    let mut button_armed = false;
    if gate > 0 {
        let attach = unsafe {
            l4_syscall6(
                SYS_IRQ_ATTACH,
                caps.irq,
                pm.sci as u64,
                gate as u64,
                IRQ_LEVEL_LOW,
                0,
                0,
            )
        };
        if attach == 0 {
            puts("acpid: SCI line attached (power button events -> endpoint)");
            if pm.system_io {
                // PWRBTN_STS (write-1-to-clear) + PWRBTN_EN (bit 8).
                let _ = unsafe { l4_syscall6(SYS_IOP_OUT, caps.io, pm.evt, 2, 1 << 8, 0, 0) };
                let en =
                    unsafe { l4_syscall6(SYS_IOP_IN, caps.io, pm.evt + pm.en_off, 2, 0, 0, 0) };
                let en_val = if en < 0 { 0 } else { en as u64 };
                let _ = unsafe {
                    l4_syscall6(
                        SYS_IOP_OUT,
                        caps.io,
                        pm.evt + pm.en_off,
                        2,
                        (en_val as u64) | (1 << 8),
                        0,
                        0,
                    )
                };
                button_armed = true;
                puts("acpid: PWRBTN_EN set — waiting for power button (L4 signal)");
            }
        } else {
            putdec("acpid: IRQ_ATTACH(sci) ret = ", attach as u64);
        }
    }

    // 7. Ожидание события с таймаут-фолбэком (демо не требует нажатия):
    //    SYS_TIME — наносекунды; окно 8 с.
    let deadline = unsafe { l4_syscall6(SYS_SYS_TIME, 0, 0, 0, 0, 0, 0) } as u64 + 8_000_000_000u64;
    let mut got_button = false;
    loop {
        let r = unsafe { l4_syscall6(SYS_IPC_RECV, gate as u64, IPC_TRY, 0, 0, 0, 0) };
        if r >= 0 {
            let word = unsafe { l4_syscall6(SYS_IPC_MSG_WORD, 0, 0, 0, 0, 0, 0) };
            puthex("acpid: SCI signal word = ", word as u64);
            let _ = unsafe { l4_syscall6(SYS_IRQ_ACK, pm.sci as u64, 0, 0, 0, 0, 0) };
            got_button = true;
            break;
        }
        let now = unsafe { l4_syscall6(SYS_SYS_TIME, 0, 0, 0, 0, 0, 0) };
        if now as u64 >= deadline {
            break;
        }
    }
    if got_button {
        puts("acpid: power button pressed (SCI fixed event)");
    } else if button_armed {
        puts("acpid: no button in window — fallback: self shutdown (S5)");
    }

    // 8. ВЫКЛЮЧЕНИЕ ПК ИЗ ЮЗЕРСПЕЙСА: PM1a_CNT <- SLP_TYPa<<10 | SLP_EN.
    let slp = (slp_typa << 10) | (1 << 13);
    // Диагностика: текущее значение PM1a_CNT (перед S5 он обычно 0).
    if pm.system_io {
        let cur = unsafe { l4_syscall6(SYS_IOP_IN, caps.io, pm.cnt, 2, 0, 0, 0) };
        puthex("acpid: PM1a_CNT now = ", cur as u64);
    }
    puthex("acpid: S5 value = ", slp);
    puts("acpid: writing S5|SLP_EN to PM1a_CNT — PC powers off");
    if pm.system_io {
        let r = unsafe { l4_syscall6(SYS_IOP_OUT, caps.io, pm.cnt, 2, slp, 0, 0) };
        if r != 0 {
            putdec("acpid: IOP_OUT ret = ", r as u64);
        }
    } else {
        // MMIO-режим (не q35): мапим регистр и пишем напрямую.
        let v = unsafe { l4_syscall6(SYS_MMIO_MAP, caps.mmio, pm.cnt, 1, 0, 0, 0) };
        if v > 0 {
            let p = v as usize as *mut u16;
            unsafe { p.write_volatile(slp as u16) };
        }
    }
    // Дошли сюда — прошивка не выключила (нет PM или QEMU-особенность).
    puts("acpid: shutdown write done; if you see this, firmware ignored S5");
    0
}

// ───────────────────────── Entry ─────────────────────────

// userlib::_start принимает стартовый IPC и зовёт ЭТОТ main; возврат
// из main завершает домен через TASK_EXIT (userlib).
#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const i8) -> i32 {
    acpid_main(argc, argv)
}
