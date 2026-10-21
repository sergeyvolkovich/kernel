// ==== IOAPIC-драйвер (v0.11): внешние линии прерываний как L4-сообщения ====
//
// Замыкает IRQ-контур ядра: IrqRouter (kernel) привязывает линию к
// endpoint'у драйвера, а ФИЗИЧЕСКИЙ источник — этот контроллер:
//
//   MADT (тип 1)          контроллер: MMIO 0xFEC0_0000, базовый GSI,
//                         число линий из регистра VER;
//   MADT (тип 2, ISO)     ISA-IRQ -> GSI + триггер/полярность;
//   enable_line           RTE линии (обычный формат), а при включённом
//                         IRQ-ремаппинге IOMMU — IRTE под линией и RTE
//                         в remapped-формате:
//                           * Intel VT-d: IRTE в зарезервированном слоте
//                             0x10+pin (SVT=00b — источника нет), RTE
//                             несёт только handle и триггер (формат
//                             bit40=0, index 55:41 — как у Linux
//                             IR_IO_APIC_route_entry и QEMU
//                             ioapic_entry_parse);
//                           * AMD-Vi: обычный RTE (вектор/назначение),
//                             ремапит IOMMU через IntTab «устройства
//                             IOAPIC» (DTE по IVHD-special/QEMU-инварианту,
//                             индекс IRTE = вектор).
//   вход (asm)            irq_entry_N (по вектору на линию) -> irq_c ->
//                         EOI + BKL + glue.on_external_irq(gsi) ->
//                         IrqRouter кладёт signal-слово в endpoint.
//
// BKL-дисциплина: под замком IF=0, внешний IRQ приходит только из
// user/idle/BKL-спина (глубина 0) — обработчик берёт замок легально;
// пояс безопасности (depth != 0 — нарушение контракта) — событие в
// счётчик потерь, не в панику.

use core::sync::atomic::{AtomicU64, Ordering};

use pkg_generic_interface::hal::traits::iommu::IommuError;
use pkg_generic_interface::hal::traits::irq::IrqLineOps;
use pkg_generic_interface::syscall::io::install_irq_line_service;

use arch::boot;

use crate::iommu::Mmio;

// ───────────────────── Регистры IOAPIC (Intel 82093AA) ─────────────────────

const REG_SEL: u64 = 0x00; // IOREGSEL: селектор регистра
const REG_WIN: u64 = 0x10; // IOWIN: окно чтения/записи (32 бита)
const REG_ID: u32 = 0x00; // идентификатор (id << 24)
const REG_VER: u32 = 0x01; // версия + макс. линию (bits 23:16)
const REG_REDTBL: u32 = 0x10; // IOREDIR: 2 регистра на линию

/// Биты RTE (обычный формат).
const RTE_MASK: u64 = 1 << 16;
const RTE_TRIGGER: u64 = 1 << 15;
const RTE_POLARITY: u64 = 1 << 14; // 1 = active low
#[allow(dead_code)] // asserted in tests; physical mode only
const RTE_DEST_LOGICAL: u64 = 1 << 11;
/// Биты remapped-формата (VT-d): format @40 (0 = remapped), index 55:41.
#[allow(dead_code)] // documented bit position; asserted in tests
const RTE_REMAP_FORMAT: u64 = 1 << 40;

/// Контроллер из MADT (инициализация — один раз в init).
struct IoApic {
    mmio: Mmio,
    /// Базовый GSI линий контроллера.
    gsi_base: u32,
    /// Число линий (регистр VER + 1).
    pins: u32,
}

static IOAPIC: spin::Mutex<Option<IoApic>> = spin::Mutex::new(None);

/// События, потерянные из-за нарушения BKL-контракта (пояс безопасности;
/// рабочий путь их не даёт — счётчик для аудита).
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// Отметить потерянное внешнее событие (аудит irq_c).
pub fn note_dropped() {
    DROPPED.fetch_add(1, Ordering::Relaxed);
}

impl IoApic {
    fn read(&self, sel: u32) -> u32 {
        self.mmio.write32(REG_SEL, sel);
        self.mmio.read32(REG_WIN)
    }

    fn write(&self, sel: u32, v: u32) {
        self.mmio.write32(REG_SEL, sel);
        self.mmio.write32(REG_WIN, v);
    }

    fn rte_read(&self, pin: u32) -> u64 {
        let lo = self.read(REG_REDTBL + 2 * pin) as u64;
        let hi = self.read(REG_REDTBL + 2 * pin + 1) as u64;
        lo | (hi << 32)
    }

    fn rte_write(&self, pin: u32, v: u64) {
        self.write(REG_REDTBL + 2 * pin, v as u32);
        self.write(REG_REDTBL + 2 * pin + 1, (v >> 32) as u32);
    }
}

// ───────────────────── Кодирование RTE (host-тестируемое) ─────────────────────

/// Обычный формат: вектор | режим доставки | назначение | триггер |
/// полярность | маска (сброшена — включаем). Назначение — физический
/// APIC ID (bits 63:56), DM=physical.
pub fn rte_normal(vector: u8, dest: u8, level: bool, active_low: bool) -> u64 {
    (vector as u64)
        | (dest as u64) << 56
        | if level { RTE_TRIGGER } else { 0 }
        | if active_low { RTE_POLARITY } else { 0 }
}

/// Remapped-формат (VT-d): вектор/назначение несёт IRTE; в RTE —
/// триггер/полярность линии, формат (0 = remapped) и handle = индекс
/// IRTE (зарезервированный слот 0x10+pin). Совпадает с раскладкой
/// Linux IR_IO_APIC_route_entry / QEMU ioapic_entry_parse (dest_idx
/// = index<<1 | format из bits 55:40).
pub fn rte_remapped(handle: u16, vector: u8, level: bool, active_low: bool) -> u64 {
    (vector as u64)
        | if level { RTE_TRIGGER } else { 0 }
        | if active_low { RTE_POLARITY } else { 0 }
        // Формат 0 (remapped) — бит 40 в нулях, указываем явно.
        | ((handle as u64 & 0x7FFF) << 41)
        | 0 // RTE_REMAP_FORMAT == 0
}

// ───────────────────── Сервис IrqLineOps ─────────────────────

struct IoApicLines;

impl IrqLineOps for IoApicLines {
    fn enable_line(&self, gsi: u32, level: bool, active_low: bool) -> Result<u8, IommuError> {
        let guard = IOAPIC.lock();
        let Some(io) = guard.as_ref() else {
            return Err(IommuError::IommuNotPresent);
        };
        let pin = match gsi.checked_sub(io.gsi_base) {
            Some(p) if p < io.pins => p,
            _ => return Err(IommuError::InvalidConfig),
        };
        // Флаги линии: ISO (MADT) каноничнее слов ресурса устройства —
        // ISA-источники описаны прошивкой, драйвер может не знать.
        let (level, active_low) = crate::smp::irq_topology()
            .map(|t| t.line_flags(gsi, level, active_low))
            .unwrap_or((level, active_low));
        let vector = boot::VEC_EXTERNAL_BASE + pin as u8;
        // Назначение — BSP (одиночный домен приёма; нагрузка линий — v0.12).
        let dest = crate::smp::lapic_id_of(0);

        // Ремаппинг: Intel приоритетнее (remapped-RTE проверяется
        // эмулятором жёстко), затем AMD (обычный RTE + IRTE по вектору),
        // без IOMMU — обычный RTE.
        let mut mode = "normal";
        let mut handle = 0u16;
        if crate::vtd::irq_remap_enabled() {
            crate::vtd::ioapic_irte(pin as u8, vector, dest, level)?;
            handle = 0x10 + pin as u16;
            mode = "vtd-remapped";
        } else if crate::amd::irq_remap_enabled() {
            crate::amd::ioapic_irte(vector, dest)?;
            mode = "amdvi-remapped";
        }
        let rte = if handle != 0 {
            rte_remapped(handle, vector, level, active_low)
        } else {
            rte_normal(vector, dest, level, active_low)
        };
        io.rte_write(pin, rte);
        crate::kprintln!(
            "ioapic: line gsi={} pin={} vec={:#x} dst={} lvl={} low={} [{}]",
            gsi,
            pin,
            vector,
            dest,
            level,
            active_low,
            mode
        );
        Ok(vector)
    }

    fn disable_line(&self, gsi: u32) -> Result<(), IommuError> {
        let guard = IOAPIC.lock();
        let Some(io) = guard.as_ref() else {
            return Err(IommuError::IommuNotPresent);
        };
        let pin = match gsi.checked_sub(io.gsi_base) {
            Some(p) if p < io.pins => p,
            _ => return Err(IommuError::InvalidConfig),
        };
        // Только маска-бит: конфигурация линии сохраняется (повторный
        // enable_line перепрограммирует её целиком).
        let v = io.rte_read(pin) | RTE_MASK;
        io.rte_write(pin, v);
        crate::kprintln!("ioapic: line gsi={} masked", gsi);
        Ok(())
    }
}

// ───────────────────── Инициализация ─────────────────────

/// Поднять контроллер из MADT-топологии и поставить сервис линий.
///
/// Вызывается платформой (X86Platform::run) после iommu::init_and_install
/// и до release_aps: конкуренции нет, линии к этому моменту замаскированы
/// (сброс IOAPIC) — включение индивидуально через IRQ_ATTACH.
pub fn init() {
    let Some(topo) = crate::smp::irq_topology() else {
        crate::kprintln!("ioapic: no MADT topology — external lines unavailable");
        return;
    };
    let Some(entry) = topo.ioapics[..topo.n_ioapics].iter().flatten().next() else {
        crate::kprintln!("ioapic: no I/O APIC in MADT (QEMU: q35 has one)");
        return;
    };
    let mmio = Mmio::new(entry.phys);
    let ver = {
        mmio.write32(REG_SEL, REG_VER);
        mmio.read32(REG_WIN)
    };
    let id = {
        mmio.write32(REG_SEL, REG_ID);
        mmio.read32(REG_WIN)
    };
    let pins = ((ver >> 16) & 0xFF).max(23) + 1;
    *IOAPIC.lock() = Some(IoApic {
        mmio,
        gsi_base: entry.gsi_base,
        pins,
    });
    crate::kprintln!(
        "ioapic: mmio={:#x} id={} ver={:#x} pins={} gsi_base={} (source overrides: {})",
        entry.phys,
        id >> 24,
        ver & 0xFF,
        pins,
        entry.gsi_base,
        topo.n_isos
    );
    // Сервис линий: IRQ_ATTACH начинает возводить линии платформой.
    install_irq_line_service(&IOAPIC_LINES);
    // Источник демо-линии: COM1 THRE (консоль — поллинг; события линии
    // IRQ4 — драйверу юзерспейса; замаскированная линия их хранит).
    arch::serial::SerialPort::COM1.enable_thre_irq();
}

static IOAPIC_LINES: IoApicLines = IoApicLines;

// ───────────────────── Легаси-шина ISA — УДАЛЕНА в v0.14 ─────────────────────
// «Устройств в ядре нет»: фиксированные ISA-узлы (COM1/PIT) больше не
// перечисляются реестром — acpid в юзерспейсе читает их из ACPI-namespace,
// а ядро лишь медитирует сырые ресурсы за IoResource-cap (порты/линии).
// Консоль ядра (COM1) — собственность boot-консоли (arch::serial), не
// «устройство реестра»; линия IRQ4 внешним драйверам — GSI через MADT-ISO.

// ───────────────────── Host-тесты ─────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rte_normal_encoding() {
        // COM1 (edge/active-high) на BSP: только вектор + dest.
        assert_eq!(rte_normal(0x44, 0, false, false), 0x44);
        // Level/low-линия: биты 15/14.
        assert_eq!(
            rte_normal(0x50, 2, true, true),
            0x50 | 0x8000 | 0x4000 | (2 << 56)
        );
        // Логический режим не используется, маскируем отдельно (disable_line).
        assert_eq!(RTE_DEST_LOGICAL, 1 << 11);
        assert_eq!(RTE_MASK, 1 << 16);
    }

    #[test]
    fn rte_remapped_encoding_matches_linux_qemu() {
        // Раскладка IR_IO_APIC_route_entry: vector 7:0, polarity 14,
        // trigger 15, format 40 (0 = remapped), index 55:41.
        let r = rte_remapped(0x14, 0x44, false, false);
        assert_eq!(r & 0xFF, 0x44);
        assert_eq!((r >> 41) & 0x7FFF, 0x14);
        assert_eq!((r >> 40) & 1, 0, "format bit = remapped");
        assert_eq!(r & 0x8000, 0);
        assert_eq!(r & 0x4000, 0);
        // Level/low переносится в биты линии.
        let r2 = rte_remapped(0x10, 0x52, true, true);
        assert_eq!(r2 & 0x8000, 0x8000);
        assert_eq!(r2 & 0x4000, 0x4000);
        assert_eq!((r2 >> 41) & 0x7FFF, 0x10);
    }

    #[test]
    fn dropped_counter_monotonic() {
        DROPPED.store(0, Ordering::Relaxed);
        note_dropped();
        note_dropped();
        assert_eq!(DROPPED.load(Ordering::Relaxed), 2);
    }
}
