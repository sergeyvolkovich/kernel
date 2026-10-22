// ==== perf: measured IPC -> per-CPU capacity + per-task speedup (v0.19) ====
//
// Feeds the load balancer's heterogeneity inputs from MEASURED
// instruction throughput instead of hardcoded symmetry:
//
//   * `CAP_Q8[cpu]`  — fleet-normalized capacity (256 = the fastest
//     core class). Consumed by steal admission (sched_lb `CoreView`)
//     and the per-task `speedup_q8` classification;
//   * `IPC_Q8[cpu]`  — aggregate per-core IPC EWMA (Q8: 256 = IPC 1.0),
//     the raw signal the normalization comes from.
//
// Two sampling modes, decided once at boot and self-validated:
//
//   * HW — architectural PMU fixed counters (instructions retired +
//     unhalted core cycles) via RDPMC. Enabled when CPUID 0xA reports
//     >= 2 fixed counters; validated by making the counters advance
//     across a bench spin, downgraded to SW on failure. KVM with
//     pmu=on and real hardware run here; unhalted-cycle counting
//     excludes halt time by construction;
//   * SW — TSC only (QEMU TCG reports no PMU, so the rig runs here).
//     Per-CPU capacity is boot-calibrated with a fixed-instruction
//     microbench (4 instructions per iteration); the segment "IPC"
//     then derives from TSC deltas. That makes the estimate the CORE's
//     class rate — task-agnostic, but honest about cross-core rate
//     differences (which is exactly what admission needs).
//
// Sampling happens ONLY at dispatch-segment boundaries (park/charge in
// the balancer): two RDPMC (~40 cycles) or one RDTSC ride along on a
// path that already touches the queues. No lock is held and none is
// taken here: the owner state follows the lb.rs per-CPU discipline,
// cross-CPU readers get the lock-free mirrors.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

use raw_cpuid::CpuId;

use crate::lapic;
use crate::smp::MAX_CPUS;

/// Aggregate IPC EWMA per CPU, Q8 (256 = IPC 1.0). Lock-free mirror.
pub static IPC_Q8: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];

/// Fleet-normalized capacity per CPU, Q8 (256 = the fastest core class).
/// Starts neutral (256 everywhere) until the first samples arrive, so
/// pre-measurement admission behaves exactly like v0.18.
pub static CAP_Q8: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(256) }; MAX_CPUS];

/// Fixed-counter width (HW mode), probed once; 0 until then.
static CTR_WIDTH: AtomicU32 = AtomicU32::new(0);

/// Sampling mode (decided by the BSP probe, inherited by the APs).
const MODE_UNDEF: u8 = 0;
const MODE_HW: u8 = 1;
const MODE_SW: u8 = 2;
static MODE: AtomicU8 = AtomicU8::new(MODE_UNDEF);

// ───────────────────────── Per-CPU owner state ─────────────────────────

/// Owner-only state (the lb.rs per-CPU discipline: only the owning core
/// touches its element, at park boundaries; readers use the mirrors).
struct PerfState {
    hw: bool,
    ctr_width: u32,
    last_instr: u64,
    last_cycles: u64,
    last_tsc: u64,
    /// SW calibration: TSC ticks per 1000 instructions of the bench mix
    /// (0 = uncalibrated: samples are impossible, everything degrades).
    tsc_per_kinstr: u64,
    /// Aggregate IPC EWMA (mirrored into IPC_Q8).
    agg_ipc_q8: u32,
}

impl PerfState {
    const fn new() -> Self {
        Self {
            hw: false,
            ctr_width: 0,
            last_instr: 0,
            last_cycles: 0,
            last_tsc: 0,
            tsc_per_kinstr: 0,
            agg_ipc_q8: 0,
        }
    }
}

#[repr(align(64))]
struct PerfCpu {
    st: UnsafeCell<PerfState>,
}

// SAFETY: per-CPU discipline — only the owning core writes its element
// (park boundaries); cross-CPU traffic goes through the atomics above.
unsafe impl Sync for PerfCpu {}

static PERF: [PerfCpu; MAX_CPUS] =
    [const { PerfCpu { st: UnsafeCell::new(PerfState::new()) } }; MAX_CPUS];

#[inline]
fn owner(cpu: usize) -> &'static mut PerfState {
    // SAFETY: owner-cpu access (discipline above); `cpu % MAX_CPUS`
    // bounds the index the same way lb.rs does.
    unsafe { &mut *PERF[cpu % MAX_CPUS].st.get() }
}

// ───────────────────────── Raw x86 access ─────────────────────────

const MSR_FIXED_CTR_CTRL: u32 = 0x38D;
const MSR_PERF_GLOBAL_CTRL: u32 = 0x38F;

#[inline]
fn rdpmc(idx: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: privileged context (kernel, IF=0 paths); the caller has
    // validated that the PMU exists (no #GP on this CPU).
    unsafe {
        core::arch::asm!(
            "rdpmc",
            in("ecx") idx,
            lateout("eax") lo,
            lateout("edx") hi,
            options(nomem, nostack)
        );
    }
    ((hi as u64) << 32) | lo as u64
}

#[inline]
fn wrmsr(msr: u32, val: u64) {
    // SAFETY: privileged context; only invoked for MSRs the probe has
    // confirmed to exist on this CPU.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") val as u32,
            in("edx") (val >> 32) as u32,
            options(nomem)
        );
    }
}

/// Fixed-instruction microbench for the SW calibration (and the HW
/// validation spin): 4 instructions per iteration — two dependent
/// adds, a counter decrement, the loop branch. The absolute number is
/// irrelevant; only the cross-CPU ratio matters.
const BENCH_ITERS: u64 = 1 << 20; // ~4M instructions, 1-3 ms under TCG
const BENCH_INSTR_PER_ITER: u64 = 4;

#[inline]
fn bench_spin() {
    // SAFETY: self-contained register play, no memory effects.
    unsafe {
        core::arch::asm!(
            "mov ecx, {n}",
            "2:",
            "add eax, eax",
            "add eax, eax",
            "sub ecx, 1",
            "jnz 2b",
            n = const BENCH_ITERS,
            out("eax") _,
            out("ecx") _,
            options(nomem, nostack)
        );
    }
}

// ───────────────────────── Bring-up ─────────────────────────

/// Bring perf up on one cpu (cpu::bsp_init / ap_init). The BSP runs the
/// mode probe exactly once — before smp::bring_up starts the APs — so
/// every AP inherits the decided mode; each cpu then calibrates itself
/// (its own TSC/instruction rate) and, in HW mode, enables and
/// self-validates its fixed counters.
pub fn cpu_up(cpu: usize) {
    if cpu == 0 && MODE.load(Ordering::Acquire) == MODE_UNDEF {
        let mut mode = MODE_SW;
        if let Some(pmi) = CpuId::new().get_performance_monitoring_info() {
            if pmi.version_id() > 0 && pmi.fixed_function_counters() >= 2 {
                mode = MODE_HW;
                let w = pmi.fixed_function_counters_bit_width();
                // 24 is the floor: 0-width would make wrap math nonsense.
                CTR_WIDTH.store(w.max(24) as u32, Ordering::Relaxed);
            }
        }
        MODE.store(mode, Ordering::Release);
    }
    let mode = MODE.load(Ordering::Acquire);
    let o = owner(cpu);

    // SW calibration: run twice, keep the second (warm caches/btb).
    let _warm = bench_once();
    let dt = bench_once();
    o.tsc_per_kinstr = if dt > 0 {
        // TSC ticks per 1000 instructions of the bench mix.
        (dt.saturating_mul(1000)) / (BENCH_ITERS * BENCH_INSTR_PER_ITER)
    } else {
        0
    };

    // HW: enable both fixed counters (ring0-only events), snapshot,
    // validate across another spin; downgrade on any anomaly.
    o.hw = false;
    if mode == MODE_HW {
        wrmsr(MSR_FIXED_CTR_CTRL, 0x11); // ctr0/ctr1: count OS (ring0) only
        wrmsr(MSR_PERF_GLOBAL_CTRL, (1u64 << 32) | (1u64 << 33));
        o.ctr_width = CTR_WIDTH.load(Ordering::Relaxed).clamp(24, 48);
        o.last_instr = rdpmc(0x4000_0000);
        o.last_cycles = rdpmc(0x4000_0001);
        o.last_tsc = lapic::read_tsc();
        bench_spin();
        let i = rdpmc(0x4000_0000);
        let c = rdpmc(0x4000_0001);
        let di = i.wrapping_sub(o.last_instr);
        let dc = c.wrapping_sub(o.last_cycles);
        if di > 0 && dc > 0 && di <= dc.saturating_mul(16) {
            o.hw = true; // counters advance plausibly: trust them
        } else {
            wrmsr(MSR_PERF_GLOBAL_CTRL, 0); // frozen/torn emulation: off
        }
    }
    o.last_tsc = lapic::read_tsc();

    if o.hw {
        crate::kprintln!(
            "perf: cpu{} mode=hw-pmu width={} tsc/kinstr={}",
            cpu,
            o.ctr_width,
            o.tsc_per_kinstr
        );
    } else if o.tsc_per_kinstr > 0 {
        crate::kprintln!("perf: cpu{} mode=sw-tsc tsc/kinstr={}", cpu, o.tsc_per_kinstr);
    } else {
        crate::kprintln!("perf: cpu{} mode=sw-tsc UNCALIBRATED (degenerate)", cpu);
    }
}

/// One calibration pass: the TSC cost of the fixed bench mix.
fn bench_once() -> u64 {
    let t0 = lapic::read_tsc();
    bench_spin();
    let t1 = lapic::read_tsc();
    t1.saturating_sub(t0)
}

// ───────────────────────── Sampling ─────────────────────────

/// Close one dispatch segment on `cpu` and sample its IPC. Called at
/// park boundaries ONLY (the balancer's charge/idle paths), never under
/// any lock. Returns the segment IPC (Q8, 256 = 1.0) when the sample is
/// usable — the caller feeds it to the task's entity (`eevdf::note_perf`)
/// together with our current capacity.
///
/// `max_cycles` bounds a sane segment length: in SW mode the TSC runs
/// through halts, so a segment spanning an idle gap is discarded (the
/// clock advances, no sample). HW mode needs no such bound — unhalted
/// counters exclude halt time by construction.
pub fn note_segment(cpu: usize, max_cycles: u64) -> Option<u32> {
    let o = owner(cpu);
    let now = lapic::read_tsc();
    let dt = now.saturating_sub(o.last_tsc);
    let bound = if o.hw { u64::MAX } else { max_cycles };
    let (di, dc) = if o.hw {
        let i = rdpmc(0x4000_0000);
        let c = rdpmc(0x4000_0001);
        let di = wrap_delta(o.last_instr, i, o.ctr_width);
        let dc = wrap_delta(o.last_cycles, c, o.ctr_width);
        o.last_instr = i;
        o.last_cycles = c;
        o.last_tsc = now;
        (di, dc)
    } else if o.tsc_per_kinstr > 0 {
        // SW estimate: instructions ~ tsc-delta scaled by THIS core's
        // calibrated rate; cycles = the tsc delta. The resulting IPC is
        // the core's class rate — task-agnostic by design.
        let di = ((dt as u128 * 1000) / o.tsc_per_kinstr as u128) as u64;
        o.last_tsc = now;
        (di, dt)
    } else {
        o.last_tsc = now;
        return None;
    };
    if dt > bound {
        return None; // post-gap segment (idle/boot): advance, discard
    }
    let sample = ipc_q8_of(di, dc)?;
    o.agg_ipc_q8 = match o.agg_ipc_q8 {
        0 => sample,
        old => ewma4(old, sample),
    };
    IPC_Q8[cpu].store(o.agg_ipc_q8, Ordering::Relaxed);
    refresh_caps();
    Some(sample)
}

// ───────────────────────── Pure helpers (host-testable) ─────────────────────────

/// Counter delta across a width-b wrap (HW counters are 24-48 bit wide
/// while the snapshots are full u64). A "wrap" spanning more than half
/// the counter range is really a reset/reconfigure (torn or reprogrammed
/// counters): reported as zero — the plausibility guard in `ipc_q8_of`
/// drops the sample anyway.
pub fn wrap_delta(last: u64, now: u64, width_bits: u32) -> u64 {
    if now >= last {
        now - last
    } else {
        let wrapped = (1u64 << width_bits).wrapping_sub(last).wrapping_add(now);
        if wrapped > (1u64 << (width_bits - 1)) {
            0
        } else {
            wrapped
        }
    }
}

/// Segment IPC in Q8 (256 = IPC 1.0); `None` when degenerate (zero
/// deltas) or implausible (a torn read — real silicon does not exceed
/// 64 instructions per cycle).
pub fn ipc_q8_of(di: u64, dc: u64) -> Option<u32> {
    if di == 0 || dc == 0 {
        return None;
    }
    if di > dc.saturating_mul(64) {
        return None;
    }
    Some(((di as u128 * 256) / dc as u128) as u32)
}

#[inline]
fn ewma4(old: u32, sample: u32) -> u32 {
    if sample >= old {
        old + ((sample - old) >> 2)
    } else {
        old - ((old - sample) >> 2)
    }
}

/// Recompute the fleet-normalized capacity mirrors from the aggregate
/// IPC mirrors (see [`caps_for`] for the policy).
pub fn refresh_caps() {
    let online = crate::smp::online_mask();
    let mut ipc = [0u32; MAX_CPUS];
    for (cpu, slot) in ipc.iter_mut().enumerate() {
        *slot = IPC_Q8[cpu].load(Ordering::Relaxed);
    }
    let caps = caps_for(&ipc, online);
    for cpu in 0..MAX_CPUS {
        let c = caps[cpu];
        if c != 0 {
            CAP_Q8[cpu].store(c, Ordering::Relaxed);
        }
    }
}

/// Pure normalization policy: the fastest measured ONLINE core class
/// maps to 256 (Q8); an online core with no samples floors at 16 Q8
/// (6% — admission would otherwise lock it out of stealing entirely);
/// offline cores and the nothing-measured case return 0 = "caller keeps
/// the mirror's previous value" (neutral 256 at boot).
pub fn caps_for(ipc: &[u32; MAX_CPUS], online: u64) -> [u32; MAX_CPUS] {
    let mut out = [0u32; MAX_CPUS];
    let mut max = 0u32;
    for cpu in 0..MAX_CPUS {
        if (online >> cpu) & 1 == 0 {
            continue;
        }
        if ipc[cpu] > max {
            max = ipc[cpu];
        }
    }
    if max == 0 {
        return out; // nothing measured: keep the neutral/last caps
    }
    for cpu in 0..MAX_CPUS {
        if (online >> cpu) & 1 == 0 {
            continue;
        }
        let v = ipc[cpu];
        out[cpu] = if v == 0 {
            16
        } else {
            (((v as u64) * 256) / max as u64).max(16) as u32
        };
    }
    out
}

// ───────────────────────── Readers (steal path) ─────────────────────────

/// Current capacity of a cpu, Q8 (256 = the fastest class; neutral 256
/// before any measurement — v0.18-compatible).
#[inline]
pub fn cap_q8(cpu: usize) -> u32 {
    CAP_Q8[cpu % MAX_CPUS].load(Ordering::Relaxed).max(1)
}

/// Current aggregate IPC of a cpu, Q8.
#[inline]
pub fn ipc_q8(cpu: usize) -> u32 {
    IPC_Q8[cpu % MAX_CPUS].load(Ordering::Relaxed)
}

// ───────────────────────── Host tests ─────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    #[test]
    fn wrap_delta_simple_and_wrapped() {
        assert_eq!(wrap_delta(100, 200, 48), 100);
        assert_eq!(wrap_delta(10, 5, 48), 0, "backwards snapshots are noise");
        // Wrap at width 48: counter past 2^48, snapshot below.
        let last = (1u64 << 47) + 10;
        let now = 5;
        assert_eq!(wrap_delta(last, now, 48), (1u64 << 48) - last + now);
    }

    #[test]
    fn ipc_q8_bounds_and_rejects() {
        assert_eq!(ipc_q8_of(1000, 1000), Some(256));
        assert_eq!(ipc_q8_of(1500, 1000), Some(384), "1.5 IPC");
        assert_eq!(ipc_q8_of(2000, 1000), Some(512), "2.0 IPC (SMT-class)");
        assert_eq!(ipc_q8_of(0, 1000), None);
        assert_eq!(ipc_q8_of(100, 0), None);
        assert_eq!(ipc_q8_of(65_000, 1000), None, "IPC 65 — torn read guard");
    }

    #[test]
    fn sw_estimation_math() {
        // dt = 20_000 ticks, tspk = 10_000: di = dt*1000/tspk = 2000
        // instructions; IPC = 2000/20000 = 0.1 -> Q8 25 (integer floor).
        let dt = 20_000u64;
        let tspk = 10_000u64;
        let di = ((dt as u128 * 1000) / tspk as u128) as u64;
        assert_eq!(di, 2000);
        assert_eq!(ipc_q8_of(di, dt), Some(25));
    }

    #[test]
    fn caps_for_normalizes_floors_and_keeps() {
        // Two online cpus: cpu1 is the fleet max, cpu0 half its rate.
        let mut ipc = [0u32; MAX_CPUS];
        ipc[0] = 128;
        ipc[1] = 256;
        let caps = caps_for(&ipc, 0b0011);
        assert_eq!(caps[1], 256, "the fastest class maps to 256");
        assert_eq!(caps[0], 128, "half the rate: half the capacity");
        // An online core with no samples floors at 16 Q8 (6%).
        ipc[0] = 0;
        let caps = caps_for(&ipc, 0b0011);
        assert_eq!(caps[0], 16);
        assert_eq!(caps[1], 256);
        // Offline cores and the nothing-measured case keep the mirrors
        // (encoded as 0 here).
        let caps = caps_for(&ipc, 0b0001);
        assert_eq!(caps[1], 0, "offline: caller keeps the old mirror");
        let mut none = [0u32; MAX_CPUS];
        let caps = caps_for(&none, 0b0011);
        assert_eq!(caps[0], 0, "all-zero: no-op");
        assert_eq!(caps[1], 0, "all-zero: no-op");
        // Cleanup for other tests in this binary.
        IPC_Q8[0].store(0, Ordering::Relaxed);
        CAP_Q8[0].store(256, Ordering::Relaxed);
    }

    #[test]
    fn ewma4_moves_by_quarters() {
        let mut v = 0u32;
        for _ in 0..40 {
            v = ewma4_pub(v, 256);
        }
        assert!(v > 250, "converges to the sample, got {v}");
        // Downward forgets as well.
        let mut d = 256u32;
        for _ in 0..40 {
            d = ewma4_pub(d, 0);
        }
        assert!(d < 6, "decays to zero, got {d}");
    }

    /// ewma4 is private; expose for the test via a shim.
    fn ewma4_pub(old: u32, sample: u32) -> u32 {
        ewma4(old, sample)
    }
}
