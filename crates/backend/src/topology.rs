// ==== Topology: real SMT / LLC / NUMA domains for the balancer (v0.19) ====
//
// The v0.18 load balancer walked a FLAT domain (one mask covering
// everything, a fixed "LLC" migration cost). This module derives the
// hierarchy the hardware actually reports and hands the steal walk the
// real thing, nearest level first:
//
//   * SMT sibling masks — CPUID leaf 0xB (extended topology): the SMT
//     level's `processors()` is the thread count per core. QEMU encodes
//     `-smp …,threads=N` there; a missing leaf degrades to "no SMT",
//     which on the default rig (threads=1) is the truth;
//   * LLC masks — CPUID leaf 4 (deterministic cache parameters): the
//     sharing count of the HIGHEST cache level, applied as an APIC-id
//     right-shift over the MADT lapic ids. No leaf 4 => one LLC domain
//     covering everything present (single-socket QEMU reality);
//   * NUMA nodes — SRAT processor-affinity entries (types 0/x2APIC 2)
//     keyed by the same lapic ids. No SRAT (QEMU without -numa) => a
//     single node, and the third walk level stays empty.
//
// Every source degrades independently: a missing table never blocks the
// levels above it. Filled once by `build()` from `smp::bring_up` (single
// writer on the BSP, before the APs are released into the scheduler);
// readers afterwards are lock-free, like `smp::TOPOLOGY`.

use raw_cpuid::{CacheType, CpuId, TopologyType};

use crate::smp::{self, AcpiError, Topology, MAX_CPUS};

/// Migration-cost ladder by domain level, Q8 (SMT < cluster < LLC < NUMA).
/// The cluster level (index 1) exists on ARM DSU-class topologies; x86_64
/// reports nothing between SMT and LLC, so the walk consumes indices
/// 0 (SMT), 2 (LLC) and 3 (NUMA).
pub const MIGCOST_LADDER_Q8: [u32; 4] = [64, 96, 128, 256];

/// One level of the steal walk: a candidate-source mask (online/overload
/// are intersected by the caller) plus this level's migration cost.
#[derive(Debug, Clone, Copy)]
pub struct Level {
    pub mask: u64,
    pub migcost_q8: u32,
}

/// Detected domain hierarchy. `llc_shift` is the APIC-id right-shift
/// identifying one LLC instance; the sentinel 63 means "everything
/// present shares one LLC" (any realistic APIC id shifts to 0 there).
///
/// Masks always include the cpu itself; the walk subtracts `self` and
/// (for the LLC level) the SMT group.
pub struct Domains {
    /// log2(threads per core); 0 = no SMT detected.
    pub smt_shift: u32,
    /// APIC-id right-shift identifying an LLC (63 = single-LLC fallback).
    pub llc_shift: u32,
    /// Boot-present cpu set (slot bits) — bounds the beyond-LLC level
    /// to cpus that actually exist (u64::MAX would fabricate them).
    pub present: u64,
    /// NUMA node id per cpu (SRAT; 0 = single-node machine).
    pub node_of: [u8; MAX_CPUS],
    /// Number of distinct NUMA nodes (>= 1).
    pub n_nodes: u8,
    /// SMT sibling mask per cpu (includes the cpu itself).
    pub smt_mask: [u64; MAX_CPUS],
    /// LLC-sharing mask per cpu (includes the cpu itself).
    pub llc_mask: [u64; MAX_CPUS],
}

impl Domains {
    const fn empty() -> Self {
        Self {
            smt_shift: 0,
            llc_shift: 63,
            present: 0,
            node_of: [0; MAX_CPUS],
            n_nodes: 1,
            smt_mask: [0; MAX_CPUS],
            llc_mask: [0; MAX_CPUS],
        }
    }
}

static mut DOMAINS: Domains = Domains::empty();

/// The boot-built domains (degenerate/flat until `build` ran — callers
/// tolerate that: empty masks just mean "no such level").
pub fn domains() -> &'static Domains {
    // SAFETY: written once on the BSP before any AP goes online; after
    // that it is strictly read-only (the smp::TOPOLOGY pattern).
    unsafe { &*(&raw const DOMAINS) }
}

// ───────────────────────── Boot-time build ─────────────────────────

/// Build the domain hierarchy from the FINAL CPU set. Called once from
/// `smp::bring_up` — after AP timeouts have punched their holes, before
/// anything else in the system can read the domains.
pub fn build(topo: &Topology) {
    // 1) SMT: CPUID 0xB, the SMT level's thread count.
    let smt_shift = probe_smt_shift();
    // 2) LLC: CPUID leaf 4, the highest cache level's sharing count.
    //    Validated: power of two, >= the SMT group; otherwise the
    //    single-LLC fallback (shift sentinel 63).
    let threads = 1usize << smt_shift;
    let llc_shift = probe_llc_share()
        .filter(|&s| s.is_power_of_two() && s >= threads)
        .map(|s| s.trailing_zeros() as u32);
    // 3) NUMA: SRAT processor affinity over the MADT lapic ids.
    let (node_of, n_nodes) = probe_nodes(topo);
    // Masks from the final slot set.
    let present = present_mask(topo);
    let (smt_mask, llc_mask) = build_masks(topo, smt_shift, llc_shift);
    // SAFETY: single writer (the BSP inside bring_up), no concurrent
    // readers exist yet (APs are parked; the BSP is right here).
    let d: &mut Domains = unsafe { &mut *(&raw mut DOMAINS) };
    d.smt_shift = smt_shift;
    d.llc_shift = llc_shift.unwrap_or(63);
    d.present = present;
    d.node_of = node_of;
    d.n_nodes = n_nodes;
    d.smt_mask = smt_mask;
    d.llc_mask = llc_mask;
    crate::kprintln!(
        "topology: present={} smt_threads={} llc_shift={} nodes={}",
        topo.present,
        1u64 << smt_shift,
        d.llc_shift,
        n_nodes
    );
}

/// Boot-present cpu set (slot bits of the final topology).
fn present_mask(topo: &Topology) -> u64 {
    let mut m = 0u64;
    for cpu in 0..MAX_CPUS {
        if topo.cpus.get(cpu).copied().flatten().is_some() {
            m |= 1u64 << cpu;
        }
    }
    m
}

/// SMT width from CPUID leaf 0xB (x2APIC extended topology). Missing or
/// non-SMT leaf => 0 (no hyperthreads: each cpu is its own sibling).
fn probe_smt_shift() -> u32 {
    let cpuid = CpuId::new();
    let mut shift = 0u32;
    if let Some(levels) = cpuid.get_extended_topology_info() {
        for lvl in levels {
            if lvl.level_type() == TopologyType::SMT {
                let t = lvl.processors();
                if t.is_power_of_two() && t > 1 {
                    shift = t.trailing_zeros();
                }
                break;
            }
        }
    }
    shift
}

/// LLC sharing width from CPUID leaf 4 (deterministic cache parameters):
/// the sharing count of the HIGHEST cache level. `None` = no leaf 4.
fn probe_llc_share() -> Option<usize> {
    let cpuid = CpuId::new();
    let mut best_level = 0u8;
    let mut best_share = 0usize;
    if let Some(caches) = cpuid.get_cache_parameters() {
        for c in caches {
            match c.cache_type() {
                CacheType::Null | CacheType::Reserved => continue,
                _ => {}
            }
            if c.level() > best_level {
                best_level = c.level();
                best_share = c.max_cores_for_cache();
            }
        }
    }
    if best_level >= 1 {
        Some(best_share)
    } else {
        None
    }
}

/// NUMA map from SRAT (by MADT lapic id). Missing SRAT (QEMU without
/// -numa) or a parse failure => single node, `node_of` all zeros.
fn probe_nodes(topo: &Topology) -> ([u8; MAX_CPUS], u8) {
    let mut node_of = [0u8; MAX_CPUS];
    if topo.rsdp_phys == 0 {
        return (node_of, 1);
    }
    let Ok((phys, len)) = smp::find_table(topo.rsdp_phys, b"SRAT", smp::phys_read8) else {
        return (node_of, 1); // no SRAT in the table set — single node
    };
    let srat = smp::phys_slice(phys, len);
    match parse_srat(srat) {
        Ok(map) => {
            for cpu in 0..MAX_CPUS {
                let Some(entry) = topo.cpus.get(cpu).copied().flatten() else { continue };
                if let Some(node) = map.node_for(entry.lapic_id as u32) {
                    node_of[cpu] = node;
                }
            }
            let n = node_of.iter().copied().max().unwrap_or(0).saturating_add(1).max(1);
            (node_of, n)
        }
        Err(e) => {
            crate::kprintln!("topology: SRAT parse failed ({:?}) — single node", e);
            (node_of, 1)
        }
    }
}

/// Sibling/LLC masks from the final CPU set (pure; host-testable).
/// `llc_shift == None` => one LLC domain covering everything present.
pub fn build_masks(
    topo: &Topology,
    smt_shift: u32,
    llc_shift: Option<u32>,
) -> ([u64; MAX_CPUS], [u64; MAX_CPUS]) {
    let mut smt_mask = [0u64; MAX_CPUS];
    let mut llc_mask = [0u64; MAX_CPUS];
    for cpu in 0..MAX_CPUS {
        let Some(entry) = topo.cpus.get(cpu).copied().flatten() else { continue };
        let apic = entry.lapic_id as u32;
        let mut smt = 0u64;
        let mut llc = 0u64;
        for other in 0..MAX_CPUS {
            let Some(e2) = topo.cpus.get(other).copied().flatten() else { continue };
            let apic2 = e2.lapic_id as u32;
            if (apic2 >> smt_shift) == (apic >> smt_shift) {
                smt |= 1u64 << other;
            }
            let same_llc = match llc_shift {
                Some(s) => (apic2 >> s) == (apic >> s),
                None => true, // single-LLC fallback: everything present
            };
            if same_llc {
                llc |= 1u64 << other;
            }
        }
        smt_mask[cpu] = smt;
        llc_mask[cpu] = llc;
    }
    (smt_mask, llc_mask)
}

// ───────────────────────── Runtime queries ─────────────────────────

#[inline]
pub fn smt_mask(cpu: usize) -> u64 {
    domains().smt_mask[cpu % MAX_CPUS]
}

#[inline]
pub fn llc_mask(cpu: usize) -> u64 {
    domains().llc_mask[cpu % MAX_CPUS]
}

/// Do two cpus share a last-level cache?
#[inline]
pub fn same_llc(a: usize, b: usize) -> bool {
    if a == b {
        return true;
    }
    if a >= MAX_CPUS || b >= MAX_CPUS {
        return false;
    }
    (domains().llc_mask[a] >> b) & 1 == 1
}

/// Do two cpus share a NUMA node?
#[inline]
pub fn same_node(a: usize, b: usize) -> bool {
    if a == b {
        return true;
    }
    if a >= MAX_CPUS || b >= MAX_CPUS {
        return false;
    }
    domains().node_of[a] == domains().node_of[b]
}

/// Mean core utilisation (Q8) over the cpus in `mask` — the EAS
/// "domain utilisation" input. Lock-free reads of the balancer's
/// `UTIL` mirrors; called from the (lock-free) steal path only.
pub fn domain_util(mask: u64) -> u32 {
    use core::sync::atomic::Ordering;
    let mut sum = 0u32;
    let mut n = 0u32;
    for cpu in 0..MAX_CPUS {
        if (mask >> cpu) & 1 == 0 {
            continue;
        }
        sum = sum.saturating_add(crate::lb::UTIL[cpu].load(Ordering::Relaxed));
        n += 1;
    }
    if n == 0 {
        0
    } else {
        sum / n
    }
}

/// The steal-walk levels for `cpu`, nearest first: SMT siblings, then
/// the rest of this LLC, then (multi-node machines only) everything
/// beyond the LLC. Empty masks mean "level absent on this machine" —
/// the walk skips them. Pure function over the given domains; the
/// backend entry point [`steal_levels`] binds the boot-built set.
pub fn levels_for(d: &Domains, cpu: usize) -> [Level; 3] {
    let cpu = cpu % MAX_CPUS;
    let me = 1u64 << cpu;
    let smt = d.smt_mask[cpu] & !me;
    let llc_rest = d.llc_mask[cpu] & !d.smt_mask[cpu] & !me;
    let numa_rest = if d.n_nodes > 1 {
        d.present & !d.llc_mask[cpu] & !me
    } else {
        0
    };
    [
        Level { mask: smt, migcost_q8: MIGCOST_LADDER_Q8[0] },
        Level { mask: llc_rest, migcost_q8: MIGCOST_LADDER_Q8[2] },
        Level { mask: numa_rest, migcost_q8: MIGCOST_LADDER_Q8[3] },
    ]
}

/// The steal-walk levels for `cpu` from the boot-built domains.
/// Allocation-free (v0.18 built a Vec here on every attempt).
pub fn steal_levels(cpu: usize) -> [Level; 3] {
    levels_for(domains(), cpu)
}

// ───────────────────────── SRAT parser (slice-based, host-testable) ─────────────────────────

/// SRAT processor-affinity map. `map[..n]` holds (apic_id, node) pairs,
/// enabled entries only.
#[derive(Debug, Clone, Copy)]
pub struct SratTopo {
    pub map: [(u32, u8); MAX_CPUS],
    pub n: usize,
}

impl SratTopo {
    /// Node of a cpu by its local-APIC id (None = not listed/disabled).
    pub fn node_for(&self, apic_id: u32) -> Option<u8> {
        self.map[..self.n].iter().find(|(a, _)| *a == apic_id).map(|(_, n)| *n)
    }
}

/// Parse SRAT processor-local affinity entries. SRAT subtables start
/// right after the 36-byte ACPI header (no MADT-style extra fields).
///
/// Type 0 (Processor Local APIC, len 8):
///   [type][len][proximity u8][apic u8][flags u32], enabled = flags bit 0.
/// Type 2 (Processor Local x2APIC, len 16):
///   [type][len][rsvd u16][proximity u32][apic u32][flags u32].
/// x2APIC proximity domains are truncated to u8 (realistic machines
/// stay far below 256 nodes).
pub fn parse_srat(srat: &[u8]) -> Result<SratTopo, AcpiError> {
    if srat.len() < 36 {
        return Err(AcpiError::Truncated);
    }
    if &srat[0..4] != b"SRAT" {
        return Err(AcpiError::NotFound);
    }
    let len = smp::table_len(&srat[0..8])?;
    if srat.len() < len {
        return Err(AcpiError::Truncated);
    }
    let mut out = SratTopo { map: [(0, 0); MAX_CPUS], n: 0 };
    let mut off = 36;
    while off + 2 <= len {
        let etype = srat[off];
        let elen = srat[off + 1] as usize;
        if elen < 2 || off + elen > len {
            return Err(AcpiError::Truncated);
        }
        if etype == 0 && elen >= 8 && out.n < MAX_CPUS {
            let flags =
                u32::from_le_bytes([srat[off + 4], srat[off + 5], srat[off + 6], srat[off + 7]]);
            let apic = srat[off + 3] as u32;
            let node = srat[off + 2];
            if flags & 1 != 0 && !out.map[..out.n].iter().any(|(a, _)| *a == apic) {
                out.map[out.n] = (apic, node);
                out.n += 1;
            }
        } else if etype == 2 && elen >= 16 && out.n < MAX_CPUS {
            let flags = u32::from_le_bytes([
                srat[off + 12],
                srat[off + 13],
                srat[off + 14],
                srat[off + 15],
            ]);
            let apic = u32::from_le_bytes([
                srat[off + 8],
                srat[off + 9],
                srat[off + 10],
                srat[off + 11],
            ]);
            let node = u32::from_le_bytes([
                srat[off + 4],
                srat[off + 5],
                srat[off + 6],
                srat[off + 7],
            ]) as u8;
            if flags & 1 != 0 && !out.map[..out.n].iter().any(|(a, _)| *a == apic) {
                out.map[out.n] = (apic, node);
                out.n += 1;
            }
        }
        off += elen;
    }
    Ok(out)
}

// ───────────────────────── Host tests ─────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smp::CpuEntry;
    // Backend is no_std; host tests link std explicitly (see smp.rs).
    extern crate std;

    fn topo_with(lapics: &[u8]) -> Topology {
        let mut t = Topology {
            cpus: [None; MAX_CPUS],
            present: lapics.len(),
            slots: lapics.len(),
            lapic_phys: 0,
            rsdp_phys: 0,
        };
        for (i, &l) in lapics.iter().enumerate() {
            t.cpus[i] = Some(CpuEntry {
                processor_id: i as u8,
                lapic_id: l,
                enabled: true,
                online_capable: true,
            });
        }
        t
    }

    fn domains_from(
        lapics: &[u8],
        smt_shift: u32,
        llc_shift: Option<u32>,
        nodes: u8,
    ) -> Domains {
        let topo = topo_with(lapics);
        let (smt_mask, llc_mask) = build_masks(&topo, smt_shift, llc_shift);
        let mut node_of = [0u8; MAX_CPUS];
        // Nodes 0 and 1 split the list in half (test convention).
        for i in 0..lapics.len() {
            node_of[i] = if nodes > 1 && i >= lapics.len() / 2 { 1 } else { 0 };
        }
        Domains {
            smt_shift,
            llc_shift: llc_shift.unwrap_or(63),
            present: (1u64 << lapics.len()).wrapping_sub(1),
            node_of,
            n_nodes: nodes,
            smt_mask,
            llc_mask,
        }
    }

    #[test]
    fn masks_flat_rig() {
        // 4 cpus, no SMT, single LLC: siblings are self-only, LLC = all.
        let topo = topo_with(&[0, 1, 2, 3]);
        let (smt, llc) = build_masks(&topo, 0, None);
        for cpu in 0..4 {
            assert_eq!(smt[cpu], 1u64 << cpu, "no SMT: self-only siblings");
            assert_eq!(llc[cpu], 0b1111, "fallback LLC covers everything");
        }
    }

    #[test]
    fn masks_smt_rig() {
        // -smp 4,cores=2,threads=2: APIC ids 0..3, siblings {0,1}/{2,3}.
        let topo = topo_with(&[0, 1, 2, 3]);
        let (smt, llc) = build_masks(&topo, 1, None);
        assert_eq!(smt[0], 0b0011);
        assert_eq!(smt[1], 0b0011);
        assert_eq!(smt[2], 0b1100);
        assert_eq!(smt[3], 0b1100);
        for cpu in 0..4 {
            assert_eq!(llc[cpu], 0b1111, "single-socket: one LLC");
        }
    }

    #[test]
    fn masks_two_llc_instances() {
        // LLC = per-core L2 (share 2 with SMT): llc == smt groups.
        let topo = topo_with(&[0, 1, 2, 3]);
        let (smt, llc) = build_masks(&topo, 1, Some(1));
        for cpu in 0..4 {
            assert_eq!(llc[cpu], smt[cpu], "L2-as-LLC: LLC == SMT group");
        }
        // share 4 (one LLC per two cores): {0,1,2,3} again at shift 2.
        let (_, llc4) = build_masks(&topo, 1, Some(2));
        for cpu in 0..4 {
            assert_eq!(llc4[cpu], 0b1111);
        }
    }

    #[test]
    fn levels_flat_rig_match_v018_semantics() {
        // The default rig: one LLC domain covering all, SMT self-only.
        // Level 0 (SMT) is empty after removing self; level 1 (LLC rest)
        // carries everyone else at the LLC cost — exactly the v0.18 walk.
        let d = domains_from(&[0, 1, 2, 3], 0, None, 1);
        let lv = levels_for(&d, 0);
        assert_eq!(lv[0].mask, 0, "no SMT: self-only siblings disappear");
        assert_eq!(lv[1].mask, 0b1110);
        assert_eq!(lv[1].migcost_q8, MIGCOST_LADDER_Q8[2]);
        assert_eq!(lv[2].mask, 0, "single node: no NUMA level");
    }

    #[test]
    fn levels_smt_multi_node_rig() {
        // -smp 4,cores=2,threads=2 -numa node,cpus=0-1 -numa node,cpus=2-3.
        let d = domains_from(&[0, 1, 2, 3], 1, None, 2);
        let lv = levels_for(&d, 0);
        assert_eq!(lv[0].mask, 0b0010, "SMT sibling of cpu0 is cpu1");
        assert_eq!(lv[0].migcost_q8, MIGCOST_LADDER_Q8[0]);
        assert_eq!(lv[1].mask, 0b1100, "rest of the LLC (cpus 2,3)");
        assert_eq!(lv[1].migcost_q8, MIGCOST_LADDER_Q8[2]);
        // Single LLC => no beyond-LLC sources even with two nodes
        // (the level is bounded by the PRESENT set — no phantom cpus).
        assert_eq!(lv[2].mask, 0);
        assert!(same_node(0, 1) && !same_node_pub(&d, 0, 2));
    }

    /// Helper: same_node over an explicit Domains (the free fn reads the
    /// boot static, which host tests cannot populate).
    fn same_node_pub(d: &Domains, a: usize, b: usize) -> bool {
        if a == b {
            return true;
        }
        d.node_of[a] == d.node_of[b]
    }

    #[test]
    fn parse_srat_maps_enabled_entries() {
        // Header (36 bytes) + type0 x3 (one disabled) + type2 x1.
        let mut srat: std::vec::Vec<u8> = std::vec::Vec::new();
        srat.resize(36, 0);
        srat[0..4].copy_from_slice(b"SRAT");
        let total = 36 + 8 + 8 + 8 + 16;
        srat[4..8].copy_from_slice(&(total as u32).to_le_bytes());
        // cpu0/lapic0 -> node1 (enabled).
        srat.extend_from_slice(&[0, 8, 1, 0, 1, 0, 0, 0]);
        // cpu1/lapic1 -> node2, DISABLED (must be skipped).
        srat.extend_from_slice(&[0, 8, 2, 1, 0, 0, 0, 0]);
        // cpu2/lapic2 -> node0 (enabled).
        srat.extend_from_slice(&[0, 8, 0, 2, 1, 0, 0, 0]);
        // x2APIC: lapic 3 -> node 4 (enabled).
        let mut e2: std::vec::Vec<u8> = std::vec::Vec::new();
        e2.extend_from_slice(&[2, 16]);
        e2.extend_from_slice(&[0, 0]); // rsvd u16
        e2.extend_from_slice(&4u32.to_le_bytes()); // proximity
        e2.extend_from_slice(&3u32.to_le_bytes()); // x2apic id
        e2.extend_from_slice(&1u32.to_le_bytes()); // flags: enabled
        srat.extend_from_slice(&e2);
        let parsed = parse_srat(&srat).expect("valid synthetic SRAT");
        assert_eq!(parsed.n, 3);
        assert_eq!(parsed.node_for(0), Some(1));
        assert_eq!(parsed.node_for(1), None, "disabled entry skipped");
        assert_eq!(parsed.node_for(2), Some(0));
        assert_eq!(parsed.node_for(3), Some(4), "x2APIC entry mapped");
        // Junk input.
        let mut bad: std::vec::Vec<u8> = std::vec::Vec::new();
        bad.resize(64, 0);
        bad[0..4].copy_from_slice(b"SRAX");
        assert!(parse_srat(&bad).is_err());
    }

    #[test]
    fn domain_util_means_over_mask() {
        use core::sync::atomic::Ordering;
        // Borrow the balancer's mirrors directly (host test; nothing
        // else on this process reads them concurrently).
        crate::lb::UTIL[0].store(100, Ordering::Relaxed);
        crate::lb::UTIL[1].store(200, Ordering::Relaxed);
        crate::lb::UTIL[2].store(0, Ordering::Relaxed);
        assert_eq!(domain_util(0b0011), 150);
        assert_eq!(domain_util(0b0001), 100);
        assert_eq!(domain_util(0), 0);
        assert_eq!(domain_util(0b1000), 0);
    }
}
