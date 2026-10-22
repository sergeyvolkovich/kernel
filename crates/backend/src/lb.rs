// ==== Load balancer backend (v0.19): per-CPU EEVDF queues + offer showcase ====
//
// Platform half of the pull-model load balancer (policy: crates/sched_lb,
// run-queue: crates/eevdf). Owns:
//
//   * RQ[cpu]        — one EEVDF run queue per CPU (leaf KSpin each);
//   * SHELF[cpu]     — the offer showcase (lock-free, owner publishes);
//   * REQ_INBOX[cpu] — variant-B steal requests (thief -> source);
//   * HANDOFF_INBOX  — detached migrants (source -> thief);
//   * lock-free mirrors for cross-CPU readers: RDY (queued count),
//     CUR_DL (running entity deadline), PUB_PRESSURE / UTIL (EWMA
//     snapshots), IDLE_MASK + IDLE_ENTER (idle set + wake-cost hint);
//   * OVERLOAD       — bitmap of cores in the "publishing" hysteresis
//     state; thieves scan it instead of polling every shelf.
//
// v0.19 — the balancer subsystem went heap-free, topology-aware and
// heterogeneity-aware:
//   * routing (HOME) is a slab-backed open-addressing hash (the v0.18
//     BTreeMaps allocated nodes under the SCHED-rank lock — a leaf
//     taking KMEM inside, against the lock discipline);
//   * the variant-B inboxes are lock-free bounded MpmcQueue rings (no
//     KSpin<VecDeque>: no push growth inside a scheduler lock, and two
//     spin locks gone from the steal path entirely);
//   * the publish path (snapshot -> select -> republish) and the sweep
//     run entirely on per-CPU scratch buffers;
//   * the steal walk consumes the REAL boot-built domain hierarchy
//     (topology.rs: CPUID 0xB SMT + leaf-4 LLC + SRAT NUMA over the
//     MADT lapic ids) instead of a heap Vec with one flat mask;
//   * admission/scoring use MEASURED per-CPU capacities (perf.rs) for
//     `CoreView::cap_q8` and the energy/fit context.
//
// Lock discipline (all SCHED-rank leaves — NEVER nested):
//   HOME -> RQ[x] -> HOME -> RQ[y] sequences are fine (sequential);
//   no path holds two of {RQ[i], RQ[j], HOME, INBOX} at once, and none
//   is taken while another SCHED leaf is held. Hooks from TcbManager
//   run under the TCB write guard exactly like the old global EEVDF
//   lock did (rank TCB -> SCHED, one-way). The inboxes need no lock at
//   all anymore (Vyukov rings).
//
// Owner-only state (LB[cpu]/SCRATCH[cpu], plain data, no locks) follows
// the per-CPU discipline of the context slots in sched.rs: only the
// owning core touches its element, at preempt boundaries and idle
// transitions.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, AtomicU32, Ordering};

use pkg_generic_interface::sync::{KSpin, MpmcQueue};
use sched_lb::{
    CoreView, Edge, Handoff, K_SLOTS, Offer, OwnerLb, PRESSURE_HARD_Q8, PRESSURE_LO_Q8,
    PUBLISH_EVERY_SLICES, STEAL_EVERY_SLICES, STEAL_PRESSURE_EPS_Q8, STEAL_REQ_TIMEOUT_SLICES,
    StealCtx, StealOutcome, StealReq, Weights, DEFAULT_WEIGHTS, admission_ok, min_stay_cycles,
    score, select_offers_into,
};

use crate::perf;
use crate::smp::MAX_CPUS;
use crate::topology;

// ───────────────────────── State ─────────────────────────

/// Per-CPU EEVDF run queues (the "rq" of the design). base_slice is
/// fixed per queue at calibration time (before SMP start).
pub static RQ: [KSpin<eevdf::RunQueue>; MAX_CPUS] =
    [const { KSpin::new(eevdf::RunQueue::new(0)) }; MAX_CPUS];

/// Per-CPU offer showcase (published by the owner, claimed by thieves).
pub static SHELF: [sched_lb::OfferShelf; MAX_CPUS] = [const { sched_lb::OfferShelf::new() }; MAX_CPUS];

/// Variant-B steal request inbox per cpu (MPSC: any thief pushes; the
/// owner pops at its preempt boundary). Lock-free bounded ring — the
/// v0.18 KSpin<VecDeque> allocated on push growth *inside a SCHED-rank
/// lock*; capacity 8 is plenty: requests are tiny, timed and best-effort
/// (a full ring drops the request — the thief's deadline expires anyway).
static REQ_INBOX: [MpmcQueue<StealReq, 8>; MAX_CPUS] = [const { MpmcQueue::new() }; MAX_CPUS];

/// Migrant handoff inbox per cpu (MPSC: sources push detached entities;
/// the owner drains at schedule boundaries / idle wakes). On a full ring
/// the source re-attaches the migrant to its own queue (see
/// `process_requests`) — the thief's request expires by timeout, nothing
/// is lost.
static HANDOFF_INBOX: [MpmcQueue<Handoff, 8>; MAX_CPUS] = [const { MpmcQueue::new() }; MAX_CPUS];

// ───────────────────────── Routing (slab-backed hash, v0.19) ─────────────────────────

/// Home routing: the run-queue every live thread is homed to, plus
/// creation-time weights parked before the first enqueue (consumed when
/// the placement registers the thread — see `place_and_enqueue`).
///
/// A fixed-capacity open-addressing hash instead of the two v0.18
/// BTreeMaps: those allocated nodes on insert under the SCHED-rank HOME
/// lock. Ids are monotonic Uuid counters, so low-bit probing spreads
/// perfectly at <= 50% load; capacity 1024 covers the 512-thread system
/// quota twice over. Deletion is backward-shift, so probe runs stay
/// prefix-valid without tombstones.
const HOME_SLOTS: usize = 1024; // power of two (mask indexing)

#[derive(Clone, Copy)]
struct HomeSlot {
    used: bool,
    key: u128,
    /// Home cpu (None = no home yet; the entry may still park a weight).
    cpu: Option<u8>,
    /// Creation-time weight parked until the first enqueue.
    pending: Option<u32>,
}

struct HomeTable {
    slots: [HomeSlot; HOME_SLOTS],
}

impl HomeTable {
    const fn new() -> Self {
        Self {
            slots: [const {
                HomeSlot { used: false, key: 0, cpu: None, pending: None }
            }; HOME_SLOTS],
        }
    }

    /// Mixed low/high fold — cheap, and monotonic counter ids spread
    /// well even without it.
    #[inline]
    fn hash(key: u128) -> usize {
        let mut h = (key as u64) ^ ((key >> 64) as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        h ^= h >> 33;
        h = h.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
        h ^= h >> 33;
        h as usize & (HOME_SLOTS - 1)
    }

    /// Slot index of `key`, if present (the probe stops at the first
    /// never-used slot — backward-shift deletion keeps that sound).
    fn find(&self, key: u128) -> Option<usize> {
        let mut i = Self::hash(key);
        for _ in 0..HOME_SLOTS {
            let s = &self.slots[i];
            if !s.used {
                return None;
            }
            if s.key == key {
                return Some(i);
            }
            i = (i + 1) & (HOME_SLOTS - 1);
        }
        None
    }

    /// Slot for `key`, creating it if absent.
    fn entry(&mut self, key: u128) -> usize {
        if let Some(i) = self.find(key) {
            return i;
        }
        let mut i = Self::hash(key);
        for _ in 0..HOME_SLOTS {
            if !self.slots[i].used {
                self.slots[i] = HomeSlot { used: true, key, cpu: None, pending: None };
                return i;
            }
            i = (i + 1) & (HOME_SLOTS - 1);
        }
        // Full table = 2x the thread quota: invariant breach upstream.
        debug_assert!(false, "lb: HOME table full");
        0 // degrade by aliasing slot 0 rather than panic in release
    }

    /// Home cpu of a thread (None = no home yet).
    fn home_of(&self, key: u128) -> Option<u8> {
        self.find(key).map(|i| self.slots[i].cpu).flatten()
    }

    /// Insert/update the home cpu.
    fn set_home(&mut self, key: u128, cpu: u8) {
        let i = self.entry(key);
        self.slots[i].cpu = Some(cpu);
    }

    /// Take (and clear) a parked creation weight.
    fn take_pending(&mut self, key: u128) -> Option<u32> {
        let i = self.entry(key);
        let w = self.slots[i].pending;
        self.slots[i].pending = None;
        self.gc_if_empty(i);
        w
    }

    /// Park a creation weight (thread with no live entity yet).
    fn park_weight(&mut self, key: u128, w: u32) {
        let i = self.entry(key);
        self.slots[i].pending = Some(w);
    }

    /// Drop a thread's routing entirely; returns its home cpu.
    fn drop_entry(&mut self, key: u128) -> Option<u8> {
        let Some(i) = self.find(key) else { return None };
        let cpu = self.slots[i].cpu;
        self.remove_at(i);
        cpu
    }

    /// Remove dead entries in one pass; returns how many went.
    /// After a `remove_at` the scan re-examines the SAME index: the
    /// backward shift moves a donor entry (possibly also dead) into the
    /// fresh hole, and advancing would skip it.
    fn sweep(&mut self, is_dead: &dyn Fn(u128) -> bool) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < HOME_SLOTS {
            let key = self.slots[i].key;
            if self.slots[i].used && is_dead(key) {
                self.remove_at(i);
                n += 1;
                continue; // a donor may now sit at i — re-examine
            }
            i += 1;
        }
        n
    }

    /// Clear a slot that holds neither a home nor a parked weight.
    fn gc_if_empty(&mut self, i: usize) {
        if self.slots[i].used && self.slots[i].cpu.is_none() && self.slots[i].pending.is_none() {
            self.remove_at(i);
        }
    }

    /// Backward-shift deletion (Knuth): every live key stays reachable
    /// from its probe start without tombstones.
    fn remove_at(&mut self, hole: usize) {
        let mut hole = hole;
        let mut j = (hole + 1) & (HOME_SLOTS - 1);
        for _ in 0..HOME_SLOTS {
            let s = self.slots[j];
            if !s.used {
                break;
            }
            let home = Self::hash(s.key);
            // Does the live slot at j legally move into `hole`?
            // Classic cyclic condition: home <= hole < j.
            let fits = if j > hole {
                home <= hole || home > j
            } else {
                home <= hole && home > j
            };
            if fits {
                self.slots[hole] = s;
                self.slots[j].used = false;
                hole = j;
            }
            j = (j + 1) & (HOME_SLOTS - 1);
        }
        self.slots[hole].used = false;
    }
}

static HOME: KSpin<HomeTable> = KSpin::new(HomeTable::new());

/// Owner-only balancer state (per-CPU discipline, see module docs).
#[repr(align(64))]
struct LbCpu {
    st: UnsafeCell<OwnerLb>,
}

// SAFETY: LB[cpu] is touched only by its owner CPU (preempt boundaries,
// idle transitions); cross-CPU readers use the atomic mirrors below.
unsafe impl Sync for LbCpu {}

static LB: [LbCpu; MAX_CPUS] = [const { LbCpu { st: UnsafeCell::new(OwnerLb::new()) } }; MAX_CPUS];

#[inline]
fn owner(cpu: usize) -> &'static mut OwnerLb {
    debug_assert!(cpu < MAX_CPUS);
    // SAFETY: owner-cpu access (discipline above); the debug assert and
    // the smp invariant (cpu_id < MAX_CPUS) bound the index.
    unsafe { &mut *LB[cpu % MAX_CPUS].st.get() }
}

// ───────────────────────── Per-CPU scratch (v0.19) ─────────────────────────

/// Owner-side scratch for the publish/sweep paths: pre-attached buffers
/// replacing the v0.18 Vecs (the candidate snapshot allocated under the
/// queue lock; the sweep Vecs under RQ/HOME). Only the owning core
/// touches its element — the LB per-CPU discipline.
struct Scratch {
    /// Queued-candidate snapshot (bounded view; see `on_preempt`).
    cands: [eevdf::QueuedCand; 64],
    /// Offer selection output (tardiness-desc, worst slip first).
    offers: [sched_lb::Offer; K_SLOTS],
    /// Sweep pagination buffer.
    ids: [u128; 128],
}

impl Scratch {
    const fn new() -> Self {
        Self {
            cands: [const { eevdf::QueuedCand::ZERO }; 64],
            offers: [const { sched_lb::Offer::ZERO }; K_SLOTS],
            ids: [0; 128],
        }
    }
}

#[repr(align(64))]
struct LbScratch {
    st: UnsafeCell<Scratch>,
}

// SAFETY: per-CPU owner discipline (see LB above).
unsafe impl Sync for LbScratch {}

static SCRATCH: [LbScratch; MAX_CPUS] =
    [const { LbScratch { st: UnsafeCell::new(Scratch::new()) } }; MAX_CPUS];

#[inline]
fn scratch(cpu: usize) -> &'static mut Scratch {
    debug_assert!(cpu < MAX_CPUS);
    // SAFETY: owner-cpu access (discipline above), bounded index.
    unsafe { &mut *SCRATCH[cpu % MAX_CPUS].st.get() }
}

// ── lock-free mirrors (cross-CPU readers) ──

/// Queued count per CPU (maintained under the respective RQ lock).
pub static RDY: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];
/// Virtual deadline of the currently-running entity (0 = none/idle).
pub static CUR_DL: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
/// Pressure EWMA snapshot (Q8), refreshed at preempt/idle/pick.
pub static PUB_PRESSURE: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];
/// Core utilisation EWMA snapshot (Q8).
pub static UTIL: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];
/// TSC of entering idle (wake-cost hint: the most recent sleeper is the
/// cheapest to wake — shallowest C-state in spirit).
pub static IDLE_ENTER: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Cores in the publishing (overloaded) hysteresis state.
pub static OVERLOAD: AtomicU64 = AtomicU64::new(0);

/// Calibrated base slice (all queues share it; set once pre-SMP).
static BASE_SLICE: AtomicU64 = AtomicU64::new(1);

/// Idle bitmap (mirrors sched::IDLE_MASK semantics; owned here so the
/// balancer's enqueue/notify paths see one coherent module).
pub static IDLE_MASK: AtomicU64 = AtomicU64::new(0);

// ───────────────────────── Time / helpers ─────────────────────────

#[inline]
fn now_tsc() -> u64 {
    crate::lapic::read_tsc()
}

#[inline]
pub fn base_slice() -> u64 {
    BASE_SLICE.load(Ordering::Relaxed).max(1)
}

#[inline]
fn idle_bit(cpu: usize) -> bool {
    (IDLE_MASK.load(Ordering::Acquire) >> (cpu & 63)) & 1 == 1
}

#[inline]
fn online_has(cpu: usize) -> bool {
    (crate::smp::online_mask() >> (cpu & 63)) & 1 == 1
}

/// Send a resched IPI to an online CPU (no-op for self/offline).
#[inline]
fn ipi_resched(target: usize) {
    if target == arch::percpu::cpu_id() as usize {
        arch::percpu::set_need_resched();
        return;
    }
    if !online_has(target) {
        return;
    }
    crate::lapic::send_ipi_to(
        crate::smp::lapic_id_of(target) as u32,
        arch::boot::VEC_IPI_RESCHED,
    );
}

/// Cheap deterministic scramble for randomizing thief scan order.
#[inline]
fn scramble(cpu: usize, seed: u64) -> u64 {
    let mut x = seed ^ (cpu as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 27;
    x.wrapping_mul(0x94D0_49BB_1331_11EB)
}

// ───────────────────────── Init ─────────────────────────

/// Fix the base slice on every queue (platform init, once, pre-SMP).
pub fn init_base_slice(cycles: u64) {
    let c = cycles.max(1);
    BASE_SLICE.store(c, Ordering::Relaxed);
    for rq in RQ.iter() {
        rq.lock().set_base_slice(c);
    }
}

// ───────────────────────── Placement & notify (enqueue path) ─────────────────────────

/// Least-loaded online cpu (queued-count first, utilisation second —
/// both from the lock-free mirrors; approximate is fine here). Ties
/// break toward our own LLC (v0.19: a cache-locality tiebreak on top
/// of the v0.18 load order).
fn least_loaded(me: usize, online: u64) -> usize {
    let mut best = 0usize;
    let mut best_key = (u32::MAX, u32::MAX, u8::MAX);
    for cpu in 0..MAX_CPUS {
        if (online >> cpu) & 1 == 0 {
            continue;
        }
        let dist: u8 = if topology::same_llc(me, cpu) { 0 } else { 1 };
        let key = (
            RDY[cpu].load(Ordering::Relaxed),
            UTIL[cpu].load(Ordering::Relaxed),
            dist,
        );
        if key < best_key {
            best_key = key;
            best = cpu;
        }
    }
    best
}

/// The idle cpu cheapest to wake, in wake-affinity tiers (v0.19): an
/// idle SMT sibling of `home` first (it shares L1/L2 with the waker's
/// working set), then the rest of home's LLC, then everything else —
/// within a tier the most recently parked cpu wins (the shallowest
/// C-state proxy, as in v0.18).
fn cheapest_idle(home: usize, online: u64) -> Option<usize> {
    let idle = IDLE_MASK.load(Ordering::Acquire) & online;
    if idle == 0 {
        return None;
    }
    let smt = topology::smt_mask(home);
    let llc = topology::llc_mask(home);
    let mut best: Option<usize> = None;
    let mut best_tier = 3u8;
    let mut best_enter = 0u64;
    for cpu in 0..MAX_CPUS {
        if (idle >> cpu) & 1 == 0 {
            continue;
        }
        let tier: u8 = if (smt >> cpu) & 1 == 1 {
            0
        } else if (llc >> cpu) & 1 == 1 {
            1
        } else {
            2
        };
        let t = IDLE_ENTER[cpu].load(Ordering::Relaxed);
        if best.is_none() || tier < best_tier || (tier == best_tier && t > best_enter) {
            best = Some(cpu);
            best_tier = tier;
            best_enter = t;
        }
    }
    best
}

/// Tell a target CPU that a task with virtual deadline `dl` just became
/// ready on its queue: wake it if idle (hlt), else preempt-IPI it only
/// when the new task beats what it is running (urgent case).
pub fn notify_target(target: usize, dl: u64) {
    let me = arch::percpu::cpu_id() as usize;
    if target == me {
        let cur = CUR_DL[me].load(Ordering::Relaxed);
        if cur != 0 && dl < cur {
            arch::percpu::set_need_resched();
        }
        return;
    }
    if idle_bit(target) {
        ipi_resched(target);
        return;
    }
    let cur = CUR_DL[target].load(Ordering::Acquire);
    if cur != 0 && dl < cur {
        ipi_resched(target);
    }
}

/// Full wake/create placement: route the thread to a run queue
/// (home-queue stickiness for cache locality), register it there
/// (consuming a pending creation weight), enqueue, mirror the ready
/// count and kick the target. Returns the chosen CPU.
///
/// Wake assist: when the home queue is busy AND overloaded and an idle
/// core exists, a genuinely PARKED entity (blocked wake — not a
/// mid-slice rotate, whose entity sits in the home running set, and
/// not a fresh thread) is MIGRATED to the idle core at enqueue time
/// (detach with lag -> attach re-based on the destination clock).
/// Without the migration the entity would simply be missing on the
/// destination queue — per-queue entity caches make cross-queue
/// routing and entity ownership inseparable.
pub fn place_and_enqueue(task: u128) -> usize {
    let me = arch::percpu::cpu_id() as usize;
    let online = crate::smp::online_mask();
    let ncpu = online.count_ones();

    // 1) Routing: existing home (if online), else the waker (fresh
    //    threads spread only when the waker itself is overloaded).
    let pending_w;
    let home = {
        let mut h = HOME.lock();
        pending_w = h.take_pending(task);
        match h.home_of(task) {
            Some(hm) if (online >> hm) & 1 == 1 => hm as usize,
            Some(_) => {
                h.set_home(task, me as u8);
                me
            }
            None => {
                let t = if ncpu > 1 && (OVERLOAD.load(Ordering::Acquire) >> me) & 1 == 1 {
                    least_loaded(me, online)
                } else {
                    me
                };
                h.set_home(task, t as u8);
                t
            }
        }
    };

    // 2) Wake assist: home busy + overloaded + an idle core exists.
    //    Only a PARKED entity (present, not running, not queued = a
    //    blocked->ready wake) migrates; rotates stay cache-hot on home.
    if ncpu > 1 && home != me && (OVERLOAD.load(Ordering::Acquire) >> home) & 1 == 1 && !idle_bit(home)
    {
        if let Some(idle) = cheapest_idle(home, online) {
            let parked = {
                let mut rq = RQ[home].lock();
                if rq.has_entity(task) && !rq.is_running_here(task) && !rq.is_queued(task) {
                    let lag = rq.lag_of(task).unwrap_or(0);
                    let e = rq.take_entity(task);
                    RDY[home].store(rq.ready_len() as u32, Ordering::Relaxed);
                    e.map(|e| (e, lag))
                } else {
                    None
                }
            };
            if let Some((e, lag)) = parked {
                HOME.lock().set_home(task, idle as u8);
                let now = now_tsc();
                let base = base_slice();
                let stay = min_stay_cycles(e.mig_count, base);
                let dl = {
                    let mut dst = RQ[idle].lock();
                    dst.attach_entity(e, lag, now.saturating_add(stay));
                    RDY[idle].store(dst.ready_len() as u32, Ordering::Relaxed);
                    dst.deadline_of(task).unwrap_or(0)
                };
                notify_target(idle, dl);
                return idle;
            }
        }
    }

    // 3) Plain enqueue on the home queue: register (consuming a parked
    //    creation weight), enqueue, mirror, notify. Single queue section.
    let dl = {
        let mut rq = RQ[home].lock();
        if !rq.has_entity(task) {
            rq.register(task, pending_w.unwrap_or(eevdf::DEFAULT_WEIGHT));
        }
        rq.enqueue(task);
        RDY[home].store(rq.ready_len() as u32, Ordering::Relaxed);
        rq.deadline_of(task).unwrap_or(0)
    };
    notify_target(home, dl);
    home
}

/// Deschedule routing: the thread's entity lives on its home queue
/// (running entities: home == the CPU executing them). Returns whether
/// the entity was parked in the throttle list (the caller cleans
/// INNER.throttled in that case).
pub fn dequeue_from_home(task: u128) -> bool {
    let me = arch::percpu::cpu_id() as usize;
    let home = {
        let h = HOME.lock();
        h.home_of(task).map(|c| c as usize).unwrap_or(me)
    };
    let mut rq = RQ[home].lock();
    let was_throttled = rq.is_throttled(task);
    rq.dequeue(task);
    RDY[home].store(rq.ready_len() as u32, Ordering::Relaxed);
    was_throttled
}

/// Priority change (also the creation-time seed): reweight on the home
/// queue, or park the weight until the first enqueue places the thread.
pub fn set_thread_weight(task: u128, w: u32) {
    let me = arch::percpu::cpu_id() as usize;
    let home = {
        let h = HOME.lock();
        h.home_of(task).map(|c| c as usize).unwrap_or(me)
    };
    let mut rq = RQ[home].lock();
    if rq.has_entity(task) {
        rq.set_weight(task, w);
        RDY[home].store(rq.ready_len() as u32, Ordering::Relaxed);
        return;
    }
    drop(rq);
    HOME.lock().park_weight(task, w);
}

// ───────────────────────── Pick / park (owner paths) ─────────────────────────

/// Owner pick: take the best eligible entity off MY queue, publish the
/// running deadline + pressure mirrors. Returns (id, deadline).
pub fn pick(cpu: usize) -> Option<(u128, u64)> {
    let mut rq = RQ[cpu].lock();
    let id = rq.pick(cpu)?;
    let dl = rq.entity_of(id).map(|e| e.deadline).unwrap_or(0);
    RDY[cpu].store(rq.ready_len() as u32, Ordering::Relaxed);
    PUB_PRESSURE[cpu].store(rq.pressure_q8(), Ordering::Relaxed);
    drop(rq);
    CUR_DL[cpu].store(dl, Ordering::Release);
    Some((id, dl))
}

/// Owner charge + park bookkeeping in one queue section: EEVDF charge
/// for the executed segment, utilisation EWMA + cache stamp via
/// `note_park`, running-deadline mirror cleared (leaving the CPU).
pub fn charge_and_park(cpu: usize, task: u128, delta_exec: u64) {
    if delta_exec == 0 {
        CUR_DL[cpu].store(0, Ordering::Release);
        return;
    }
    let now = now_tsc();
    {
        let mut rq = RQ[cpu].lock();
        rq.charge(task, delta_exec);
        rq.note_park(task, now, delta_exec);
    }
    CUR_DL[cpu].store(0, Ordering::Release);
    // v0.19: the park closes this task's dispatch segment — sample it
    // for the measured-IPC machinery (no lock held here; the entity
    // update below rides its own short queue section). Segment bound:
    // 4 slices; longer ones span idle/boot gaps and get discarded.
    if let Some(seg_ipc) = perf::note_segment(cpu, base_slice().saturating_mul(4)) {
        let cap = perf::cap_q8(cpu);
        let mut rq = RQ[cpu].lock();
        rq.note_perf(task, cap, seg_ipc);
    }
}

/// Throttle parking (quota exhausted): entity leaves the running set of
/// ITS OWN queue (throttle happens on the executing CPU).
pub fn mark_throttled(cpu: usize, task: u128) {
    let mut rq = RQ[cpu].lock();
    rq.mark_throttled(task);
    CUR_DL[cpu].store(0, Ordering::Release);
}

/// Period boundary: return the throttle list to readiness, routed to
/// each thread's home queue, with aggregated notify kicks.
pub fn unthrottle_batch(ids: &[u128]) -> usize {
    // v0.19: kick aggregation without the heap — at most MAX_CPUS
    // targets, tracked in a fixed stack array.
    let mut kicks = [(0usize, 0u64); MAX_CPUS];
    let mut n_kicks = 0usize;
    for &id in ids {
        let home = {
            let h = HOME.lock();
            h.home_of(id).unwrap_or(0) as usize
        };
        let dl = {
            let mut rq = RQ[home].lock();
            rq.enqueue(id);
            RDY[home].store(rq.ready_len() as u32, Ordering::Relaxed);
            rq.deadline_of(id).unwrap_or(0)
        };
        match kicks[..n_kicks].iter_mut().find(|(c, _)| *c == home) {
            Some((_, d)) => *d = (*d).min(dl),
            None => {
                kicks[n_kicks] = (home, dl);
                n_kicks += 1;
            }
        }
    }
    for (cpu, dl) in &kicks[..n_kicks] {
        notify_target(*cpu, *dl);
    }
    ids.len()
}

/// Thread teardown: unregister from its home queue + drop routing.
pub fn drop_thread(task: u128) {
    let me = arch::percpu::cpu_id() as usize;
    let home = {
        let mut h = HOME.lock();
        h.drop_entry(task)
    };
    match home {
        Some(h) => {
            let h = h as usize;
            let mut rq = RQ[h].lock();
            rq.unregister(task);
            RDY[h].store(rq.ready_len() as u32, Ordering::Relaxed);
        }
        None => {
            // In transit (steal mid-flight) or never enqueued; the sweep
            // covers whichever queue ends up holding the entity.
            let mut rq = RQ[me].lock();
            if rq.has_entity(task) {
                rq.unregister(task);
                RDY[me].store(rq.ready_len() as u32, Ordering::Relaxed);
            }
        }
    }
}

/// Sweep dead entities off every queue + drop their routing entries.
/// `is_dead` must be lock-free (called between queue sections). Returns
/// how many entities were reaped.
pub fn sweep_dead(is_dead: &dyn Fn(u128) -> bool) -> usize {
    let me = arch::percpu::cpu_id() as usize;
    let sc = scratch(me);
    let mut reaped = 0usize;
    for cpu in 0..MAX_CPUS {
        // v0.19: pagination over the fixed scratch buffer instead of a
        // Vec collected under the queue lock. Removals shift the map, so
        // a round that reaped anything restarts from index 0; a clean
        // pass (or a short page) finishes this queue.
        let mut skip = 0usize;
        loop {
            let n = {
                let rq = RQ[cpu].lock();
                // Cheap pre-filter: an empty queue owns nothing.
                if rq.ready_len() == 0 && rq.entity_count() == 0 {
                    0
                } else {
                    rq.entity_ids_into(skip, &mut sc.ids)
                }
            };
            if n == 0 {
                break;
            }
            let mut dead_here = 0usize;
            for i in 0..n {
                if !is_dead(sc.ids[i]) {
                    continue;
                }
                let mut rq = RQ[cpu].lock();
                rq.unregister(sc.ids[i]);
                RDY[cpu].store(rq.ready_len() as u32, Ordering::Relaxed);
                dead_here += 1;
                reaped += 1;
            }
            if dead_here > 0 {
                skip = 0; // map changed: re-examine from the start
            } else if n < sc.ids.len() {
                break; // clean full pass: nothing dead here
            } else {
                skip += n; // stable: continue past this page
            }
        }
    }
    // Routing table hygiene: one pass, no intermediate Vec (v0.19).
    {
        let mut h = HOME.lock();
        h.sweep(is_dead);
    }
    reaped
}

// ───────────────────────── Owner preempt boundary ─────────────────────────

/// Preempt-boundary service of the owner CPU (called from preempt_step
/// AFTER the current thread's state was published): utilisation sample,
/// pressure mirror, rate-limited showcase publication with hysteresis,
/// hard-starvation idle kick, variant-B request duty and the periodic
/// steal attempt of an underloaded runner.
pub fn on_preempt(cpu: usize) {
    let now = now_tsc();
    let o = owner(cpu);
    o.util_sample(true);
    UTIL[cpu].store(o.util_q8, Ordering::Relaxed);
    let base = base_slice();
    let publish_due = now.saturating_sub(o.last_publish_tsc) >= base.saturating_mul(PUBLISH_EVERY_SLICES);

    let sc = scratch(cpu);
    let (pressure, n_cands) = {
        let rq = RQ[cpu].lock();
        let p = rq.pressure_q8();
        RDY[cpu].store(rq.ready_len() as u32, Ordering::Relaxed);
        // v0.19: allocation-free snapshot into the owner scratch (the
        // v0.18 `queued_snapshot()` built a Vec UNDER this lock).
        let n = if publish_due && p > 0 {
            rq.collect_queued(&mut sc.cands)
        } else {
            0
        };
        (p, n)
    };
    PUB_PRESSURE[cpu].store(pressure, Ordering::Relaxed);

    if publish_due {
        o.last_publish_tsc = now;
        match o.hyst.update(pressure) {
            Edge::Raised => {
                OVERLOAD.fetch_or(1u64 << cpu, Ordering::AcqRel);
            }
            Edge::Dropped => {
                OVERLOAD.fetch_and(!(1u64 << cpu), Ordering::AcqRel);
                SHELF[cpu].withdraw_all();
            }
            Edge::None => {}
        }
        if o.hyst.over {
            // Publish on the tick, never in the hot path: refresh the
            // showcase with the current worst slip offenders (v0.19: the
            // selection fills the owner scratch — no heap on the way).
            let n_off =
                select_offers_into(&sc.cands[..n_cands], now, base, K_SLOTS, &mut sc.offers);
            SHELF[cpu].republish(&sc.offers[..n_off]);
            // Hard starvation and no live underloaded core in sight:
            // wake ONE idle core (cheapest) so a pull can happen now.
            if pressure >= PRESSURE_HARD_Q8 {
                let online = crate::smp::online_mask();
                if let Some(idle) = cheapest_idle(cpu, online) {
                    ipi_resched(idle);
                }
            }
        }
    }

    // Variant-B source duty: thieves that failed the try-lock parked
    // their requests here — detach and hand over what is still valid.
    process_requests(cpu, now);

    // Periodic steal of an underloaded runner (idle-entry steals are
    // served by the idle loop, unthrottled by this rate limit).
    if now.saturating_sub(o.last_steal_tsc) >= base.saturating_mul(STEAL_EVERY_SLICES) {
        o.last_steal_tsc = now;
        let _ = try_steal(cpu, false);
    }
}

/// Variant-B source side: drain our request inbox, detach still-queued
/// victims (one queue section per request) and push them to the
/// thieves' handoff inboxes with a wake kick.
fn process_requests(cpu: usize, now: u64) {
    // v0.19: the inbox is a lock-free ring — pop per request (no inbox
    // lock, no Vec drain); the handoff push is lock-free too. A full
    // ring re-attaches the migrant to OUR queue: the thief's request
    // expires by timeout, nothing is lost.
    while let Some(r) = REQ_INBOX[cpu].pop() {
        if now > r.deadline_tsc {
            continue; // thief lost interest (timeout)
        }
        let handoff = {
            let mut rq = RQ[cpu].lock();
            if !rq.is_queued(r.task) {
                continue; // picked/gone/never was
            }
            let lag = rq.lag_of(r.task).unwrap_or(0);
            match rq.take_entity(r.task) {
                Some(e) => {
                    RDY[cpu].store(rq.ready_len() as u32, Ordering::Relaxed);
                    Some(Handoff { entity: e, lag })
                }
                None => None,
            }
        };
        let Some(h) = handoff else { continue };
        // Re-home first (concurrent kills/lookups route to the new owner;
        // the sweep covers the window) — reverted on push failure.
        HOME.lock().set_home(r.task, r.thief);
        match HANDOFF_INBOX[r.thief as usize].push(h) {
            Ok(()) => {
                if idle_bit(r.thief as usize) {
                    ipi_resched(r.thief as usize);
                }
            }
            Err(back) => {
                // Ring full (thief parked deep without draining): park
                // the migrant back on OUR queue; the request dies young.
                let base = base_slice();
                let stay = now.saturating_add(min_stay_cycles(back.entity.mig_count, base));
                let mut rq = RQ[cpu].lock();
                rq.attach_entity(back.entity, back.lag, stay);
                RDY[cpu].store(rq.ready_len() as u32, Ordering::Relaxed);
                HOME.lock().set_home(r.task, cpu as u8);
            }
        }
    }
}

// ───────────────────────── Idle path ─────────────────────────

/// Idle-entry service: clear the running deadline, sample utilisation
/// down, relax pressure (no dispatches happen) and let the hysteresis
/// drop the OVERLOADED flag of a drained core.
pub fn on_idle_entry(cpu: usize) {
    CUR_DL[cpu].store(0, Ordering::Release);
    let o = owner(cpu);
    o.util_sample(false);
    UTIL[cpu].store(o.util_q8, Ordering::Relaxed);
    let pressure = {
        let mut rq = RQ[cpu].lock();
        rq.relax_pressure();
        let p = rq.pressure_q8();
        RDY[cpu].store(rq.ready_len() as u32, Ordering::Relaxed);
        p
    };
    PUB_PRESSURE[cpu].store(pressure, Ordering::Relaxed);
    if o.hyst.update(pressure) == Edge::Dropped {
        OVERLOAD.fetch_and(!(1u64 << cpu), Ordering::AcqRel);
        SHELF[cpu].withdraw_all();
    }
}

/// Drain handoffs into MY queue (owner at schedule boundaries / idle
/// wakes). Returns how many migrants were attached.
pub fn drain_handoffs(cpu: usize) -> usize {
    // v0.19: lock-free pops into a fixed stack page, ONE queue section
    // for the attaches (the v0.18 drain built a Vec under the inbox
    // lock, then locked again for the attaches anyway).
    let mut page: [Option<Handoff>; 8] = [None; 8];
    let mut n = 0usize;
    while n < page.len() {
        match HANDOFF_INBOX[cpu].pop() {
            Some(h) => {
                page[n] = Some(h);
                n += 1;
            }
            None => break,
        }
    }
    if n == 0 {
        return 0;
    }
    let now = now_tsc();
    let base = base_slice();
    let mut rq = RQ[cpu].lock();
    for h in page.iter().take(n).flatten() {
        let stay = min_stay_cycles(h.entity.mig_count, base);
        rq.attach_entity(h.entity, h.lag, now.saturating_add(stay));
    }
    RDY[cpu].store(rq.ready_len() as u32, Ordering::Relaxed);
    n
}

/// Ready-count mirror read (idle loop's "is there work" peek).
#[inline]
pub fn ready(cpu: usize) -> u32 {
    RDY[cpu].load(Ordering::Relaxed)
}

// ───────────────────────── Thief path ─────────────────────────

/// Attempt ONE steal for `cpu`. `idle_trigger` relaxes the own-pressure
/// precondition (an idle core has nothing latency-critical to protect —
/// its own pressure is stale by construction) but keeps the backoff.
pub fn try_steal(cpu: usize, idle_trigger: bool) -> StealOutcome {
    let now = now_tsc();
    let o = owner(cpu);
    if now < o.steal_backoff_until {
        return StealOutcome::None;
    }
    if !idle_trigger
        && PUB_PRESSURE[cpu].load(Ordering::Relaxed) >= STEAL_PRESSURE_EPS_Q8
    {
        return StealOutcome::None; // thieves must not create victims
    }
    let online = crate::smp::online_mask();
    let my_util = UTIL[cpu].load(Ordering::Relaxed);
    let my_pressure = PUB_PRESSURE[cpu].load(Ordering::Relaxed);
    // v0.19: MEASURED capacity (perf.rs) instead of the hardcoded 256 —
    // admission and the fit term now follow real per-core rates.
    let me_view = CoreView {
        cap_q8: perf::cap_q8(cpu),
        util_q8: my_util,
        pressure_q8: my_pressure,
    };
    let w: Weights = DEFAULT_WEIGHTS;

    // Domain walk (v0.19): the REAL boot-built hierarchy — SMT siblings
    // first, then the rest of the LLC, then beyond the LLC on
    // multi-node machines; random start order so thieves do not herd.
    // Stops at the first level that yields prey; allocation-free.
    let start = (scramble(cpu, now) % MAX_CPUS as u64) as usize;
    for lvl in topology::steal_levels(cpu) {
        let over = OVERLOAD.load(Ordering::Acquire) & lvl.mask & online & !(1u64 << cpu);
        if over == 0 {
            continue;
        }
        let mut scanned = 0usize;
        for i in 0..MAX_CPUS {
            let src = (start + i) % MAX_CPUS;
            if (over >> src) & 1 == 0 {
                continue;
            }
            scanned += 1;
            if scanned > sched_lb::MAX_SOURCES_PER_STEAL {
                break;
            }
            // Do not drain a source that already fell below `lo`.
            let src_pressure = PUB_PRESSURE[src].load(Ordering::Acquire);
            if src_pressure <= PRESSURE_LO_Q8 {
                continue;
            }
            let shelf = &SHELF[src];
            if !shelf.any_offered() {
                continue;
            }
            let src_view = CoreView {
                cap_q8: perf::cap_q8(src),
                util_q8: UTIL[src].load(Ordering::Relaxed),
                pressure_q8: src_pressure,
            };
            let ctx = StealCtx {
                migcost_q8: lvl.migcost_q8,
                // v0.19: energy domain = shared LLC (the best
                // frequency-domain proxy available here); the EAS ΔE
                // term comes alive only across LLC boundaries now.
                same_energy_domain: topology::same_llc(cpu, src),
                // v0.19: domain-mean utilisations (the EAS cluster
                // inputs) instead of the two per-cpu values.
                cluster_util_me_q8: topology::domain_util(topology::llc_mask(cpu)),
                cluster_util_src_q8: topology::domain_util(topology::llc_mask(src)),
            };
            // Claim phase 1 + scoring (admission folded into the score:
            // inadmissible candidates score i32::MIN and lose).
            let best = shelf.claim_best(cpu as u8, |off| {
                if !admission_ok(&me_view, &src_view, off.util_q8) {
                    return i32::MIN;
                }
                score(off, &me_view, &src_view, &ctx, now, &w)
            });
            let Some((slot, claim, sc)) = best else { continue };
            if sc == i32::MIN {
                // Everything offered here is inadmissible for us —
                // release the winner and move to the next source.
                shelf.release(slot, claim.cycle);
                continue;
            }
            match transfer(cpu, src, slot, claim, now) {
                StealOutcome::Stolen => {
                    o.note_steal_ok();
                    return StealOutcome::Stolen;
                }
                StealOutcome::Requested => {
                    // Async in flight; the handoff inbox will deliver.
                    return StealOutcome::Requested;
                }
                StealOutcome::None => {
                    // Validation missed (task left the queue): next slot.
                    continue;
                }
            }
        }
    }
    o.note_steal_fail(now, base_slice());
    StealOutcome::None
}

/// Phase 2 — the transfer. Fast path: try-lock the source queue,
/// validate (still queued, not running, not throttled), detach with the
/// clamped lag, re-home, attach on MY queue with the anti-thrash
/// minimum stay. Fallback (source queue busy): park a timed request in
/// its inbox — the source detaches at its next preempt boundary and
/// pushes the migrant to our handoff inbox.
fn transfer(me: usize, src: usize, slot: usize, claim: sched_lb::Claim, now: u64) -> StealOutcome {
    let task = claim.offer.task;
    // Fast path (variant A): one try-lock, short section.
    if let Some(mut rq) = RQ[src].try_lock() {
        if rq.is_queued(task) {
            let lag = rq.lag_of(task).unwrap_or(0);
            let entity = rq.take_entity(task);
            RDY[src].store(rq.ready_len() as u32, Ordering::Relaxed);
            drop(rq);
            if let Some(e) = entity {
                // Re-home before attaching: concurrent kills/lookups
                // route to the new owner; the sweep covers the window.
                HOME.lock().set_home(task, me as u8);
                let base = base_slice();
                let stay = min_stay_cycles(e.mig_count, base);
                let mut my = RQ[me].lock();
                my.attach_entity(e, lag, now.saturating_add(stay));
                RDY[me].store(my.ready_len() as u32, Ordering::Relaxed);
                drop(my);
                SHELF[src].release(slot, claim.cycle);
                return StealOutcome::Stolen;
            }
        }
        // Validation failed: the victim is gone/running/throttled.
        SHELF[src].release(slot, claim.cycle);
        return StealOutcome::None;
    }
    // Fallback (variant B): ask the source to detach at its schedule().
    // v0.19: lock-free push; a full ring drops the request (best-effort
    // by design — the thief's backoff re-tries later).
    let timeout = base_slice().saturating_mul(STEAL_REQ_TIMEOUT_SLICES);
    let _dropped = REQ_INBOX[src].push(StealReq {
        task,
        thief: me as u8,
        posted_tsc: now,
        deadline_tsc: now.saturating_add(timeout),
    });
    SHELF[src].release(slot, claim.cycle);
    StealOutcome::Requested
}

// ───────────────────────── Host tests (routing slab) ─────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    /// Churn HomeTable against a std::HashMap reference model: mixed
    /// inserts/upserts/drops under a deterministic PRNG, with periodic
    /// full-agreement audits (the backward-shift deletion is the part
    /// this really hunts).
    #[test]
    fn home_table_matches_reference_model() {
        let mut t = HomeTable::new();
        let mut model: std::collections::HashMap<u128, u8> = std::collections::HashMap::new();
        let mut rng: u64 = 0x243F_6A88_85A3_08D3;
        let mut next_id = 1u128;
        let mut live: std::vec::Vec<u128> = std::vec::Vec::new();
        for step in 0..4000 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            if live.is_empty() || (rng % 5) < 3 {
                // Insert or upsert (existing id sometimes, fresh otherwise).
                let id = if (rng >> 8) % 4 == 0 && !live.is_empty() {
                    live[(rng >> 16) as usize % live.len()]
                } else {
                    next_id += 7; // monotonic-counter vibe
                    let id = next_id.wrapping_mul(0x9E37_79B9_7F4A_7C15); // spread
                    live.push(id);
                    id
                };
                let cpu = (step % 31) as u8;
                t.set_home(id, cpu);
                model.insert(id, cpu);
            } else {
                // Drop one.
                let idx = (rng >> 16) as usize % live.len();
                let id = live.swap_remove(idx);
                t.drop_entry(id);
                model.remove(&id);
            }
            if step % 97 == 0 {
                // Full-table agreement audit.
                for (id, cpu) in &model {
                    assert_eq!(
                        t.home_of(*id),
                        Some(*cpu),
                        "id {id} lost after churn step {step}"
                    );
                }
                assert_eq!(t.sweep(&|_| false), 0);
            }
        }
        // Sweep removes exactly the dead entries.
        let dead: std::vec::Vec<u128> = model.keys().copied().filter(|k| k & 1 == 0).collect();
        let before = model.len();
        let n = t.sweep(&|id| model.contains_key(&id) && id & 1 == 0);
        assert_eq!(n, dead.len());
        for id in &dead {
            model.remove(id);
        }
        assert_eq!(model.len(), before - n);
        for (id, cpu) in &model {
            assert_eq!(t.home_of(*id), Some(*cpu), "survivors reachable after sweep");
        }
    }

    #[test]
    fn home_pending_lifecycle() {
        let mut t = HomeTable::new();
        assert_eq!(t.home_of(42), None);
        // Parked weight without a home.
        t.park_weight(42, 777);
        assert_eq!(t.home_of(42), None, "a parked weight is not a home");
        assert_eq!(t.take_pending(42), Some(777));
        assert_eq!(t.take_pending(42), None); // consumed once
        assert_eq!(t.home_of(42), None, "the empty slot gc'd itself");
        // Home + pending coexist (the in-transit reweight window).
        t.set_home(42, 3);
        t.park_weight(42, 888);
        assert_eq!(t.home_of(42), Some(3));
        assert_eq!(t.take_pending(42), Some(888));
        assert_eq!(
            t.home_of(42),
            Some(3),
            "taking the weight keeps the home"
        );
        // Drop clears everything.
        assert_eq!(t.drop_entry(42), Some(3));
        assert_eq!(t.home_of(42), None);
        assert_eq!(t.drop_entry(42), None, "double drop is a no-op");
        // Probing stays sound after the churn above.
        t.set_home(9, 1);
        t.set_home(10, 2);
        assert_eq!(t.home_of(9), Some(1));
        assert_eq!(t.home_of(10), Some(2));
        assert_eq!(t.home_of(11), None);
    }
}
