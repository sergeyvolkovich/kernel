// ==== EEVDF: Earliest Eligible Virtual Deadline First (policy library) ====
//
// A self-contained, platform-free implementation of the EEVDF fair-scheduling
// policy (Stoica & Abdel-Wahab 1995; the same family as the Linux 6.6+
// CFS replacement). This crate is pure policy + data structures:
//
//   * NO locking discipline of its own — every method takes `&mut self`;
//     the scheduler backend owns the run-queue and serializes access
//     (in this kernel: a leaf-rank spin lock, see backend `sched.rs`);
//   * NO time source — the backend passes raw counter deltas (TSC cycles
//     on x86_64); all bookkeeping is in those units;
//   * ids are opaque `u128` (L4 global thread IDs map 1:1).
//
// ───────────────────────── Model ─────────────────────────
//
// Each runnable entity carries:
//
//   weight    w    — derived from the L4 priority (0..=255) through the
//                    classic Linux nice-weight table (10% steps);
//   vruntime  v    — service received, normalized by weight:
//                        v += delta_exec * NICE0 / w
//                    so an entity with 2x weight accumulates vruntime 2x
//                    slower for the same executed time;
//   deadline   d   — virtual deadline of the CURRENT time slice:
//                        d = v + slice * NICE0 / w
//                    heavier weight ⇒ shorter virtual slice ⇒ runs sooner
//                    (this is the EEVDF latency property).
//
// Eligibility (which entities may be picked right now) uses the
// weight-averaged vruntime of the queued entities:
//
//   avg = sum(w_i * v_i) / sum(w_i)
//
// An entity is eligible iff `v_e <= avg` (its received service does not
// exceed its fair share — it is "owed" service). The entity with the
// minimum vruntime is always eligible (avg is a weighted mean), so the
// pick scan below always terminates.
//
// Pick rule: among ELIGIBLE entities take the one with the EARLIEST
// (deadline, vruntime, id) — earliest eligible virtual deadline first.
//
// ───────────────────────── Wake/rotate/sleep ─────────────────────────
//
//   rotate (preempted, still ready): keeps its deadline while the slice
//       budget lasts; a fresh slice+deadline is issued once the current
//       slice is exhausted — so a preempted entity is NOT penalized;
//   wake (blocked/suspended/throttled -> ready): the entity keeps its
//       vruntime (service history), but sleeper credit is CLAMPED —
//       v := max(v, avg - LAG_CAP_SLICES * vslice) — bounding the
//       unfairness a long sleeper may reclaim after waking;
//   fresh entity (first enqueue): v := avg (starts fair, does not jump
//       the queue from zero), d := v + vslice.
//
// ───────────────────────── Preemption hints ─────────────────────────
//
// The backend must wake idle CPUs and, occasionally, ask running CPUs to
// re-evaluate (preempt). Instead of broadcasting resched-IPIs on every
// wakeup (the old behaviour), the run-queue tracks the (deadline, cpu)
// of every currently-running entity and offers
// `preempt_cpus(min_deadline)`: CPUs whose running entity has a LATER
// deadline than the best queued one — those are the only ones that would
// switch threads anyway.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicUsize, Ordering};

// ───────────────────────── Weight table ─────────────────────────

/// Reference weight (nice 0) — the unit of the virtual-time scaling.
pub const NICE0_WEIGHT: u32 = 1024;

/// Linux-style nice weights, index = nice + 20 (10% steps per level).
pub const NICE_WEIGHTS: [u32; 40] = [
    /* -20 */ 88761, 71755, 56483, 46273, 36291,
    /* -15 */ 29154, 23254, 18705, 14949, 11916,
    /* -10 */ 9548, 7620, 6100, 4904, 3906,
    /*  -5 */ 3121, 2501, 1991, 1586, 1277,
    /*   0 */ 1024, 820, 655, 526, 423,
    /*   5 */ 335, 272, 215, 172, 137,
    /*  10 */ 110, 87, 70, 56, 45,
    /*  15 */ 36, 29, 23, 18, 15,
];

/// Default weight when a thread is enqueued before its priority is known
/// (creation order: the kernel fires `on_priority_change` first, but the
/// backend must tolerate a priority-less enqueue).
pub const DEFAULT_WEIGHT: u32 = NICE0_WEIGHT;

/// Map an L4 priority (0 = lowest, 255 = highest, seL4-style) to a weight.
///
/// Linear mapping onto the 40-step nice table: prio 0 -> nice 19 (weight
/// 15), prio 255 -> nice -20 (weight 88761), default prio 100 -> nice 4
/// (weight 820). Monotonic, so higher priority always means more CPU
/// share and earlier virtual deadlines.
pub const fn weight_for_priority(priority: u8) -> u32 {
    // nice = 19 - prio * 39 / 255 in [-20, 19]; table index = nice + 20
    // = 39 - prio * 39 / 255, always in [0, 39] (no underflow).
    let idx = 39u32 - (priority as u32 * 39) / 255;
    NICE_WEIGHTS[idx as usize]
}

/// Weighted virtual time delta: `delta_exec * NICE0 / weight`
/// (u128 intermediate — delta_exec can be large on GHz-class TSCs).
#[inline]
fn scaled(delta_exec: u64, weight: u32) -> u64 {
    ((delta_exec as u128 * NICE0_WEIGHT as u128) / weight.max(1) as u128) as u64
}

/// Virtual slice length for a weight (base slice scaled like vruntime).
#[inline]
fn vslice(base_slice: u64, weight: u32) -> u64 {
    scaled(base_slice, weight)
}

/// EWMA update with α=1/2 on Q8 values: halfway toward the sample.
/// (Both directions — a saturating `sample − old` would freeze on the
/// first decrease, which is exactly what the utilisation/tardiness
/// trackers need to forget stale history.)
#[inline]
fn ewma2(old: u32, sample: u32) -> u32 {
    if sample >= old {
        old + ((sample - old) >> 1)
    } else {
        old - ((old - sample) >> 1)
    }
}

/// EWMA update with α=1/4 on Q8 values (slower tracker — pressure).
#[inline]
fn ewma4(old: u32, sample: u32) -> u32 {
    if sample >= old {
        old + ((sample - old) >> 2)
    } else {
        old - ((old - sample) >> 2)
    }
}

// ───────────────────────── Entity ─────────────────────────

/// Scheduling state of one thread, cached by the backend (the kernel TCB
/// owns the authoritative state; this is the scheduler's private mirror).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entity {
    /// Opaque id (L4 global ThreadId as u128).
    pub id: u128,
    /// Current weight (from the last `set_weight`/registration).
    pub weight: u32,
    /// Weight-normalized executed time (virtual runtime).
    pub vruntime: u64,
    /// Virtual deadline of the current slice.
    pub deadline: u64,
    /// Full length of the current slice (raw time units).
    pub slice: u64,
    /// Remainder of the current slice (0 ⇒ next rotate takes a new one).
    pub slice_left: u64,
    /// On the run queue (queued, not yet picked).
    pub on_rq: bool,
    /// Parked by the CPU-quota throttle (not ready until period end).
    pub throttled: bool,
    // ── v0.18 load-balancer bookkeeping (showcase/steal; see sched_lb) ──
    /// EWMA (Q8, 0..=255) of dispatch-time tardiness `(V − vd)/vslice`
    /// sampled at every pick. Latency-sensitive tasks that keep missing
    /// their virtual deadlines converge to a high value — this is the
    /// "deadline slip" signal that drives offer publication and steal
    /// scoring.
    pub tard_q8: u32,
    /// EWMA (Q8, 0..=255) of the inter-park duty cycle `exec/window`
    /// (window = time since the previous park). Approximates the task's
    /// CPU demand for steal admission control. Starts at 255 (assume
    /// CPU-bound until a park proves otherwise — conservative admission).
    pub util_q8: u32,
    /// Heterogeneity hint (Q8 ratio rate_big/rate_little, 256 = 1.0).
    /// v0.19: maintained from measured per-task dispatch-segment IPC on
    /// the two capacity classes (see [`RunQueue::note_perf`]) — once both
    /// sides have samples it tracks the task's own cross-class rate
    /// ratio; until then it stays at the neutral 256. Carried across
    /// migrations so the destination scores the task with its history.
    pub speedup_q8: u32,
    /// v0.19: EWMA (Q8, IPC×256) of the task's dispatch-segment IPC
    /// measured on a max-capacity core (cap_q8 >= 256). 0 = no sample.
    pub ipc_fast_q8: u32,
    /// v0.19: same, measured on a lower-capacity core. 0 = no sample.
    pub ipc_slow_q8: u32,
    /// TSC of the last park (dispatch segment end). Cache-hotness input:
    /// a task parked long ago is cheap to migrate ("не cache-hot").
    pub last_ran: u64,
    /// Completed migrations (steals). Anti-thrash: the minimum-stay
    /// window grows exponentially with this counter.
    pub mig_count: u16,
    /// TSC before which the task must not be offered for stealing again
    /// (freshly stolen tasks stay put for a few slices).
    pub cooldown_until: u64,
}

/// Ordering key of the run queue: earliest deadline first, ties broken
/// by vruntime then id (deterministic).
type Key = (u64, u64, u128);

#[inline]
fn key_of(e: &Entity) -> Key {
    (e.deadline, e.vruntime, e.id)
}

/// A currently-running entity: deadline + the CPU it was dispatched on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunningEnt {
    pub deadline: u64,
    pub cpu: usize,
}

/// A queued (ready, not running) thread as seen by the offer publisher /
/// steal scorer (v0.18). Plain data snapshot of an [`Entity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueuedCand {
    pub id: u128,
    pub weight: u32,
    /// Full slice length (raw time units).
    pub slice: u64,
    /// Virtual deadline of the current slice.
    pub deadline: u64,
    /// Deadline-slip EWMA, Q8.
    pub tard_q8: u32,
    /// CPU-demand EWMA, Q8.
    pub util_q8: u32,
    /// Big/little rate ratio hint, Q8 (256 = 1.0).
    pub speedup_q8: u32,
    /// TSC of the last park (cache-hotness).
    pub last_ran: u64,
    /// Migration cooldown gate (TSC).
    pub cooldown_until: u64,
}

impl QueuedCand {
    /// v0.19: zeroed placeholder for const-initializing per-CPU scratch
    /// buffers (the allocation-free publisher snapshot path).
    pub const ZERO: QueuedCand = QueuedCand {
        id: 0,
        weight: 0,
        slice: 0,
        deadline: 0,
        tard_q8: 0,
        util_q8: 0,
        speedup_q8: 0,
        last_ran: 0,
        cooldown_until: 0,
    };
}

// ───────────────────────── Run queue ─────────────────────────

/// How much sleeper credit a waking entity may keep, in virtual slices
/// (avg - LAG_CAP*vslice is the furthest behind the average a waker may
/// start; bounds post-wake starvation of the other entities).
pub const LAG_CAP_SLICES: u64 = 2;

/// v0.19: running-set capacity. Steady state holds ONE entry (a queue
/// dispatches a single thread at a time); spare slots cover transient
/// rotate/migration windows. A fixed array keeps the pick/park path off
/// the heap — the old BTreeMap paid a talc alloc/dealloc pair on every
/// dispatch segment, under the queue lock (leaf SCHED taking KMEM).
const MAX_RUNNING: usize = 8;

/// v0.19: one slot of the fixed running set.
#[derive(Debug, Clone, Copy)]
struct RunningSlot {
    in_use: bool,
    id: u128,
    ent: RunningEnt,
}

/// EEVDF run queue: ordered ready entities + per-thread state cache +
/// running-entity index (for preemption hints).
///
/// Invariants (all under the caller's serialization):
///   * `queue` keys and `entities[id].on_rq` agree;
///   * `weight_sum` / `wv_sum` track exactly the queued entities
///     (`wv_sum = sum(w_i * v_i)`), so `avg_vruntime()` is the weighted
///     mean of the QUEUED vruntimes;
///   * `running` contains exactly the dispatched-but-not-yet-requeued
///     entities (picked but not rotated/throttled/blocked);
///   * `ready` (atomic) == number of queued entities — a lock-free
///     "is there work" peek for idle loops.
pub struct RunQueue {
    /// (deadline, vruntime, id) -> id, the pick order.
    queue: BTreeMap<Key, u128>,
    /// Per-thread cached state; persists while blocked (service history).
    entities: BTreeMap<u128, Entity>,
    /// Dispatched entities: fixed slots (see [`MAX_RUNNING`]).
    running: [RunningSlot; MAX_RUNNING],
    /// sum of queued weights (W).
    weight_sum: u64,
    /// sum of queued (w_i * v_i) (u128: 512 * 88761 * vruntime).
    wv_sum: u128,
    /// Monotonic floor of observed vruntime (placement anchor).
    min_vruntime: u64,
    /// Base slice in raw time units (backend passes TSC cycles).
    base_slice: u64,
    /// Queued entity count — lock-free ready peek (idle loop).
    ready: AtomicUsize,
    /// v0.18: EWMA (Q8, 0..=255) of the share of LATE dispatches on this
    /// queue — "pressure". Sampled at every pick (late = V > vd of the
    /// chosen entity). Drives offer-publication hysteresis and steal
    /// preconditions in the backend (sched_lb).
    pressure_q8: u32,
}

impl RunQueue {
    /// Empty queue with the given base slice (raw time units per slice).
    pub const fn new(base_slice: u64) -> Self {
        Self {
            queue: BTreeMap::new(),
            entities: BTreeMap::new(),
            running: [const {
                RunningSlot {
                    in_use: false,
                    id: 0,
                    ent: RunningEnt { deadline: 0, cpu: 0 },
                }
            }; MAX_RUNNING],
            weight_sum: 0,
            wv_sum: 0,
            min_vruntime: 0,
            base_slice,
            ready: AtomicUsize::new(0),
            pressure_q8: 0,
        }
    }

    /// Base slice (raw time units).
    pub fn base_slice(&self) -> u64 {
        self.base_slice
    }

    /// Re-fix the base slice (raw time units). The backend calls this
    /// once, right after time-source calibration and BEFORE SMP start /
    /// the first enqueue (the constructor cannot know the calibrated
    /// frequency; slices granted before this call use the stale value).
    pub fn set_base_slice(&mut self, cycles: u64) {
        self.base_slice = cycles.max(1);
    }

    /// Queued entity count (approximate, lock-free: maintained with
    /// relaxed atomics by the mutators under the caller's lock).
    pub fn ready_len(&self) -> usize {
        self.ready.load(Ordering::Relaxed)
    }

    /// Weighted mean of the queued vruntimes; `min_vruntime` when the
    /// queue is empty. This is the EEVDF eligibility threshold.
    pub fn avg_vruntime(&self) -> u64 {
        if self.weight_sum == 0 {
            return self.min_vruntime;
        }
        (self.wv_sum / self.weight_sum as u128) as u64
    }

    /// Earliest queued virtual deadline (preemption hint input).
    pub fn min_queued_deadline(&self) -> Option<u64> {
        self.queue.keys().next().map(|k| k.0)
    }

    /// Snapshot of the running entities (id, deadline, cpu) — the caller
    /// decides which CPUs to nudge.
    pub fn running_snapshot(&self) -> impl Iterator<Item = (u128, RunningEnt)> + '_ {
        self.running.iter().filter(|s| s.in_use).map(|s| (s.id, s.ent))
    }

    /// Is the entity queued? (backend diagnostics)
    pub fn is_queued(&self, id: u128) -> bool {
        self.entities.get(&id).is_some_and(|e| e.on_rq)
    }

    /// Is the thread currently dispatched from THIS queue's running set?
    /// (v0.18 wake-placement guard: a mid-slice rotate requeues on its
    /// own queue — the entity is cache-hot and the EEVDF ROTATE path
    /// must preserve its deadline; it is not a push-assist candidate.)
    pub fn is_running_here(&self, id: u128) -> bool {
        self.running.iter().any(|s| s.in_use && s.id == id)
    }

    // ───────────────── v0.19: fixed running-set helpers ─────────────────

    /// Drop a dispatched entity (park/rotate/throttle/migrate/kill);
    /// returns whether it WAS in the running set (the rotate path).
    fn running_take(&mut self, id: u128) -> bool {
        if let Some(slot) = self.running.iter_mut().find(|s| s.in_use && s.id == id) {
            slot.in_use = false;
            true
        } else {
            false
        }
    }

    /// Drop a dispatched entity (park/rotate/throttle/migrate/kill).
    fn running_remove(&mut self, id: u128) {
        let _ = self.running_take(id);
    }

    /// Live running-set size (diagnostics/tests).
    pub fn running_len(&self) -> usize {
        self.running.iter().filter(|s| s.in_use).count()
    }

    /// Register (or re-register) a thread with a weight. Off-queue; the
    /// entity keeps no service history on re-registration. Called on
    /// thread creation (`on_priority_change` fires before the first
    /// enqueue, seeding the weight).
    pub fn register(&mut self, id: u128, weight: u32) {
        self.entities.insert(
            id,
            Entity {
                id,
                weight: weight.max(1),
                vruntime: self.avg_vruntime(),
                deadline: 0,
                slice: self.base_slice,
                slice_left: 0,
                on_rq: false,
                throttled: false,
                tard_q8: 0,
                util_q8: 255,
                speedup_q8: 256,
                ipc_fast_q8: 0,
                ipc_slow_q8: 0,
                last_ran: 0,
                mig_count: 0,
                cooldown_until: 0,
            },
        );
    }

    /// Drop a thread's cached state entirely (thread destroyed). Returns
    /// whether it was queued (the caller maintains its ready counter if
    /// it keeps one separate). Frees the entity and any queue/running
    /// membership.
    pub fn unregister(&mut self, id: u128) -> bool {
        let was_queued = self.is_queued(id);
        if self.entities.get(&id).is_some_and(|e| e.on_rq) {
            self.queue_remove(id);
        }
        self.running_remove(id);
        self.entities.remove(&id);
        if was_queued {
            self.ready.fetch_sub(1, Ordering::Relaxed);
        }
        was_queued
    }

    /// Priority change: update the weight and, if queued, reposition.
    /// Vruntime (service history) is kept; the deadline is recomputed
    /// from the current vruntime under the new weight — approximation of
    /// the full EEVDF reweight (lag-preserving rescale), sufficient for
    /// interactive priority changes.
    pub fn set_weight(&mut self, id: u128, weight: u32) {
        let Some(e) = self.entities.get_mut(&id) else { return };
        let w = weight.max(1);
        if e.on_rq {
            // Remove under the old key, reinsert with the recomputed
            // deadline under the new weight.
            let old_key = key_of(e);
            let mut updated = *e;
            updated.weight = w;
            updated.deadline = updated.vruntime + vslice(self.base_slice, w);
            self.queue.remove(&old_key);
            self.weight_sum = self.weight_sum.wrapping_sub(e.weight as u64);
            self.wv_sum = self
                .wv_sum
                .wrapping_sub(e.weight as u128 * e.vruntime as u128);
            self.queue.insert(key_of(&updated), id);
            self.weight_sum = self.weight_sum.wrapping_add(w as u64);
            self.wv_sum = self
                .wv_sum
                .wrapping_add(w as u128 * updated.vruntime as u128);
            *e = updated;
            return;
        }
        e.weight = w;
    }

    /// Mark the entity as parked by the CPU-quota throttle (off-queue by
    /// construction — it was running; remove the running entry).
    /// `enqueue` on a throttled entity (period boundary) clears the flag.
    pub fn mark_throttled(&mut self, id: u128) {
        self.running_remove(id);
        if let Some(e) = self.entities.get_mut(&id) {
            e.throttled = true;
        }
    }

    /// Is the entity currently parked in the throttle list?
    pub fn is_throttled(&self, id: u128) -> bool {
        self.entities.get(&id).is_some_and(|e| e.throttled)
    }

    /// All cached entity ids (backend sweep: unregister destroyed threads).
    pub fn entity_ids(&self) -> impl Iterator<Item = u128> + '_ {
        self.entities.keys().copied()
    }

    /// Number of cached entities (diagnostics).
    pub fn entity_count(&self) -> usize {
        self.entities.len()
    }

    // ───────────────────────── Core transitions ─────────────────────────

    /// Thread became ready. Exactly one of:
    ///
    ///   * fresh entity (never registered): registered at `avg` vruntime,
    ///     full slice — starts fair, no queue jump;
    ///   * ROTATE — the entity is currently in `running` (preempted but
    ///     still ready): keeps its deadline while slice budget remains,
    ///     otherwise takes a fresh slice + deadline;
    ///   * WAKE — blocked/suspended/throttled before: sleeper-lag-clamped
    ///     vruntime, fresh slice + deadline.
    ///
    /// Idempotent: enqueue of an already-queued entity is a no-op.
    pub fn enqueue(&mut self, id: u128) {
        // ROTATE: entity is dispatched right now (preempt-rotate path).
        if self.running_take(id) {
            let Some(e) = self.entities.get_mut(&id) else { return };
            if e.slice_left > 0 {
                // Slice budget remains: keep the deadline, requeue as-is.
                e.on_rq = true;
                let k = key_of(e);
                let w = e.weight as u64;
                let v = e.vruntime as u128 * e.weight as u128;
                self.queue.insert(k, id);
                self.weight_sum = self.weight_sum.wrapping_add(w);
                self.wv_sum = self.wv_sum.wrapping_add(v);
                self.ready.fetch_add(1, Ordering::Relaxed);
                return;
            }
            // Slice exhausted: fresh slice + deadline at current vruntime.
            e.slice = self.base_slice;
            e.slice_left = self.base_slice;
            e.deadline = e.vruntime + vslice(self.base_slice, e.weight);
            e.on_rq = true;
            let k = key_of(e);
            let w = e.weight as u64;
            let v = e.vruntime as u128 * e.weight as u128;
            self.queue.insert(k, id);
            self.weight_sum = self.weight_sum.wrapping_add(w);
            self.wv_sum = self.wv_sum.wrapping_add(v);
            self.ready.fetch_add(1, Ordering::Relaxed);
            return;
        }

        // Already queued (defensive; eager dequeue makes this impossible).
        if self.entities.get(&id).is_some_and(|e| e.on_rq) {
            return;
        }

        let avg = self.avg_vruntime();
        if let Some(e) = self.entities.get_mut(&id) {
            // WAKE: clamp sleeper credit to LAG_CAP_SLICES virtual slices.
            let cap = LAG_CAP_SLICES.saturating_mul(vslice(self.base_slice, e.weight));
            if e.vruntime.saturating_add(cap) < avg {
                e.vruntime = avg - cap;
            }
            e.throttled = false;
            e.slice = self.base_slice;
            e.slice_left = self.base_slice;
            e.deadline = e.vruntime + vslice(self.base_slice, e.weight);
            e.on_rq = true;
            let k = key_of(e);
            let w = e.weight as u64;
            let v = e.vruntime as u128 * e.weight as u128;
            self.queue.insert(k, id);
            self.weight_sum = self.weight_sum.wrapping_add(w);
            self.wv_sum = self.wv_sum.wrapping_add(v);
            self.ready.fetch_add(1, Ordering::Relaxed);
            return;
        }

        // FRESH: register at avg vruntime with a full slice.
        let e = Entity {
            id,
            weight: DEFAULT_WEIGHT,
            vruntime: avg,
            deadline: avg + vslice(self.base_slice, DEFAULT_WEIGHT),
            slice: self.base_slice,
            slice_left: self.base_slice,
            on_rq: true,
            throttled: false,
            tard_q8: 0,
            util_q8: 255,
            speedup_q8: 256,
            ipc_fast_q8: 0,
            ipc_slow_q8: 0,
            last_ran: 0,
            mig_count: 0,
            cooldown_until: 0,
        };
        let k = key_of(&e);
        self.queue.insert(k, id);
        self.weight_sum = self.weight_sum.wrapping_add(e.weight as u64);
        self.wv_sum = self
            .wv_sum
            .wrapping_add(e.weight as u128 * e.vruntime as u128);
        self.ready.fetch_add(1, Ordering::Relaxed);
        self.entities.insert(id, e);
    }

    /// Thread left the ready/running set (blocked, suspended or dead).
    /// Eager removal from the ordered queue keeps the weight accounting
    /// free of phantom entries (unlike the lazy-deschedule ring the old
    /// backend used). Idempotent.
    pub fn dequeue(&mut self, id: u128) {
        if self.entities.get(&id).is_some_and(|e| e.on_rq) {
            self.queue_remove(id);
            self.ready.fetch_sub(1, Ordering::Relaxed);
        }
        self.running_remove(id);
    }

    /// Charge executed time to the (running) entity and advance the
    /// virtual clock floor. Safe after `dequeue` as well (the entity
    /// persists — service must be recorded even if the thread blocked
    /// before the charge reached the backend).
    pub fn charge(&mut self, id: u128, delta_exec: u64) {
        let Some(e) = self.entities.get_mut(&id) else { return };
        let dv = scaled(delta_exec, e.weight);
        if e.on_rq {
            // Queued entity being charged (rare: charge landed after a
            // cross-CPU wake) — keep the sums consistent.
            let old_key = key_of(e);
            self.weight_sum = self.weight_sum.wrapping_sub(e.weight as u64);
            self.wv_sum = self
                .wv_sum
                .wrapping_sub(e.weight as u128 * e.vruntime as u128);
            e.vruntime = e.vruntime.saturating_add(dv);
            e.slice_left = e.slice_left.saturating_sub(delta_exec);
            self.weight_sum = self.weight_sum.wrapping_add(e.weight as u64);
            self.wv_sum = self
                .wv_sum
                .wrapping_add(e.weight as u128 * e.vruntime as u128);
            let new_key = key_of(e);
            if old_key != new_key {
                if let Some(v) = self.queue.remove(&old_key) {
                    self.queue.insert(new_key, v);
                }
            }
        } else {
            e.vruntime = e.vruntime.saturating_add(dv);
            e.slice_left = e.slice_left.saturating_sub(delta_exec);
        }
        if e.vruntime > self.min_vruntime {
            self.min_vruntime = e.vruntime;
        }
    }

    /// Pick the entity to dispatch next: earliest virtual deadline among
    /// ELIGIBLE entities (`v <= avg`, tiny epsilon for the integer floor
    /// of the division). The minimum-vruntime entity is always eligible
    /// (avg is a weighted mean), so the scan terminates; the leftmost
    /// fallback is belt-and-braces. The entity moves to the running set
    /// (deadline + cpu recorded for preemption hints).
    ///
    /// v0.18: the pick also samples the deadline-slip signal — if the
    /// chosen entity's virtual deadline is already in the past at pick
    /// time (`V > vd`), the task was waiting too long. Per-task EWMA of
    /// `(V − vd)/vslice` lands in `Entity::tard_q8`; the per-queue share
    /// EWMA lands in `pressure_q8` (see [`RunQueue::pressure_q8`]).
    /// Short-slice (latency-nice) tasks trip first, so the signal
    /// naturally isolates latency-sensitive load.
    pub fn pick(&mut self, cpu: usize) -> Option<u128> {
        let avg = self.avg_vruntime();
        let eps = 1; // integer-floor tolerance of the weighted mean
        let mut chosen: Option<Key> = None;
        for k in self.queue.keys() {
            let e = self
                .entities
                .get(&k.2)
                .expect("queue key maps to a cached entity");
            if e.vruntime <= avg.saturating_add(eps) {
                chosen = Some(*k);
                break;
            }
        }
        let key = chosen.or_else(|| self.queue.keys().next().copied())?;
        let id = self.queue.remove(&key)?;
        let e = self
            .entities
            .get_mut(&id)
            .expect("queued entity is cached");
        debug_assert!(e.on_rq);
        // v0.18: deadline-slip sampling (BEFORE the entity leaves the
        // queued set — `avg` still includes its weight/vruntime).
        let vd = e.deadline;
        let vs = vslice(self.base_slice, e.weight).max(1);
        let slip = avg.saturating_sub(vd); // 0 unless the deadline passed
        let sample = ((slip as u128 * 256) / vs as u128).min(255) as u32;
        e.tard_q8 = ewma2(e.tard_q8, sample);
        let late_x256: u32 = if slip > 0 { 256 } else { 0 };
        self.pressure_q8 = ewma4(self.pressure_q8, late_x256);
        e.on_rq = false;
        self.weight_sum = self.weight_sum.wrapping_sub(e.weight as u64);
        self.wv_sum = self
            .wv_sum
            .wrapping_sub(e.weight as u128 * e.vruntime as u128);
        self.ready.fetch_sub(1, Ordering::Relaxed);
        if e.vruntime > self.min_vruntime {
            self.min_vruntime = e.vruntime;
        }
        // Record the dispatch in the running set. Disjoint-field writes
        // (`self.running` while the `e` borrow of `self.entities` is
        // live) keep the borrow checker happy; overflow recycles slot 0
        // (see `MAX_RUNNING`).
        match self.running.iter_mut().find(|s| !s.in_use) {
            Some(slot) => {
                slot.in_use = true;
                slot.id = id;
                slot.ent = RunningEnt {
                    deadline: e.deadline,
                    cpu,
                };
            }
            None => {
                debug_assert!(false, "eevdf: running set overflow");
                self.running[0] = RunningSlot {
                    in_use: true,
                    id,
                    ent: RunningEnt {
                        deadline: e.deadline,
                        cpu,
                    },
                };
            }
        }
        Some(id)
    }

    /// CPUs whose running entity has a deadline strictly later than
    /// `min_deadline` (the best queued deadline) — the only CPUs that
    /// would actually switch threads if they re-ran the picker now.
    /// Excludes `skip_cpu` (its own enqueue path re-evaluates anyway).
    pub fn preempt_cpus(&self, min_deadline: u64, skip_cpu: usize) -> impl Iterator<Item = usize> + '_ {
        self.running
            .iter()
            .filter(move |s| s.in_use)
            .filter(move |s| s.ent.cpu != skip_cpu && s.ent.deadline > min_deadline)
            .map(|s| s.ent.cpu)
    }

    // ───────────────── v0.18: steal/migration support (sched_lb) ─────────────────

    /// Current queue pressure (Q8): EWMA of the late-dispatch share.
    /// Read by the backend's tick path (publish hysteresis) and mirrored
    /// into a lock-free per-CPU atomic for steal preconditions.
    pub fn pressure_q8(&self) -> u32 {
        self.pressure_q8
    }

    /// Decay pressure toward zero (backend calls this when the CPU goes
    /// idle: no dispatches happen, so the late share is vacuously 0 and
    /// the OVERLOADED flag must not stick on a drained core). Values
    /// below ~1.5% snap to zero — a plain `p − p/4` has a fixed point
    /// at p < 4 and would never fully drain.
    pub fn relax_pressure(&mut self) {
        let p = self.pressure_q8;
        self.pressure_q8 = if p <= 4 { 0 } else { p - (p >> 2) };
    }

    /// Is a thread registered in this queue's cache (queued, running or
    /// blocked-with-history)? The backend consults this when routing a
    /// first enqueue (fresh registration vs. wake) and when applying a
    /// priority change (entity present -> reweight here, else park the
    /// weight until the first enqueue).
    pub fn has_entity(&self, id: u128) -> bool {
        self.entities.contains_key(&id)
    }

    /// Copy of the cached entity (diagnostics / balancer scoring).
    pub fn entity_of(&self, id: u128) -> Option<Entity> {
        self.entities.get(&id).copied()
    }

    /// Queued (pickable, not running) virtual deadline of a thread — the
    /// backend uses it to decide whether a target CPU should preempt its
    /// current task for a freshly enqueued one.
    pub fn deadline_of(&self, id: u128) -> Option<u64> {
        self.entities.get(&id).filter(|e| e.on_rq).map(|e| e.deadline)
    }

    /// A queued-thread snapshot for the offer publisher: everything the
    /// showcase selection and the thief-side scoring need, collected in
    /// one pass under the caller's lock (returned owned — the publisher
    /// releases the queue lock before touching the slot array).
    pub fn queued_snapshot(&self) -> alloc::vec::Vec<QueuedCand> {
        self.entities
            .values()
            .filter(|e| e.on_rq)
            .map(|e| QueuedCand {
                id: e.id,
                weight: e.weight,
                slice: e.slice,
                deadline: e.deadline,
                tard_q8: e.tard_q8,
                util_q8: e.util_q8,
                speedup_q8: e.speedup_q8,
                last_ran: e.last_ran,
                cooldown_until: e.cooldown_until,
            })
            .collect()
    }

    /// v0.19: allocation-free variant of [`RunQueue::queued_snapshot`]
    /// for the preempt-boundary publisher: fills `out` (truncating at
    /// its length) and returns how many candidates were copied. The
    /// caller supplies a per-CPU scratch buffer, so the queue-lock
    /// section stays free of heap traffic (the Vec-returning snapshot
    /// allocated under the lock — leaf SCHED taking KMEM, against the
    /// lock discipline).
    pub fn collect_queued(&self, out: &mut [QueuedCand]) -> usize {
        let mut n = 0;
        for e in self.entities.values() {
            if n == out.len() {
                break;
            }
            if !e.on_rq {
                continue;
            }
            out[n] = QueuedCand {
                id: e.id,
                weight: e.weight,
                slice: e.slice,
                deadline: e.deadline,
                tard_q8: e.tard_q8,
                util_q8: e.util_q8,
                speedup_q8: e.speedup_q8,
                last_ran: e.last_ran,
                cooldown_until: e.cooldown_until,
            };
            n += 1;
        }
        n
    }

    /// v0.19: feed one dispatch-segment IPC sample (Q8, 256 = IPC 1.0)
    /// for the task, measured on a core whose fleet-normalized capacity
    /// is `core_cap_q8` (256 = the fastest class). Updates the per-class
    /// tracker (`ipc_fast_q8` on a max-capacity core, `ipc_slow_q8`
    /// below); once both classes have samples, `speedup_q8` tracks their
    /// ratio (clamped to [0.75x, 2x] in Q8) — the per-task big/little
    /// hint carried into `Offer::speedup_q8` for steal scoring.
    pub fn note_perf(&mut self, id: u128, core_cap_q8: u32, seg_ipc_q8: u32) {
        let Some(e) = self.entities.get_mut(&id) else { return };
        if seg_ipc_q8 == 0 {
            return;
        }
        if core_cap_q8 >= 256 {
            e.ipc_fast_q8 = match e.ipc_fast_q8 {
                0 => seg_ipc_q8,
                old => ewma4(old, seg_ipc_q8),
            };
        } else {
            e.ipc_slow_q8 = match e.ipc_slow_q8 {
                0 => seg_ipc_q8,
                old => ewma4(old, seg_ipc_q8),
            };
        }
        if e.ipc_fast_q8 > 0 && e.ipc_slow_q8 > 0 {
            // This task's own cross-class rate ratio; the clamp bounds
            // scoring noise from tiny samples.
            let ratio =
                ((e.ipc_fast_q8 as u64 * 256) / e.ipc_slow_q8 as u64).clamp(192, 512) as u32;
            e.speedup_q8 = ewma4(e.speedup_q8.max(1), ratio);
        }
    }

    /// v0.19: allocation-free sweep helper — copies up to `out.len()`
    /// cached entity ids starting at index `skip` (callers loop chunks;
    /// see backend `sweep_dead`).
    pub fn entity_ids_into(&self, skip: usize, out: &mut [u128]) -> usize {
        let mut n = 0;
        for (i, id) in self.entities.keys().enumerate() {
            if i < skip {
                continue;
            }
            if n == out.len() {
                break;
            }
            out[n] = *id;
            n += 1;
        }
        n
    }

    /// Record the end of a dispatch segment (park: block, rotate or
    /// throttle — the thread leaves the CPU). Updates the per-task
    /// utilisation EWMA (duty cycle over the inter-park window; the
    /// first park keeps the conservative "assume CPU-bound" value) and
    /// the cache-hotness stamp `last_ran`.
    pub fn note_park(&mut self, id: u128, now: u64, exec_cycles: u64) {
        let Some(e) = self.entities.get_mut(&id) else { return };
        if e.last_ran != 0 && now > e.last_ran {
            let window = now - e.last_ran;
            let on = exec_cycles.min(window);
            let sample = (((on as u128) * 256) / (window as u128)).min(255) as u32;
            e.util_q8 = ewma2(e.util_q8, sample); // α=1/2
        }
        e.last_ran = now;
    }

    /// Signed service imbalance of a queued thread vs. this queue's
    /// virtual clock: `lag = V − ve` (positive = owed service — the task
    /// ran less than its fair share). Clamped to ±`LAG_CAP_SLICES`
    /// virtual slices so a waking thief cannot be flooded by a huge
    /// sleeper/misfit credit. `None` if the thread is unknown here.
    pub fn lag_of(&self, id: u128) -> Option<i64> {
        let e = self.entities.get(&id)?;
        let vs = vslice(self.base_slice, e.weight).max(1) as i64;
        let lag = self.avg_vruntime() as i64 - e.vruntime as i64;
        Some(lag.clamp(-2 * vs, 2 * vs))
    }

    /// Remove a thread from this queue ENTIRELY (ordered queue, running
    /// set, cache, weight sums) and hand the cached entity to the caller
    /// — the migration detach half. The attach half is
    /// [`RunQueue::attach_entity`] on the destination queue. The caller
    /// must hold this queue's lock and has typically just validated the
    /// thread via [`RunQueue::is_queued`] under the same section.
    pub fn take_entity(&mut self, id: u128) -> Option<Entity> {
        if self.is_queued(id) {
            self.queue_remove(id);
            self.ready.fetch_sub(1, Ordering::Relaxed);
        }
        if let Some(e) = self.entities.get_mut(&id) {
            e.on_rq = false;
        }
        self.running_remove(id);
        self.entities.remove(&id)
    }

    /// Attach a migrant entity (taken from another queue with
    /// [`RunQueue::take_entity`]) into THIS queue — the migration attach
    /// half. Virtual time is re-based on the DESTINATION queue's clock:
    ///
    ///   `ve_dst = V_dst − clamp(lag, ±LAG_CAP_SLICES·vslice)`
    ///
    /// A positive lag (the usual case for an overdue task) makes the
    /// migrant immediately eligible with an early deadline — that is the
    /// point of stealing it — while the clamp bounds how hard it can
    /// squeeze the locals (no "jump the whole queue" floods; a thief
    /// cannot be abused as a priority booster). The migration counter
    /// and the caller-computed cooldown window implement the anti-thrash
    /// minimum stay (freshly stolen tasks are not re-offered).
    pub fn attach_entity(&mut self, mut e: Entity, lag: i64, cooldown_until: u64) {
        // Defensive: an entry with this id here would duplicate the
        // migrant — replace it wholesale (the steal protocol makes this
        // impossible in practice; unregister keeps the sums consistent).
        if self.entities.contains_key(&e.id) {
            self.unregister(e.id);
        }
        let avg = self.avg_vruntime();
        let vs = vslice(self.base_slice, e.weight).max(1) as i64;
        let lag = lag.clamp(-2 * vs, 2 * vs);
        let ve = (avg as i128 - lag as i128).clamp(0, u64::MAX as i128) as u64;
        e.vruntime = ve;
        e.deadline = ve + vs.max(1) as u64;
        e.slice = self.base_slice;
        e.slice_left = self.base_slice;
        e.on_rq = true;
        e.throttled = false;
        e.mig_count = e.mig_count.saturating_add(1);
        e.cooldown_until = cooldown_until;
        let k = key_of(&e);
        let id = e.id;
        self.queue.insert(k, id);
        self.weight_sum = self.weight_sum.wrapping_add(e.weight as u64);
        self.wv_sum = self
            .wv_sum
            .wrapping_add(e.weight as u128 * e.vruntime as u128);
        self.ready.fetch_add(1, Ordering::Relaxed);
        if ve > self.min_vruntime {
            self.min_vruntime = ve;
        }
        self.entities.insert(id, e);
    }

    // ───────────────────────── Internals ─────────────────────────

    /// Remove a queued entity from the ordered map and the sums.
    /// (Does NOT touch `on_rq` — callers fix it.)
    fn queue_remove(&mut self, id: u128) {
        let Some(e) = self.entities.get(&id) else { return };
        if !e.on_rq {
            return;
        }
        let k = key_of(e);
        if self.queue.remove(&k).is_some() {
            self.weight_sum = self.weight_sum.wrapping_sub(e.weight as u64);
            self.wv_sum = self
                .wv_sum
                .wrapping_sub(e.weight as u128 * e.vruntime as u128);
            if let Some(e) = self.entities.get_mut(&id) {
                e.on_rq = false;
            }
        }
    }
}

// ───────────────────────── Tests (host) ─────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SLICE: u64 = 1000;

    #[test]
    fn weight_mapping_is_monotonic() {
        let mut prev = 0;
        for prio in [0u8, 1, 50, 100, 128, 200, 254, 255] {
            let w = weight_for_priority(prio);
            assert!(w >= prev, "weight must not decrease with priority");
            prev = w;
        }
        assert_eq!(weight_for_priority(255), 88761);
        assert_eq!(weight_for_priority(0), 15);
    }

    #[test]
    fn weight_mapping_edges_never_underflow() {
        // Every priority byte maps inside the table (regression: the
        // first version wrapped at 19 - x and indexed out of bounds).
        for prio in 0..=255u8 {
            let w = weight_for_priority(prio);
            assert!((15..=88761).contains(&w), "prio {prio} -> {w}");
        }
    }

    #[test]
    fn single_entity_round_trip() {
        let mut rq = RunQueue::new(SLICE);
        rq.enqueue(1);
        assert_eq!(rq.ready_len(), 1);
        assert_eq!(rq.pick(0), Some(1));
        assert_eq!(rq.ready_len(), 0);
        assert_eq!(rq.pick(0), None); // nothing queued
        // Rotate (preempted while still running): back to the queue.
        rq.enqueue(1);
        assert_eq!(rq.ready_len(), 1);
        assert_eq!(rq.pick(0), Some(1));
    }

    #[test]
    fn equal_weights_share_cpu_fairly() {
        let mut rq = RunQueue::new(SLICE);
        for id in 1..=3u128 {
            rq.enqueue(id);
        }
        // Full round: each runs SLICE, all vruntimes stay together.
        for round in 0..6 {
            let id = rq.pick(0).expect("someone is eligible");
            rq.charge(id, SLICE);
            rq.enqueue(id); // rotate (slice exhausted -> fresh deadline)
            let _ = round;
        }
        let v1 = rq.entities.get(&1).unwrap().vruntime;
        let v2 = rq.entities.get(&2).unwrap().vruntime;
        let v3 = rq.entities.get(&3).unwrap().vruntime;
        // Same weight, same service: vruntimes within one slice of scaled.
        let scaled_slice = scaled(SLICE, DEFAULT_WEIGHT);
        assert!((v1 as i64 - v2 as i64).abs() as u64 <= scaled_slice);
        assert!((v1 as i64 - v3 as i64).abs() as u64 <= scaled_slice);
    }

    #[test]
    fn heavier_weight_gets_more_cpu() {
        let mut rq = RunQueue::new(SLICE);
        rq.register(10, NICE0_WEIGHT); // normal
        rq.register(20, 8 * NICE0_WEIGHT); // 8x heavier
        rq.enqueue(10);
        rq.enqueue(20);
        let mut runs = [0u64; 2]; // index 0 -> id 10, 1 -> id 20
        for _ in 0..20 {
            let id = rq.pick(0).unwrap();
            rq.charge(id, SLICE);
            runs[(id / 10 - 1) as usize] += SLICE;
            rq.enqueue(id);
        }
        // The 8x-weight entity must have received strictly more CPU.
        assert!(
            runs[1] > runs[0],
            "heavy={} light={}",
            runs[1],
            runs[0]
        );
        // And the light one must not be starved.
        assert!(runs[0] >= SLICE);
    }

    #[test]
    fn sleeper_wake_is_eligible_and_clamped() {
        let mut rq = RunQueue::new(SLICE);
        rq.register(1, NICE0_WEIGHT);
        rq.register(2, NICE0_WEIGHT);
        rq.enqueue(1);
        rq.enqueue(2);
        // 1 runs a lot while 2 sleeps.
        let id = rq.pick(0).unwrap();
        assert_eq!(id, 1); // earliest deadline first among eligible
        rq.charge(id, SLICE * 100);
        rq.dequeue(2); // 2 blocks (was queued — eager removal)
        rq.enqueue(2); // wakes much later
        let e2 = rq.entities.get(&2).unwrap();
        // vruntime clamped to avg - 2*vslice at the latest.
        let avg = rq.avg_vruntime();
        let cap = LAG_CAP_SLICES * vslice(SLICE, NICE0_WEIGHT);
        assert!(e2.vruntime + cap >= avg, "sleeper credit must be clamped");
        // And it is immediately eligible (owed service).
        assert_eq!(rq.pick(0), Some(2));
    }

    #[test]
    fn preempt_hint_fires_only_for_laggards() {
        let mut rq = RunQueue::new(SLICE);
        rq.register(1, NICE0_WEIGHT);
        rq.enqueue(1);
        assert_eq!(rq.pick(0), Some(1)); // running on cpu 0
        // CPU 1 wakes an equal-weight thread: the runner's deadline is
        // not beaten — no preemption IPI.
        rq.register(2, NICE0_WEIGHT);
        rq.enqueue(2);
        let qmin = rq.min_queued_deadline().unwrap();
        let targets: alloc::vec::Vec<usize> = rq.preempt_cpus(qmin, 1).collect();
        assert!(targets.is_empty(), "equal wake must not force preemption");
        // CPU 1 wakes a heavy-weight thread: virtual slice shrinks, its
        // deadline beats the runner's — cpu 0 gets the resched IPI.
        rq.register(3, 32 * NICE0_WEIGHT);
        rq.enqueue(3);
        let qmin = rq.min_queued_deadline().unwrap();
        let targets: alloc::vec::Vec<usize> = rq.preempt_cpus(qmin, 1).collect();
        assert_eq!(targets, alloc::vec![0], "heavy wake must preempt cpu 0");
    }

    #[test]
    fn unregister_cleans_everything() {
        let mut rq = RunQueue::new(SLICE);
        rq.enqueue(7);
        assert!(rq.unregister(7));
        assert_eq!(rq.ready_len(), 0);
        assert_eq!(rq.entity_count(), 0);
        assert_eq!(rq.pick(0), None);
        // Running entity unregistration (thread killed while running).
        rq.enqueue(8);
        assert_eq!(rq.pick(1), Some(8));
        assert!(!rq.unregister(8));
        assert_eq!(rq.running_len(), 0);
    }

    #[test]
    fn dequeue_then_enqueue_takes_wake_path() {
        let mut rq = RunQueue::new(SLICE);
        rq.register(5, NICE0_WEIGHT);
        rq.enqueue(5);
        let id = rq.pick(0).unwrap();
        rq.charge(id, SLICE / 4);
        rq.dequeue(5); // blocks mid-slice
        rq.enqueue(5); // wakes: fresh slice + deadline
        let e = rq.entities.get(&5).unwrap();
        assert_eq!(e.slice_left, SLICE, "wake grants a fresh slice");
        assert!(e.deadline > e.vruntime);
    }

    #[test]
    fn set_weight_repositions_queued_entity() {
        let mut rq = RunQueue::new(SLICE);
        rq.register(1, NICE0_WEIGHT);
        rq.enqueue(1);
        let before = rq.min_queued_deadline().unwrap();
        rq.set_weight(1, 16 * NICE0_WEIGHT);
        let after = rq.min_queued_deadline().unwrap();
        // Heavier weight: shorter virtual slice: earlier deadline.
        assert!(after < before, "heavier weight must pull the deadline in");
        assert_eq!(rq.pick(0), Some(1));
    }

    #[test]
    fn throttle_flag_lifecycle() {
        let mut rq = RunQueue::new(SLICE);
        rq.enqueue(9);
        assert_eq!(rq.pick(0), Some(9));
        rq.mark_throttled(9);
        assert!(rq.is_throttled(9));
        assert!(rq.running_snapshot().next().is_none());
        rq.enqueue(9); // unthrottle at the period boundary
        assert!(!rq.is_throttled(9));
        assert_eq!(rq.pick(0), Some(9));
    }

    #[test]
    fn fairness_across_mixed_weights_long_run() {
        // Proportionality: 2:1 weights converge to ~2:1 CPU shares.
        let mut rq = RunQueue::new(SLICE);
        rq.register(1, 2 * NICE0_WEIGHT);
        rq.register(2, NICE0_WEIGHT);
        rq.enqueue(1);
        rq.enqueue(2);
        let mut exec = [0u64; 2];
        for _ in 0..200 {
            let id = rq.pick(0).unwrap();
            rq.charge(id, SLICE);
            exec[(id - 1) as usize] += SLICE;
            rq.enqueue(id);
        }
        let ratio = exec[0] as f64 / exec[1] as f64;
        assert!(
            (1.6..=2.4).contains(&ratio),
            "weight ratio must converge to 2:1, got {ratio} ({} vs {})",
            exec[0],
            exec[1]
        );
    }

    // ───────── v0.18: steal/migration support ─────────

    #[test]
    fn pressure_and_tardiness_track_late_dispatches() {
        // Overload two same-weight entities on one CPU with tiny slices:
        // every dispatch is late (V ran past the queued deadline), so the
        // pressure EWMA must climb; the repeatedly-delayed entity keeps a
        // positive tardiness EWMA.
        let mut rq = RunQueue::new(SLICE);
        for id in 1..=4u128 {
            rq.enqueue(id);
        }
        for _ in 0..40 {
            let id = rq.pick(0).unwrap();
            // Overshoot: each dispatched entity burns 4 slices, so the
            // queue's virtual clock runs far past everyone's queued
            // deadline — every subsequent dispatch is late.
            rq.charge(id, 4 * SLICE);
            rq.enqueue(id);
        }
        assert!(
            rq.pressure_q8() >= 128,
            "sustained late dispatches must raise pressure, got {}",
            rq.pressure_q8()
        );
        let slippers = (1..=4u128)
            .filter(|&id| rq.entity_of(id).map(|e| e.tard_q8 > 0).unwrap_or(false))
            .count();
        assert!(slippers >= 2, "queued entities must record slip");
        // Idle drain: pressure decays monotonically to zero.
        let mut prev = rq.pressure_q8();
        for _ in 0..40 {
            rq.relax_pressure();
            let now = rq.pressure_q8();
            assert!(now <= prev);
            prev = now;
        }
        assert_eq!(rq.pressure_q8(), 0);
    }

    #[test]
    fn note_park_duty_cycle_ewma() {
        let mut rq = RunQueue::new(SLICE);
        rq.enqueue(7);
        // First park: keeps the conservative 255, stamps last_ran.
        rq.note_park(7, 1000, 10);
        assert_eq!(rq.entity_of(7).unwrap().util_q8, 255);
        assert_eq!(rq.entity_of(7).unwrap().last_ran, 1000);
        // 25% duty cycle over the next window: util EWMA halves toward 64.
        rq.note_park(7, 2000, 250); // on/window = 250/1000
        let u = rq.entity_of(7).unwrap().util_q8;
        assert_eq!(u, 255 - (255 - 64) / 2, "α=1/2 step toward the sample");
        // A CPU-bound pattern converges back up.
        for _ in 0..20 {
            rq.note_park(7, 0, 0); // no-op windows keep the stamp fresh
        }
        let mut t = 2000;
        for _ in 0..30 {
            t += 1000;
            rq.note_park(7, t, 1000); // 100% duty
        }
        assert!(rq.entity_of(7).unwrap().util_q8 > 200);
    }

    #[test]
    fn migration_lag_is_clamped_and_rebased() {
        // src: two entities; one lags far behind (huge positive lag).
        let mut src = RunQueue::new(SLICE);
        let mut dst = RunQueue::new(SLICE);
        src.register(1, NICE0_WEIGHT);
        src.register(2, NICE0_WEIGHT);
        src.enqueue(1);
        src.enqueue(2);
        // Run only entity 1 for a long time: entity 2 accumulates lag.
        for _ in 0..30 {
            let id = src.pick(0).unwrap();
            src.charge(id, if id == 1 { SLICE } else { 0 });
            src.enqueue(id);
        }
        let lag = src.lag_of(2).expect("entity 2 is queued");
        let vs = vslice(SLICE, NICE0_WEIGHT) as i64;
        assert!(
            lag <= 2 * vs && lag >= -2 * vs,
            "lag must be clamped to ±2 vslices, got {lag} (vs={vs})"
        );
        // Detach + attach with the clamped lag: the migrant must land at
        // vruntime = V_dst − lag, be queued with a fresh slice, and its
        // migration counter/cooldown must advance.
        let e = src.take_entity(2).unwrap();
        assert!(!src.has_entity(2));
        assert_eq!(src.ready_len(), 1);
        let v_dst_before = dst.avg_vruntime();
        dst.attach_entity(e, lag, 42);
        let m = dst.entity_of(2).unwrap();
        assert_eq!(m.on_rq, true);
        assert_eq!(m.mig_count, 1);
        assert_eq!(m.cooldown_until, 42);
        assert_eq!(m.slice_left, SLICE, "migrant gets a fresh slice");
        let expect = (v_dst_before as i64 - lag).max(0) as u64;
        assert!(
            m.vruntime.abs_diff(expect) <= 1,
            "ve must be rebased on the destination clock"
        );
        assert_eq!(dst.ready_len(), 1);
        // The migrant is immediately pickable (eligible by construction:
        // ve <= avg of the queue that now contains it).
        assert_eq!(dst.pick(1), Some(2));
    }

    #[test]
    fn migration_preserves_policy_state() {
        let mut src = RunQueue::new(SLICE);
        let mut dst = RunQueue::new(SLICE);
        src.register(3, 8 * NICE0_WEIGHT);
        src.enqueue(3);
        // Give the entity some balancer history.
        src.note_park(3, 500, 128);
        let e = src.take_entity(3).unwrap();
        dst.attach_entity(e, 0, 0);
        let m = dst.entity_of(3).unwrap();
        assert_eq!(m.weight, 8 * NICE0_WEIGHT, "weight survives migration");
        assert_eq!(m.last_ran, 500, "cache stamp survives migration");
        assert_eq!(m.util_q8, 255, "util history survives migration");
    }

    #[test]
    fn queued_snapshot_lists_only_queued() {
        let mut rq = RunQueue::new(SLICE);
        rq.register(1, NICE0_WEIGHT);
        rq.register(2, NICE0_WEIGHT);
        rq.register(3, NICE0_WEIGHT);
        rq.enqueue(1);
        rq.enqueue(2);
        assert_eq!(rq.pick(0), Some(1)); // 1 is running now
        let snap = rq.queued_snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].id, 2);
        assert_eq!(rq.deadline_of(2), Some(snap[0].deadline));
        assert_eq!(rq.deadline_of(1), None, "running entity has no queued dl");
    }

    #[test]
    fn negative_lag_migrant_does_not_jump_ahead() {
        // A migrant that ran MORE than its share (negative lag) must not
        // end up before the destination locals: ve = V_dst − lag > V_dst.
        let mut dst = RunQueue::new(SLICE);
        dst.register(1, NICE0_WEIGHT);
        dst.enqueue(1);
        let mut src = RunQueue::new(SLICE);
        src.register(9, NICE0_WEIGHT);
        src.enqueue(9);
        let e = src.take_entity(9).unwrap();
        let v_dst = dst.avg_vruntime();
        dst.attach_entity(e, -(vslice(SLICE, NICE0_WEIGHT) as i64), 0);
        let m = dst.entity_of(9).unwrap();
        assert!(m.vruntime >= v_dst, "negative-lag migrant starts at/behind V");
        // The local (eligible, at V) must win the next pick.
        assert_eq!(dst.pick(0), Some(1));
    }

    // ───────── v0.19: fixed running set + perf/snapshot additions ─────────

    #[test]
    fn running_set_marks_and_clears_by_id() {
        let mut rq = RunQueue::new(SLICE);
        rq.register(1, NICE0_WEIGHT);
        rq.register(2, NICE0_WEIGHT);
        rq.enqueue(1);
        rq.enqueue(2);
        assert_eq!(rq.pick(3), Some(1)); // dispatched on cpu 3
        assert!(rq.is_running_here(1));
        assert!(!rq.is_running_here(2));
        assert_eq!(rq.running_len(), 1);
        let snap: alloc::vec::Vec<(u128, RunningEnt)> = rq.running_snapshot().collect();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].0, 1);
        assert_eq!(snap[0].1.cpu, 3);
        rq.running_remove(1);
        assert!(!rq.is_running_here(1));
        assert_eq!(rq.running_len(), 0);
        // Re-dispatch reuses the slot array without heap traffic.
        assert_eq!(rq.pick(4), Some(2));
        assert!(rq.is_running_here(2));
        assert_eq!(rq.running_len(), 1);
    }

    #[test]
    fn running_survives_queue_removal_paths() {
        // take_entity / dequeue / mark_throttled all clear the running
        // mark without leaving stale slots behind.
        let mut rq = RunQueue::new(SLICE);
        rq.enqueue(5);
        assert_eq!(rq.pick(0), Some(5));
        let e = rq.take_entity(5).unwrap();
        assert!(!e.on_rq);
        assert_eq!(rq.running_len(), 0);
        rq.enqueue(6);
        assert_eq!(rq.pick(0), Some(6));
        rq.dequeue(6);
        assert_eq!(rq.running_len(), 0);
        rq.enqueue(7);
        assert_eq!(rq.pick(0), Some(7));
        rq.mark_throttled(7);
        assert_eq!(rq.running_len(), 0);
    }

    #[test]
    fn note_perf_builds_cross_class_ratio() {
        let mut rq = RunQueue::new(SLICE);
        rq.register(1, NICE0_WEIGHT);
        rq.enqueue(1);
        let e0 = rq.entity_of(1).unwrap();
        assert_eq!(e0.speedup_q8, 256);
        assert_eq!(e0.ipc_fast_q8, 0);
        // Only fast-class samples: the ratio stays neutral.
        for _ in 0..10 {
            rq.note_perf(1, 256, 400);
        }
        let e1 = rq.entity_of(1).unwrap();
        assert_eq!(e1.ipc_fast_q8, 400);
        assert_eq!(e1.ipc_slow_q8, 0);
        assert_eq!(e1.speedup_q8, 256, "one-sided history keeps the neutral hint");
        // Slow-class samples arrive: ratio 400/200 = 2x -> Q8 512 (clamped).
        for _ in 0..40 {
            rq.note_perf(1, 128, 200);
        }
        let e2 = rq.entity_of(1).unwrap();
        assert_eq!(e2.ipc_slow_q8, 200);
        assert!(
            e2.speedup_q8 > 256 && e2.speedup_q8 <= 512,
            "speedup must converge toward 2x, got {}",
            e2.speedup_q8
        );
        // Zero sample and unknown task: no-ops.
        rq.note_perf(1, 256, 0);
        rq.note_perf(999, 256, 300);
        assert!(rq.entity_of(999).is_none());
    }

    #[test]
    fn collect_queued_matches_vec_snapshot() {
        let mut rq = RunQueue::new(SLICE);
        for id in 1..=5u128 {
            rq.enqueue(id);
        }
        assert_eq!(rq.pick(0), Some(1)); // one running
        let vec_snap = rq.queued_snapshot();
        let mut buf = [QueuedCand::ZERO; 64];
        let n = rq.collect_queued(&mut buf);
        assert_eq!(n, vec_snap.len());
        for i in 0..n {
            assert_eq!(buf[i].id, vec_snap[i].id);
            assert_eq!(buf[i].tard_q8, vec_snap[i].tard_q8);
            assert_eq!(buf[i].speedup_q8, vec_snap[i].speedup_q8);
        }
        // Truncation: a 2-slot buffer keeps the first queued entities.
        let mut tiny = [QueuedCand::ZERO; 2];
        let m = rq.collect_queued(&mut tiny);
        assert_eq!(m, 2);
        assert_eq!(tiny[0].id, vec_snap[0].id);
        assert_eq!(tiny[1].id, vec_snap[1].id);
    }

    #[test]
    fn entity_ids_into_paginates() {
        let mut rq = RunQueue::new(SLICE);
        for id in 1..=6u128 {
            rq.register(id, NICE0_WEIGHT);
        }
        let total = rq.entity_count();
        let mut seen: alloc::vec::Vec<u128> = alloc::vec::Vec::new();
        let mut skip = 0;
        let mut buf = [0u128; 4];
        loop {
            let n = rq.entity_ids_into(skip, &mut buf);
            if n == 0 {
                break;
            }
            for i in 0..n {
                seen.push(buf[i]);
            }
            skip += n;
            if seen.len() >= total {
                break;
            }
        }
        assert_eq!(seen.len(), total);
        let mut a = seen.clone();
        let mut b: alloc::vec::Vec<u128> = rq.entity_ids().collect();
        a.sort_unstable();
        b.sort_unstable();
        assert_eq!(a, b);
    }
}
