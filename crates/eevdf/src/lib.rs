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

// ───────────────────────── Run queue ─────────────────────────

/// How much sleeper credit a waking entity may keep, in virtual slices
/// (avg - LAG_CAP*vslice is the furthest behind the average a waker may
/// start; bounds post-wake starvation of the other entities).
pub const LAG_CAP_SLICES: u64 = 2;

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
    /// Dispatched entities: id -> (deadline, cpu).
    running: BTreeMap<u128, RunningEnt>,
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
}

impl RunQueue {
    /// Empty queue with the given base slice (raw time units per slice).
    pub const fn new(base_slice: u64) -> Self {
        Self {
            queue: BTreeMap::new(),
            entities: BTreeMap::new(),
            running: BTreeMap::new(),
            weight_sum: 0,
            wv_sum: 0,
            min_vruntime: 0,
            base_slice,
            ready: AtomicUsize::new(0),
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
        self.running.iter().map(|(id, r)| (*id, *r))
    }

    /// Is the entity queued? (backend diagnostics)
    pub fn is_queued(&self, id: u128) -> bool {
        self.entities.get(&id).is_some_and(|e| e.on_rq)
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
        self.running.remove(&id);
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
        self.running.remove(&id);
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
        if let Some(running) = self.running.remove(&id) {
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
                let _ = running; // deadline already kept in the entity
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
        self.running.remove(&id);
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
        e.on_rq = false;
        self.weight_sum = self.weight_sum.wrapping_sub(e.weight as u64);
        self.wv_sum = self
            .wv_sum
            .wrapping_sub(e.weight as u128 * e.vruntime as u128);
        self.ready.fetch_sub(1, Ordering::Relaxed);
        if e.vruntime > self.min_vruntime {
            self.min_vruntime = e.vruntime;
        }
        self.running.insert(
            id,
            RunningEnt {
                deadline: e.deadline,
                cpu,
            },
        );
        Some(id)
    }

    /// CPUs whose running entity has a deadline strictly later than
    /// `min_deadline` (the best queued deadline) — the only CPUs that
    /// would actually switch threads if they re-ran the picker now.
    /// Excludes `skip_cpu` (its own enqueue path re-evaluates anyway).
    pub fn preempt_cpus(&self, min_deadline: u64, skip_cpu: usize) -> impl Iterator<Item = usize> + '_ {
        self.running
            .values()
            .filter(move |r| r.cpu != skip_cpu && r.deadline > min_deadline)
            .map(|r| r.cpu)
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
        assert!(rq.running.is_empty());
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
}
