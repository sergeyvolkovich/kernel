// ==== sched_lb: pull-model load balancing policy (offer showcase) ====
//
// A self-contained policy library for the v0.18 scheduler load balancer.
// Same discipline as the `eevdf` crate: pure data structures + policy
// math, NO platform dependencies, NO locks of its own — the backend
// (x86_64 `backend::lb`) owns the arrays, serializes owner-side state
// and supplies the time source (TSC). Host unit tests run under std.
//
// ───────────────────────── Architecture (the idea) ─────────────────────────
//
// An OVERLOADED core (deadline slips piling up, see `eevdf` pressure)
// publishes a short list of victim candidates — the SHOWCASE. An
// underloaded core (the thief) scans showcases across the domain
// hierarchy (SMT -> cluster -> LLC -> NUMA), scores the candidates and
// takes ONE task via a two-phase claim:
//
//   phase 1 — CAS the slot word  OFFERED(cycle) -> CLAIMED(cycle, thief):
//             exactly one thief wins; the 32-bit generation defends
//             against ABA on slot reuse;
//   phase 2 — validate + transfer: fast path takes the source run-queue
//             with a try-lock and detaches/attaches the entity; the
//             fallback parks a request in the source's MPSC inbox and
//             the source hands the task over at its next schedule().
//
// Slot lifecycle:  FREE -> OFFERED(cycle) -> CLAIMED(cycle,thief) -> FREE
//                  (cycle+1 on every return to FREE — a generation is
//                  never reused until wraparound).
//
// Memory-ordering contract (the only cross-CPU part of the crate):
//   * the slot PAYLOAD is plain data written exclusively by the owner
//     (publisher) core BEFORE the word.store(OFFERED, Release);
//   * a thief may read the payload ONLY after its own successful
//     CAS to CLAIMED (Acquire) — which pairs with the publisher's
//     Release and also blocks any further publisher writes (publish
//     targets FREE slots only, invalidate targets OFFERED only);
//   * the claimer returns the slot with a Release store (FREE, cycle+1);
//     the publisher's next payload write for that slot happens after it
//     observes FREE, i.e. strictly after the claimer finished reading.
//     No torn payload reads are possible under this protocol.
//
// The owner-side state (hysteresis, backoff, stamps) lives in
// `OwnerLb` — plain data, no atomics: only the owning core touches it
// (backend per-CPU discipline, like the context slots in sched.rs).

#![cfg_attr(not(test), no_std)]

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering};

use eevdf::Entity;

// ───────────────────────── Tunables (Q8 fixed point) ─────────────────────────

/// Showcase slots per core (K = 4..8 per the design; 4 keeps the scan
/// cheap for a 32-CPU ceiling and covers the top tardiness offenders).
pub const K_SLOTS: usize = 4;

/// Publish pressure threshold (Q8 share of late dispatches): a core
/// starts advertising victims after its EWMA rises above this.
pub const PRESSURE_HI_Q8: u32 = 48; // ≈ 19% late dispatches

/// Withdraw threshold (hysteresis lower edge).
pub const PRESSURE_LO_Q8: u32 = 16; // ≈ 6%

/// Hard-starvation threshold: publishing above this also kicks an idle
/// core in the domain (IPI) so a pull can actually happen.
pub const PRESSURE_HARD_Q8: u32 = 128; // 50%

/// A running (non-idle) core may only go stealing when its own
/// pressure is below this epsilon — thieves must not create victims.
pub const STEAL_PRESSURE_EPS_Q8: u32 = 24; // ≈ 9%

/// Consecutive publish-window samples required to cross a hysteresis
/// edge (both raise and drop) — filters pressure flutter.
pub const HYSTERESIS_TICKS: u32 = 2;

/// Minimum interval between showcase publications, in slices
/// (publish on the tick, never in the dispatch hot path).
pub const PUBLISH_EVERY_SLICES: u64 = 4;

/// Minimum interval between PERIODIC steal attempts of a running core
/// (idle-entry steals are not rate-limited by this — see backend).
pub const STEAL_EVERY_SLICES: u64 = 4;

/// A task parked less than this many slices ago is cache-hot: not
/// offered. With a 10 ms slice this is a 20 ms window — a rotating
/// queue's tail is far older, so depth (and thus pressure) is what
/// makes victims available, exactly as intended.
pub const CACHE_HOT_SLICES: u64 = 2;

/// Admission margin (Q8 of capacity, 288 = 112.5%): the thief accepts
/// work while its projected utilisation stays under cap·margin.
pub const ADMIT_MARGIN_Q8: u32 = 288;

/// Asymmetric admission delta (Q8): up-migration (to a stronger core)
/// gets `margin + delta`, down-migration gets `margin − delta`.
/// Symmetric capacities (current x86_64 target) are unaffected.
pub const ADMIT_ASYM_Q8: u32 = 16;

/// Steal-request timeout, in slices: a fallback (variant B) request
/// older than this is dropped by the source — the thief lost interest.
pub const STEAL_REQ_TIMEOUT_SLICES: u64 = 4;

/// Sources scanned per steal attempt (thief's candidate bound).
pub const MAX_SOURCES_PER_STEAL: usize = 8;

// ───────────────────────── Slot word encoding ─────────────────────────

/// Slot state (2 bits of the word).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SlotState {
    Free = 0,
    Offered = 1,
    Claimed = 2,
}

impl SlotState {
    #[inline]
    fn from_word(w: u64) -> Self {
        match w & 0b11 {
            0 => SlotState::Free,
            1 => SlotState::Offered,
            _ => SlotState::Claimed,
        }
    }
}

#[inline]
const fn encode_word(cycle: u32, state: SlotState, thief: u8) -> u64 {
    ((cycle as u64) << 10) | ((thief as u64 & 0xFF) << 2) | (state as u64)
}

#[inline]
fn word_cycle(w: u64) -> u32 {
    (w >> 10) as u32
}

// ───────────────────────── Offer payload ─────────────────────────

/// One published victim: plain data snapshot of a queued EEVDF entity.
/// Written by the owner core only (see the ordering contract above);
/// read by thieves after a successful claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Offer {
    /// Victim thread id (L4 global ThreadId).
    pub task: u128,
    /// EEVDF weight (priority class).
    pub weight: u32,
    /// Full slice length, raw time units (TSC cycles).
    pub slice: u64,
    /// Deadline-slip EWMA, Q8 — the urgency input of the steal score.
    pub tard_q8: u32,
    /// CPU-demand EWMA, Q8 — the admission input.
    pub util_q8: u32,
    /// Big/little rate-ratio hint, Q8 (256 = 1.0) — the fit input.
    pub speedup_q8: u32,
    /// TSC of the last park (cache-hotness).
    pub last_ran: u64,
}

impl Offer {
    pub const ZERO: Offer = Offer {
        task: 0,
        weight: 0,
        slice: 0,
        tard_q8: 0,
        util_q8: 0,
        speedup_q8: 256,
        last_ran: 0,
    };
}

/// A successful phase-1 claim: the slot generation (for the release
/// CAS) plus the payload read under the claim.
#[derive(Debug, Clone, Copy)]
pub struct Claim {
    pub cycle: u32,
    pub offer: Offer,
}

// ───────────────────────── Offer slot (single showcase cell) ─────────────────────────

/// One showcase cell: an atomic word (cycle|thief|state) plus plain
/// payload guarded by the publish/claim ordering contract.
///
/// SAFETY discipline (single-writer payload):
///   * `publish`/`invalidate`/`invalidate_all` — owner core ONLY;
///   * `claim`/`release` — any core, but payload reads only between a
///     successful claim and the matching release;
///   * `state()` — any core (advisory).
pub struct OfferSlot {
    word: AtomicU64,
    payload: UnsafeCell<Offer>,
}

// SAFETY: the payload is protected by the word protocol (see module
// docs): publishers write it only while the slot is FREE and before a
// Release store of OFFERED; readers hold a CLAIMED lease acquired via
// an acquiring CAS that pairs with that store.
unsafe impl Sync for OfferSlot {}

impl OfferSlot {
    pub const fn new() -> Self {
        Self {
            word: AtomicU64::new(encode_word(0, SlotState::Free, 0)),
            payload: UnsafeCell::new(Offer::ZERO),
        }
    }

    /// Advisory state peek (thief pre-filter — avoids CASing cold slots).
    #[inline]
    pub fn state(&self) -> SlotState {
        SlotState::from_word(self.word.load(Ordering::Acquire))
    }

    /// Owner-side publication: fills a FREE slot (payload first, then
    /// the OFFERED word with the SAME generation the slot carried in
    /// FREE). Returns false if the slot is not free (claimed in-flight
    /// or still offered).
    pub fn publish(&self, offer: &Offer) -> bool {
        let w = self.word.load(Ordering::Relaxed);
        if SlotState::from_word(w) != SlotState::Free {
            return false;
        }
        // SAFETY: owner-side write; the slot is FREE (read above) and no
        // thief can touch the payload until OFFERED is published.
        unsafe {
            *self.payload.get() = *offer;
        }
        self.word
            .store(encode_word(word_cycle(w), SlotState::Offered, 0), Ordering::Release);
        true
    }

    /// Owner-side withdrawal of a still-offered slot (refresh pass).
    /// CLAIMED slots are mid-transfer and left alone. Returns true if
    /// this call retired an offer.
    pub fn invalidate(&self) -> bool {
        let w = self.word.load(Ordering::Relaxed);
        if SlotState::from_word(w) != SlotState::Offered {
            return false;
        }
        self.word
            .compare_exchange(
                w,
                encode_word(word_cycle(w).wrapping_add(1), SlotState::Free, 0),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Phase 1 — thief claims an OFFERED slot. On success the payload
    /// is read (safe: the acquiring CAS pairs with the publisher's
    /// Release, and no writer exists until the matching release).
    /// Returns the generation (for release) and the payload.
    pub fn claim(&self, thief: u8) -> Option<Claim> {
        loop {
            let w = self.word.load(Ordering::Acquire);
            if SlotState::from_word(w) != SlotState::Offered {
                return None;
            }
            let claimed = encode_word(word_cycle(w), SlotState::Claimed, thief);
            match self.word.compare_exchange_weak(
                w,
                claimed,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    // SAFETY: we own the CLAIMED lease on this
                    // generation; see the ordering contract.
                    let offer = unsafe { *self.payload.get() };
                    return Some(Claim {
                        cycle: word_cycle(w),
                        offer,
                    });
                }
                Err(new_w) => {
                    // Either another thief won, or the word changed;
                    // retry only while it still looks OFFERED.
                    if SlotState::from_word(new_w) != SlotState::Offered {
                        return None;
                    }
                    core::hint::spin_loop();
                }
            }
        }
    }

    /// Phase-1 loser/finisher: the claimer returns the slot to FREE
    /// with generation+1 (invalidating this offer cycle). Plain store —
    /// only the claimer writes a CLAIMED slot.
    pub fn release(&self, cycle: u32) {
        self.word.store(
            encode_word(cycle.wrapping_add(1), SlotState::Free, 0),
            Ordering::Release,
        );
    }
}

impl Default for OfferSlot {
    fn default() -> Self {
        Self::new()
    }
}

// ───────────────────────── Offer shelf (per-core showcase) ─────────────────────────

/// The per-core showcase: `K_SLOTS` cells. Owner publishes/invalidates;
/// thieves claim. All methods are lock-free.
pub struct OfferShelf {
    slots: [OfferSlot; K_SLOTS],
}

impl OfferShelf {
    pub const fn new() -> Self {
        Self {
            slots: [const { OfferSlot::new() }; K_SLOTS],
        }
    }

    /// Owner-side refresh: retire every still-OFFERED slot (CLAIMED
    /// ones are mid-transfer and will be released by their thieves),
    /// then publish `offers` into free slots. Returns how many offers
    /// landed.
    pub fn republish(&self, offers: &[Offer]) -> usize {
        for s in &self.slots {
            let _ = s.invalidate();
        }
        let mut n = 0;
        'outer: for offer in offers {
            for s in &self.slots {
                if s.publish(offer) {
                    n += 1;
                    continue 'outer;
                }
            }
            break; // shelf full (everything claimed/in-flight)
        }
        n
    }

    /// Owner-side full withdrawal (pressure dropped below `lo`, or the
    /// core drained): retire all OFFERED slots.
    pub fn withdraw_all(&self) {
        for s in &self.slots {
            let _ = s.invalidate();
        }
    }

    /// Thief-side pre-filter: any live offer?
    pub fn any_offered(&self) -> bool {
        self.slots.iter().any(|s| s.state() == SlotState::Offered)
    }

    /// Thief-side pick: claim every OFFERED slot in turn, score the
    /// payloads, keep the best and release the rest. `score` receives
    /// each claimed payload; higher is better. Returns the slot index,
    /// its generation and the winning payload. The winner stays
    /// CLAIMED — the caller MUST `release` it (index + cycle) once the
    /// transfer completes or fails.
    pub fn claim_best(
        &self,
        thief: u8,
        score: impl Fn(&Offer) -> i32,
    ) -> Option<(usize, Claim, i32)> {
        let mut best: Option<(usize, Claim, i32)> = None;
        for (i, s) in self.slots.iter().enumerate() {
            if s.state() != SlotState::Offered {
                continue;
            }
            let Some(c) = s.claim(thief) else { continue };
            let sc = score(&c.offer);
            match best {
                Some((bi, bc, bs)) => {
                    if sc > bs {
                        self.slots[bi].release(bc.cycle);
                        best = Some((i, c, sc));
                    } else {
                        s.release(c.cycle);
                    }
                }
                None => best = Some((i, c, sc)),
            }
        }
        best
    }

    /// Release a slot won via [`OfferShelf::claim_best`].
    pub fn release(&self, idx: usize, cycle: u32) {
        self.slots[idx % K_SLOTS].release(cycle);
    }
}

impl Default for OfferShelf {
    fn default() -> Self {
        Self::new()
    }
}

// ───────────────────────── Pressure hysteresis ─────────────────────────

/// Outcome of one steal attempt (thief-side).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StealOutcome {
    /// A victim was detached from the source and attached to the
    /// thief's queue — exactly one task per attempt.
    Stolen,
    /// The source queue was busy; a timed request was parked in its
    /// inbox (variant B) — the source will push the migrant to the
    /// thief's handoff inbox at its next schedule boundary.
    Requested,
    /// Nothing taken: no prey, failed validation, admission rejection
    /// everywhere, or the thief is in/backing-off.
    None,
}

/// Hysteresis edge crossing (owner-side reaction).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edge {
    /// No transition.
    None,
    /// Pressure held above `hi` for k samples: start publishing.
    Raised,
    /// Pressure held below `lo` for k samples: withdraw the showcase.
    Dropped,
}

/// Two-threshold + k-consecutive-samples hysteresis over the pressure
/// EWMA. Owner-side only (no atomics). The k-sample filter prevents a
/// single busy burst from flipping the OVERLOADED bit (and the IPI
/// kicks that come with it) back and forth.
#[derive(Debug, Clone, Copy)]
pub struct Hysteresis {
    pub over: bool,
    over_ticks: u32,
    under_ticks: u32,
}

impl Hysteresis {
    pub const fn new() -> Self {
        Self {
            over: false,
            over_ticks: 0,
            under_ticks: 0,
        }
    }

    /// Feed one publish-window pressure sample.
    pub fn update(&mut self, pressure_q8: u32) -> Edge {
        if !self.over {
            if pressure_q8 >= PRESSURE_HI_Q8 {
                self.over_ticks = self.over_ticks.saturating_add(1);
                self.under_ticks = 0;
                if self.over_ticks >= HYSTERESIS_TICKS {
                    self.over = true;
                    self.over_ticks = 0;
                    return Edge::Raised;
                }
            } else {
                self.over_ticks = 0;
            }
            return Edge::None;
        }
        if pressure_q8 <= PRESSURE_LO_Q8 {
            self.under_ticks = self.under_ticks.saturating_add(1);
            self.over_ticks = 0;
            if self.under_ticks >= HYSTERESIS_TICKS {
                self.over = false;
                self.under_ticks = 0;
                return Edge::Dropped;
            }
        } else {
            self.under_ticks = 0;
        }
        Edge::None
    }
}

impl Default for Hysteresis {
    fn default() -> Self {
        Self::new()
    }
}

// ───────────────────────── Steal admission & scoring ─────────────────────────

/// The thief's / source's view of a core, Q8 fixed point.
#[derive(Debug, Clone, Copy)]
pub struct CoreView {
    /// Core capacity (256 = one full core; SMT siblings and little
    /// cores carry less on heterogeneous targets).
    pub cap_q8: u32,
    /// Smoothed core utilisation (demand sum / duty cycle), Q8.
    pub util_q8: u32,
    /// Deadline-pressure EWMA, Q8.
    pub pressure_q8: u32,
}

impl CoreView {
    /// Symmetric full core at the given utilisation/pressure.
    pub const fn plain(util_q8: u32, pressure_q8: u32) -> Self {
        Self {
            cap_q8: 256,
            util_q8,
            pressure_q8,
        }
    }
}

/// Hard admission filter for a steal:
///
///   `util_me + util_task · cap_src / cap_me  ≤  cap_me · margin / 256`
///
/// with the margin relaxed for up-migration (stronger target) and
/// tightened for down-migration. A task that does not fit the little
/// side (misfit) is simply rejected by the capacity term on
/// heterogeneous systems — the symmetric target always passes unless
/// the thief is genuinely saturated.
pub fn admission_ok(me: &CoreView, src: &CoreView, task_util_q8: u32) -> bool {
    let cap_me = me.cap_q8.max(1) as u64;
    let scaled = (task_util_q8 as u64 * src.cap_q8 as u64) / cap_me;
    let margin = if me.cap_q8 > src.cap_q8 {
        ADMIT_MARGIN_Q8.saturating_add(ADMIT_ASYM_Q8)
    } else if me.cap_q8 < src.cap_q8 {
        ADMIT_MARGIN_Q8.saturating_sub(ADMIT_ASYM_Q8)
    } else {
        ADMIT_MARGIN_Q8
    };
    let budget = (cap_me * margin as u64) >> 8;
    me.util_q8 as u64 + scaled <= budget
}

/// Soft score weights (Q8 multipliers over Q8 inputs). Higher score =
/// more attractive steal. The energy weight `c` is modulated down by
/// the source pressure (urgency buys an energy budget).
#[derive(Debug, Clone, Copy)]
pub struct Weights {
    pub urgency: i32,
    pub fit: i32,
    pub energy: i32,
    pub migcost: i32,
}

pub const DEFAULT_WEIGHTS: Weights = Weights {
    urgency: 256, // tardiness dominates: this IS the load-balancing goal
    fit: 64,      // heterogeneity placement (dormant on symmetric x86)
    energy: 128,  // EAS-style energy delta (0 within one freq domain)
    migcost: 96,  // cache/migration penalty by topology level
};

/// Topology/energy context of a candidate (precomputed per source by
/// the backend before scoring).
#[derive(Debug, Clone, Copy)]
pub struct StealCtx {
    /// Migration cost of this source for THIS thief, Q8 (SMT cheap ->
    /// NUMA expensive; cache-warm victims cost more).
    pub migcost_q8: u32,
    /// Thief and source share a frequency/power domain? On a single
    /// shared domain a migration moves no energy at all (the domain's
    /// OPP depends on the total, which does not change) — the energy
    /// term collapses to zero by construction.
    pub same_energy_domain: bool,
    /// Cluster utilisation of the thief's domain, Q8 (EAS input).
    pub cluster_util_me_q8: u32,
    /// Cluster utilisation of the source's domain, Q8.
    pub cluster_util_src_q8: u32,
}

/// Soft candidate score:
///
/// `score = a·urgency + b·fit − c_eff·ΔE − d·migcost`
///
/// * urgency — the victim's deadline-slip EWMA (tard_q8);
/// * fit — capacity-aware speedup placement hint;
/// * c_eff — the energy weight scaled DOWN by the source pressure:
///   a starving source is served regardless of ΔE, a comfortable one
///   only yields its victims when the move is energy-neutral-or-better;
/// * migcost — topology distance + cache warmth of the victim.
pub fn score(offer: &Offer, me: &CoreView, src: &CoreView, ctx: &StealCtx, now: u64, w: &Weights) -> i32 {
    let urgency = offer.tard_q8 as i32;
    // fit: how much the thief's capacity leverages the task's
    // heterogeneity hint (1.0 speedup on a full core = 256 = neutral).
    let fit = ((offer.speedup_q8 as i32 * me.cap_q8 as i32) >> 8).min(512);
    // Energy: both ends, EAS-style. ΔE = (E_me' − E_me) + (E_src' − E_src)
    // with E(core) = P(opp(util_domain)); intra-domain moves are 0.
    let d_e = if ctx.same_energy_domain {
        0
    } else {
        energy_delta(
            ctx.cluster_util_me_q8,
            ctx.cluster_util_src_q8,
            offer.util_q8,
            me,
            src,
        )
    };
    // Cache warmth: a victim parked microseconds ago on another core
    // pays the full distance price; a long-queued (cold) one pays a
    // quarter (its working set has decayed anyway).
    let warm = offer.last_ran != 0 && now.saturating_sub(offer.last_ran) < (offer.slice * CACHE_HOT_SLICES).max(1);
    let migcost = if warm {
        ctx.migcost_q8 as i32
    } else {
        (ctx.migcost_q8 >> 2) as i32
    };
    // Urgency-linked energy budget: c_eff = c · (1 − pressure_src).
    let c_eff = (w.energy * (256 - src.pressure_q8.min(256) as i32)) >> 8;
    (w.urgency * urgency + w.fit * fit - c_eff * d_e - w.migcost * migcost) >> 8
}

/// Static 4-step OPP table for the energy model (abstract rate levels;
/// a real DVFS driver would populate per-domain tables). Power in
/// abstract Q8 units per OPP level.
const OPP_THRESH_Q8: [u32; 4] = [64, 128, 192, 256];
const OPP_POWER_Q8: [u32; 4] = [40, 90, 160, 260];

#[inline]
fn opp_power(util_q8: u32) -> u32 {
    for (i, &t) in OPP_THRESH_Q8.iter().enumerate() {
        if util_q8 <= t {
            return OPP_POWER_Q8[i];
        }
    }
    OPP_POWER_Q8[OPP_POWER_Q8.len() - 1]
}

/// ΔE of moving `task_util` between the two domains (abstract units).
fn energy_delta(
    cluster_me_q8: u32,
    cluster_src_q8: u32,
    task_util_q8: u32,
    _me: &CoreView,
    _src: &CoreView,
) -> i32 {
    let u = cluster_me_q8.saturating_add(task_util_q8);
    let s = cluster_src_q8.saturating_sub(task_util_q8);
    let after = opp_power(u) as i32 + opp_power(s) as i32;
    let before = opp_power(cluster_me_q8) as i32 + opp_power(cluster_src_q8) as i32;
    after - before
}

// ───────────────────────── Publish-side selection ─────────────────────────

/// Offer selection from a queued-candidate snapshot: drop cache-hot
/// and cooldown-gated tasks, order by tardiness (worst slips first),
/// take at most `k`. `now` and `base_slice` come from the backend's
/// TSC/slice calibration.
///
/// (Vec variant, kept for host tests; the backend's preempt path uses
/// the allocation-free [`select_offers_into`].)
pub fn select_offers(
    cands: &[eevdf::QueuedCand],
    now: u64,
    base_slice: u64,
    k: usize,
    include_hot: bool,
) -> alloc::vec::Vec<Offer> {
    let hot_window = base_slice.saturating_mul(CACHE_HOT_SLICES).max(1);
    let mut picked: alloc::vec::Vec<Offer> = cands
        .iter()
        .filter(|c| {
            if now < c.cooldown_until {
                return false; // freshly stolen: minimum stay not served yet
            }
            if !include_hot && c.last_ran != 0 && now.saturating_sub(c.last_ran) < hot_window {
                return false; // cache-hot victim: better left in place
            }
            true
        })
        .map(|c| Offer {
            task: c.id,
            weight: c.weight,
            slice: c.slice,
            tard_q8: c.tard_q8,
            util_q8: c.util_q8,
            speedup_q8: c.speedup_q8,
            last_ran: c.last_ran,
        })
        .collect();
    picked.sort_unstable_by_key(|o| core::cmp::Reverse(o.tard_q8));
    picked.truncate(k);
    picked
}

/// v0.19: allocation-free variant of [`select_offers`] — fills `out`
/// with at most `k` offers kept sorted by tardiness (worst slip first)
/// and returns how many landed. The publisher passes a per-CPU scratch
/// buffer; the preempt-boundary publish path no longer touches the heap
/// (the Vec version allocated on every publish window).
///
/// v0.20 `include_hot`: cache-warmth yields to starvation relief. With
/// the strict cache-hot filter, a victim set where every task ran within
/// the hot window (two equal CPU-bound spinners alternating slices — each
/// is queued for exactly one slice) publishes an EMPTY showcase forever:
/// pressure crosses the hard threshold, the idle kick fires, the woken
/// thief finds nothing to claim and sleeps again — a livelock. When the
/// publisher's pressure is at/above [`PRESSURE_HARD_Q8`] the backend
/// passes `include_hot = true` and the showcase admits hot victims
/// (worst tardiness first, as always).
pub fn select_offers_into(
    cands: &[eevdf::QueuedCand],
    now: u64,
    base_slice: u64,
    k: usize,
    out: &mut [Offer],
    include_hot: bool,
) -> usize {
    let hot_window = base_slice.saturating_mul(CACHE_HOT_SLICES).max(1);
    let k = k.min(out.len());
    let mut n = 0;
    for c in cands {
        if now < c.cooldown_until {
            continue; // freshly stolen: minimum stay not served yet
        }
        if !include_hot && c.last_ran != 0 && now.saturating_sub(c.last_ran) < hot_window {
            continue; // cache-hot victim: better left in place
        }
        let off = Offer {
            task: c.id,
            weight: c.weight,
            slice: c.slice,
            tard_q8: c.tard_q8,
            util_q8: c.util_q8,
            speedup_q8: c.speedup_q8,
            last_ran: c.last_ran,
        };
        if n < k {
            // Insert into the sorted (tardiness-desc) prefix.
            out[n] = off;
            let mut i = n;
            while i > 0 && out[i - 1].tard_q8 < out[i].tard_q8 {
                out.swap(i - 1, i);
                i -= 1;
            }
            n += 1;
        } else if k > 0 && off.tard_q8 > out[k - 1].tard_q8 {
            // Replace the weakest and reposition it. (k == 0 skips here:
            // nothing is ever selected.)
            let mut i = k - 1;
            out[i] = off;
            while i > 0 && out[i - 1].tard_q8 < out[i].tard_q8 {
                out.swap(i - 1, i);
                i -= 1;
            }
        }
    }
    n
}

// ───────────────────────── Anti-thrash math ─────────────────────────

/// Minimum-stay window after the n-th migration, in raw time units:
/// 2 slices base, exponential backoff by migration counter (2, 4, 8,
/// 16 slices, capped). A freshly stolen task is not offered again
/// until the window expires.
#[inline]
pub fn min_stay_cycles(mig_count: u16, base_slice: u64) -> u64 {
    let shift = (mig_count as u32).min(3);
    base_slice.saturating_mul(2u64 << shift)
}

/// Post-failure steal backoff of a thief, in raw time units:
/// 1 slice base, exponential per consecutive failure (1, 2, 4, 8).
#[inline]
pub fn steal_backoff_cycles(consec_fails: u32, base_slice: u64) -> u64 {
    base_slice.saturating_mul(1u64 << consec_fails.min(3))
}

// ───────────────────────── IPI-kick policy (v0.20) ─────────────────────────
//
// The publisher-side hard-pressure kick: when deadline slips pile up
// past the hard threshold and NO active core is in a position to pull
// soon (all others idle or themselves overloaded past the steal
// epsilon), the publisher wakes ONE idle core with an IPI so the pull
// can happen immediately instead of waiting for a periodic tick.
//
// Architectural split: the DECISION (this section — pure, host-tested)
// vs the TRANSPORT (kernel-hal `IdleWakeInterface`, implemented by the
// backend: LAPIC resched-IPI on x86_64, an SGI on a future ARM port).

/// Snapshot of what the publisher sees when contemplating a kick.
#[derive(Debug, Clone, Copy)]
pub struct KickView {
    /// Publisher pressure (Q8 EWMA of late dispatches).
    pub pressure_q8: u32,
    /// Idle CPUs (bitmask, already intersected with the online mask;
    /// the publisher itself must NOT be in it).
    pub idle_mask: u64,
    /// An ACTIVE (non-idle) core exists that is expected to scan the
    /// showcase soon: its own pressure is below the steal epsilon, so
    /// its periodic steal is not suppressed. If true, a kick is
    /// redundant — relief is already on its way.
    pub active_relief: bool,
    /// Offers currently published on this publisher's shelf (the
    /// showcase a woken thief would scan).
    pub offers_published: usize,
}

/// Whether the publisher should IPI-kick an idle core right now.
/// Two fire modes:
///  * hard starvation — pressure at/above the hard threshold (by then
///    cache warmth has already yielded and victims are on the shelf);
///  * live shelf — sustained overload (pressure at/above the publish
///    threshold) with offers ACTUALLY published: without a kick the
///    showcase just sits there — an idle core is asleep in hlt and no
///    running core is in a position to pull (each past the steal
///    epsilon). This is the steady oversubscription case: pressure
///    saturates well below the hard line, yet the pull never happens
///    unless the source kicks.
///
/// Both modes require: no active relief en route and an idle target.
pub fn kick_idle_needed(v: &KickView) -> bool {
    let hard = v.pressure_q8 >= PRESSURE_HARD_Q8;
    let live_shelf = v.pressure_q8 >= PRESSURE_HI_Q8 && v.offers_published > 0;
    (hard || live_shelf) && !v.active_relief && v.idle_mask != 0
}

/// Rank and pick the idle core CHEAPEST to wake, in priority order:
///   1. wake class — shallowest C-state first (an C6 exit can be
///      50-100x the cost of C1; a hard-pressure victim cannot afford
///      the latency);
///   2. topology tier — SMT sibling of `origin`, then same LLC, then
///      the rest (cache warmth of the STOLEN task, which lived on the
///      publisher's side of the hierarchy);
///   3. recency — the most recently slept core wins within a tie
///      (its caches are the warmest and its C-state residency, if
///      escalation is in play, is the shallowest).
///
/// Pure function over caller-supplied accessors: no platform types
/// leak into the policy (the backend closes over the idle-wake HAL
/// seam, the topology tables and the idle-enter stamps).
pub fn select_kick_target(
    ncpu: usize,
    idle_mask: u64,
    wake_class: impl Fn(usize) -> u8,
    tier: impl Fn(usize) -> u8,
    idle_enter: impl Fn(usize) -> u64,
) -> Option<usize> {
    let mut best: Option<usize> = None;
    let mut b_cls = u8::MAX;
    let mut b_tier = u8::MAX;
    let mut b_enter = 0u64;
    for cpu in 0..ncpu {
        if (idle_mask >> cpu) & 1 == 0 {
            continue;
        }
        let (cls, tr, t) = (wake_class(cpu), tier(cpu), idle_enter(cpu));
        let better = cls < b_cls
            || (cls == b_cls && tr < b_tier)
            || (cls == b_cls && tr == b_tier && t > b_enter);
        if better {
            best = Some(cpu);
            b_cls = cls;
            b_tier = tr;
            b_enter = t;
        }
    }
    best
}

// ───────────────────────── Handoff (variant B) ─────────────────────────

/// Fallback-path steal request: the thief failed to try-lock the
/// source run-queue and asks the SOURCE to detach the victim at its
/// next schedule() and push it into the thief's handoff inbox.
#[derive(Debug, Clone, Copy)]
pub struct StealReq {
    pub task: u128,
    pub thief: u8,
    /// TSC when posted (diagnostics).
    pub posted_tsc: u64,
    /// TSC deadline: the source drops requests older than this.
    pub deadline_tsc: u64,
}

/// A detached entity in flight from source to thief (source-side
/// detach under the source run-queue lock; the thief attaches under
/// its own lock — the lag is carried in the SOURCE's virtual units and
/// clamped, per `eevdf::RunQueue::lag_of`).
#[derive(Debug, Clone, Copy)]
pub struct Handoff {
    pub entity: Entity,
    pub lag: i64,
}

// ───────────────────────── Owner-side per-CPU balancer state ─────────────────────────

/// Owner-core-only balancer state (no atomics — the backend keeps one
/// instance per CPU under its per-CPU discipline, like the context
/// slots). Touched at preempt boundaries and idle transitions only.
#[derive(Debug, Clone, Copy)]
pub struct OwnerLb {
    pub hyst: Hysteresis,
    /// Last showcase publication (TSC).
    pub last_publish_tsc: u64,
    /// Last periodic steal attempt (TSC).
    pub last_steal_tsc: u64,
    /// Consecutive failed steal attempts (backoff input).
    pub steal_fails: u32,
    /// Steal backoff deadline (TSC).
    pub steal_backoff_until: u64,
    /// Smoothed core utilisation, Q8 (sampled at preempt/idle).
    pub util_q8: u32,
}

impl OwnerLb {
    pub const fn new() -> Self {
        Self {
            hyst: Hysteresis::new(),
            last_publish_tsc: 0,
            last_steal_tsc: 0,
            steal_fails: 0,
            steal_backoff_until: 0,
            util_q8: 0,
        }
    }

    /// Utilisation EWMA sample (α=1/4) — busy at preempts, idle at
    /// idle entries.
    pub fn util_sample(&mut self, busy: bool) {
        let s = if busy { 256 } else { 0 };
        let old = self.util_q8;
        self.util_q8 = if s >= old {
            old + ((s - old) >> 2)
        } else {
            old - ((old - s) >> 2)
        };
    }

    /// Register a failed steal attempt (backoff grows).
    pub fn note_steal_fail(&mut self, now: u64, base_slice: u64) {
        self.steal_fails = self.steal_fails.saturating_add(1);
        self.steal_backoff_until = now.saturating_add(steal_backoff_cycles(self.steal_fails, base_slice));
    }

    /// Register a successful steal (backoff resets).
    pub fn note_steal_ok(&mut self) {
        self.steal_fails = 0;
        self.steal_backoff_until = 0;
    }
}

impl Default for OwnerLb {
    fn default() -> Self {
        Self::new()
    }
}

extern crate alloc;

// ───────────────────────── Tests (host, std) ─────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering as StOrdering};

    fn offer(task: u128, tard: u32, util: u32, last_ran: u64) -> Offer {
        Offer {
            task,
            weight: 1024,
            slice: 1000,
            tard_q8: tard,
            util_q8: util,
            speedup_q8: 256,
            last_ran,
        }
    }

    // ── word protocol ──

    #[test]
    fn slot_lifecycle_and_generation_advance() {
        let s = OfferSlot::new();
        assert_eq!(s.state(), SlotState::Free);
        assert!(s.publish(&offer(1, 10, 64, 0)));
        assert_eq!(s.state(), SlotState::Offered);
        // Double publish without release: rejected.
        assert!(!s.publish(&offer(2, 10, 64, 0)));
        let c = s.claim(7).expect("offered slot must be claimable");
        assert_eq!(c.offer.task, 1);
        assert_eq!(c.cycle, 0);
        assert_eq!(s.state(), SlotState::Claimed);
        // Second claim on a CLAIMED slot fails.
        assert!(s.claim(8).is_none());
        // Owner invalidate on a CLAIMED slot is a no-op (mid-transfer).
        assert!(!s.invalidate());
        s.release(c.cycle);
        assert_eq!(s.state(), SlotState::Free);
        // Generation advanced: a stale (cycle 0) publish is impossible by
        // construction (publish reuses the observed cycle), and a new
        // publish/claim cycle carries cycle+1.
        assert!(s.publish(&offer(3, 10, 64, 0)));
        let c2 = s.claim(9).expect("re-published slot claimable");
        assert_eq!(c2.cycle, 1, "generation must advance on each FREE return");
        assert_eq!(c2.offer.task, 3);
        s.release(c2.cycle);
    }

    #[test]
    fn invalidate_retires_offers_and_bumps_gen() {
        let s = OfferSlot::new();
        assert!(s.publish(&offer(5, 10, 64, 0)));
        assert!(s.invalidate());
        assert_eq!(s.state(), SlotState::Free);
        assert!(!s.invalidate());
        assert!(s.publish(&offer(6, 10, 64, 0)));
        let c = s.claim(1).unwrap();
        assert_eq!(c.cycle, 1, "invalidate advanced the generation");
        s.release(c.cycle);
    }

    #[test]
    fn claim_aba_protection_via_generation() {
        // After claim + release + republish, an old-generation claim
        // cannot resurrect the first payload: the claim CAS matches the
        // CURRENT word (cycle, OFFERED); a thief holding cycle g data from
        // a previous cycle simply fails the CAS on stale expectations.
        let s = OfferSlot::new();
        assert!(s.publish(&offer(11, 10, 64, 0)));
        let c1 = s.claim(2).unwrap();
        assert_eq!(c1.offer.task, 11);
        s.release(c1.cycle); // cycle 0 retired
        assert!(s.publish(&offer(12, 10, 64, 0)));
        let c2 = s.claim(3).unwrap();
        assert_eq!(c2.offer.task, 12, "new cycle must carry new payload");
        assert_ne!(c2.cycle, c1.cycle);
        s.release(c2.cycle);
    }

    #[test]
    fn concurrent_claims_have_exactly_one_winner() {
        // 8 threads race on a freshly published slot; exactly one claim
        // wins per generation. Repeat over many generations.
        const THREADS: usize = 8;
        const GENS: usize = 2000;
        let slot = Arc::new(OfferSlot::new());
        let wins = Arc::new(AtomicUsize::new(0));
        let cycle_published = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut handles = Vec::new();
        for t in 0..THREADS {
            let slot = Arc::clone(&slot);
            let wins = Arc::clone(&wins);
            let stop = Arc::clone(&stop);
            handles.push(std::thread::spawn(move || {
                let mut claimed_cycles: Vec<u32> = Vec::new();
                while !stop.load(StOrdering::Relaxed) {
                    if let Some(c) = slot.claim(t as u8) {
                        wins.fetch_add(1, StOrdering::Relaxed);
                        claimed_cycles.push(c.cycle);
                        slot.release(c.cycle);
                    }
                }
                // Each generation can be won at most once across all
                // threads: verify locally that our own wins are unique
                // (global uniqueness is the sum check below).
                claimed_cycles.sort_unstable();
                let mut dup = false;
                for w in claimed_cycles.windows(2) {
                    if w[0] == w[1] {
                        dup = true;
                    }
                }
                assert!(!dup, "a thread won the same generation twice");
            }));
        }
        for g in 0..GENS as u32 {
            // Wait until the slot is free, then publish generation g.
            loop {
                let w = slot.state();
                if w == SlotState::Free {
                    break;
                }
                std::hint::spin_loop();
            }
            assert!(slot.publish(&offer(g as u128, g as u32, 64, 0)));
            cycle_published.fetch_add(1, StOrdering::Relaxed);
        }
        // Retire the last offer if still pending and stop the racers.
        loop {
            if slot.state() == SlotState::Free || slot.invalidate() {
                break;
            }
        }
        stop.store(true, StOrdering::Relaxed);
        for h in handles {
            h.join().unwrap();
        }
        let total_wins = wins.load(StOrdering::Relaxed);
        let published = cycle_published.load(StOrdering::Relaxed);
        assert_eq!(
            total_wins, published,
            "exactly one winner per published generation ({total_wins} wins / {published} gens)"
        );
    }

    // ── shelf ──

    #[test]
    fn shelf_republish_and_claim_best() {
        let shelf = OfferShelf::new();
        assert!(!shelf.any_offered());
        // The backend publishes the OUTPUT of select_offers — already
        // sorted by tardiness, worst slip first. Republish takes them in
        // order until the shelf is full.
        let mut offers: Vec<Offer> = (0..K_SLOTS as u128 + 2)
            .map(|i| offer(i, (i * 10) as u32, 64, 0))
            .collect();
        offers.sort_unstable_by(|a, b| b.tard_q8.cmp(&a.tard_q8));
        let n = shelf.republish(&offers);
        assert_eq!(n, K_SLOTS, "shelf holds at most K offers");
        assert!(shelf.any_offered());
        // claim_best keeps the highest-scoring (tardiness) offer and
        // releases the losers.
        let (idx, c, sc) = shelf
            .claim_best(1, |o| o.tard_q8 as i32)
            .expect("offers exist");
        let best_tard = offers[0].tard_q8;
        assert_eq!(c.offer.tard_q8, best_tard, "best tardiness must win");
        assert_eq!(sc, best_tard as i32);
        // Losers released: only the winner stays claimed; the rest are
        // back to FREE (available for the next publish pass).
        let offered = shelf.slots.iter().filter(|s| s.state() == SlotState::Offered).count();
        let claimed = shelf.slots.iter().filter(|s| s.state() == SlotState::Claimed).count();
        let free = shelf.slots.iter().filter(|s| s.state() == SlotState::Free).count();
        assert_eq!(claimed, 1);
        assert_eq!(offered, 0, "claim_best must release the losers");
        assert_eq!(free, K_SLOTS - 1);
        shelf.release(idx, c.cycle);
        assert_eq!(
            shelf.slots.iter().filter(|s| s.state() == SlotState::Free).count(),
            K_SLOTS
        );
    }

    #[test]
    fn shelf_claim_best_reports_score_for_rejection() {
        let shelf = OfferShelf::new();
        shelf.republish(&[offer(3, 100, 64, 0), offer(4, 150, 64, 0)]);
        // All candidates rejected by the hard filter (i32::MIN): the
        // best is still handed back WITH its score — the caller must
        // check and decline (this is the admission-control contract).
        let (idx, c, sc) = shelf.claim_best(1, |_| i32::MIN).expect("claimed");
        assert_eq!(sc, i32::MIN);
        shelf.release(idx, c.cycle);
        assert_eq!(
            shelf.slots.iter().filter(|s| s.state() == SlotState::Free).count(),
            K_SLOTS
        );
    }

    #[test]
    fn shelf_withdraw_all() {
        let shelf = OfferShelf::new();
        shelf.republish(&[offer(1, 10, 64, 0), offer(2, 20, 64, 0)]);
        shelf.withdraw_all();
        assert!(!shelf.any_offered());
        assert!(shelf.claim_best(1, |o| o.tard_q8 as i32).is_none());
    }

    // ── hysteresis ──

    #[test]
    fn hysteresis_requires_consecutive_samples() {
        let mut h = Hysteresis::new();
        // Flutter around hi: never k consecutive — no raise.
        for i in 0..100 {
            let p = if i % 2 == 0 { PRESSURE_HI_Q8 + 10 } else { PRESSURE_HI_Q8 - 5 };
            assert_eq!(h.update(p), Edge::None);
        }
        // k consecutive high samples raise.
        assert_eq!(h.update(PRESSURE_HI_Q8 + 1), Edge::None);
        assert_eq!(h.update(PRESSURE_HI_Q8 + 1), Edge::Raised);
        assert!(h.over);
        // Flutter between lo and hi: no drop.
        for i in 0..100 {
            let p = if i % 2 == 0 { PRESSURE_LO_Q8 } else { PRESSURE_LO_Q8 + 10 };
            assert_eq!(h.update(p), Edge::None);
        }
        // k consecutive low samples drop.
        assert_eq!(h.update(PRESSURE_LO_Q8), Edge::None);
        assert_eq!(h.update(PRESSURE_LO_Q8), Edge::Dropped);
        assert!(!h.over);
    }

    // ── admission ──

    #[test]
    fn admission_symmetric_and_heterogeneous() {
        let me = CoreView::plain(64, 0); // 25% utilised thief
        let src = CoreView::plain(230, 128); // 90% utilised source
        // util_me + util_t = 64 + 128 = 192 <= 288: accepted.
        assert!(admission_ok(&me, &src, 128));
        // 64 + 255 = 319 > 288: rejected (thief would overload itself).
        assert!(!admission_ok(&me, &src, 255));
        // Heterogeneous: little thief (cap 128) pulling from big (cap 256)
        // scales the task demand by 2x and tightens the margin.
        let little = CoreView { cap_q8: 128, util_q8: 64, pressure_q8: 0 };
        let big = CoreView { cap_q8: 256, util_q8: 200, pressure_q8: 200 };
        // util_t=100 scales to 200; budget = 128*(288-16)/256 = 136;
        // 64 + 200 = 264 > 136: rejected (down-migration is hard).
        assert!(!admission_ok(&little, &big, 100));
        // Up-migration to big from little gets slack and scale-down.
        let big_thief = CoreView { cap_q8: 256, util_q8: 100, pressure_q8: 0 };
        let little_src = CoreView { cap_q8: 128, util_q8: 120, pressure_q8: 200 };
        // util_t=120 scales to 60; budget = 256*(288+16)/256 = 304;
        // 100 + 60 = 160 <= 304: accepted.
        assert!(admission_ok(&big_thief, &little_src, 120));
    }

    // ── scoring ──

    #[test]
    fn score_orders_by_urgency_and_respects_energy_budget() {
        let w = DEFAULT_WEIGHTS;
        let now = 100_000;
        let ctx = StealCtx {
            migcost_q8: 128,
            same_energy_domain: true, // flat x86: ΔE = 0
            cluster_util_me_q8: 64,
            cluster_util_src_q8: 200,
        };
        let me = CoreView::plain(64, 0);
        let mut src_comfy = CoreView::plain(200, 0);
        let urgent = offer(1, 200, 64, 0);
        let calm = offer(2, 10, 64, 0);
        // Same source: urgent wins.
        assert!(score(&urgent, &me, &src_comfy, &ctx, now, &w) > score(&calm, &me, &src_comfy, &ctx, now, &w));
        // Cross-domain energy: a starving source zeroes the energy term.
        let mut ctx_x = ctx;
        ctx_x.same_energy_domain = false;
        // The thief's domain sits at 70 (just below the 128 OPP step):
        // pulling the task in (util 64) pushes it to 134 -> next OPP,
        // a real positive ΔE for a comfortable source.
        ctx_x.cluster_util_me_q8 = 70;
        ctx_x.cluster_util_src_q8 = 70;
        let s_comfy = score(&calm, &me, &src_comfy, &ctx_x, now, &w);
        let mut src_starving = src_comfy;
        src_starving.pressure_q8 = 256;
        let s_starving = score(&calm, &me, &src_starving, &ctx_x, now, &w);
        assert!(s_starving > s_comfy, "urgency must buy an energy budget");
        src_comfy.pressure_q8 = 10;
        let _ = src_comfy;
    }

    #[test]
    fn score_penalizes_cache_warm_victims() {
        let w = DEFAULT_WEIGHTS;
        let ctx = StealCtx { migcost_q8: 128, same_energy_domain: true, cluster_util_me_q8: 0, cluster_util_src_q8: 0 };
        let me = CoreView::plain(64, 0);
        let src = CoreView::plain(200, 100);
        let now = 1_000_000u64;
        let warm = offer(1, 100, 64, now - 100); // parked 100 cycles ago (hot)
        let cold = offer(2, 100, 64, now - 500_000); // parked long ago
        assert!(score(&cold, &me, &src, &ctx, now, &w) > score(&warm, &me, &src, &ctx, now, &w));
    }

    // ── selection ──

    fn cand(id: u128, tard: u32, last_ran: u64, cooldown: u64) -> eevdf::QueuedCand {
        eevdf::QueuedCand {
            id,
            weight: 1024,
            slice: 1000,
            deadline: 0,
            tard_q8: tard,
            util_q8: 64,
            speedup_q8: 256,
            last_ran,
            cooldown_until: cooldown,
        }
    }

    #[test]
    fn select_offers_filters_and_sorts() {
        let now = 1_000_000u64;
        let base = 10_000u64; // slice; hot window = 2 slices = 20_000
        let cands = vec![
            cand(1, 50, now - 100, 0),         // cache-hot: filtered
            cand(2, 10, now - 1_000_000, 0),   // cold, low tard
            cand(3, 200, now - 1_000_000, 0),  // cold, worst slip
            cand(4, 150, now - 1_000_000, now + 50_000), // cooldown: filtered
            cand(5, 100, 0, 0),                // never ran: cold enough
        ];
        let picked = select_offers(&cands, now, base, K_SLOTS, false);
        let ids: Vec<u128> = picked.iter().map(|o| o.task).collect();
        assert_eq!(ids, vec![3, 5, 2], "tardiness-descending, filters applied");
        // k bound:
        let many: Vec<eevdf::QueuedCand> = (0..10u128).map(|i| cand(100 + i, (i * 20) as u32, 0, 0)).collect();
        assert_eq!(select_offers(&many, now, base, 2, false).len(), 2);
    }

    #[test]
    fn select_offers_hard_relief_admits_hot_victims() {
        let now = 1_000_000u64;
        let base = 10_000u64; // hot window = 2 slices = 20_000
        // Two equal CPU-bound spinners alternating slices: each queued
        // task last ran well within the hot window -> the strict filter
        // publishes an EMPTY showcase (livelock with a useless kick).
        let cands = vec![
            cand(1, 50, now - 100, 0),  // hot
            cand(2, 240, now - 500, 0), // hot, worst slip
        ];
        assert_eq!(
            select_offers(&cands, now, base, K_SLOTS, false).len(),
            0,
            "strict mode: all hot -> empty showcase"
        );
        // Hard starvation: hot victims admitted, worst slip first.
        let picked = select_offers(&cands, now, base, K_SLOTS, true);
        let ids: Vec<u128> = picked.iter().map(|o| o.task).collect();
        assert_eq!(ids, vec![2, 1]);
        // Both variants agree in hard mode too.
        let mut b = [Offer::ZERO; 4];
        let bn = select_offers_into(&cands, now, base, 4, &mut b, true);
        assert_eq!(bn, 2);
        assert_eq!(b[0].task, 2);
        assert_eq!(b[1].task, 1);
    }

    #[test]
    fn select_offers_into_matches_vec_version() {
        let now = 1_000_000u64;
        let base = 10_000u64; // hot window = 2 slices = 20_000
        // Distinct tardiness values (37 is invertible mod 260): the two
        // variants must agree element-for-element, worst slip first.
        let cands: Vec<eevdf::QueuedCand> = (0..40u128)
            .map(|i| cand(100 + i, (i * 37 % 260) as u32, 0, 0))
            .collect();
        let a = select_offers(&cands, now, base, 3, false);
        let mut b = [Offer::ZERO; 3];
        let bn = select_offers_into(&cands, now, base, 3, &mut b, false);
        assert_eq!(a.len(), bn);
        for i in 0..bn {
            assert_eq!(a[i].task, b[i].task, "same pick order, index {}", i);
            assert_eq!(a[i].tard_q8, b[i].tard_q8);
        }
        // Degenerate shapes: empty candidates, k = 0, oversized out.
        let mut z = [Offer::ZERO; 4];
        assert_eq!(select_offers_into(&[], now, base, 3, &mut z, false), 0);
        assert_eq!(select_offers_into(&cands, now, base, 0, &mut z, false), 0);
        assert_eq!(select_offers_into(&cands, now, base, 99, &mut z, false), 4);
    }

    // ── anti-thrash math ──

    #[test]
    fn min_stay_and_backoff_progression() {
        let s = 1000u64;
        assert_eq!(min_stay_cycles(0, s), 2 * s);
        assert_eq!(min_stay_cycles(1, s), 4 * s);
        assert_eq!(min_stay_cycles(2, s), 8 * s);
        assert_eq!(min_stay_cycles(3, s), 16 * s);
        assert_eq!(min_stay_cycles(9, s), 16 * s, "capped backoff");
        assert_eq!(steal_backoff_cycles(0, s), s);
        assert_eq!(steal_backoff_cycles(1, s), 2 * s);
        assert_eq!(steal_backoff_cycles(7, s), 8 * s, "capped backoff");
    }

    #[test]
    fn owner_lb_backoff_and_util() {
        let mut o = OwnerLb::new();
        for _ in 0..10 {
            o.util_sample(true);
        }
        assert!(o.util_q8 > 200, "busy samples must raise util, got {}", o.util_q8);
        for _ in 0..40 {
            o.util_sample(false);
        }
        assert!(o.util_q8 < 10, "idle samples must drain util, got {}", o.util_q8);
        o.note_steal_fail(100, 1000);
        assert_eq!(o.steal_backoff_until, 100 + 2 * 1000);
        o.note_steal_ok();
        assert_eq!(o.steal_fails, 0);
        assert_eq!(o.steal_backoff_until, 0);
    }

    // ───────── IPI-kick policy (v0.20) ─────────

    fn kv(pressure: u32, idle: u64, relief: bool) -> KickView {
        KickView {
            pressure_q8: pressure,
            idle_mask: idle,
            active_relief: relief,
            offers_published: 0,
        }
    }

    #[test]
    fn kick_needed_full_matrix() {
        // Below the hard threshold, empty shelf: never kick.
        assert!(!kick_idle_needed(&kv(PRESSURE_HARD_Q8 - 1, 0b11, false)));
        // Hard pressure + idle targets + no relief: KICK (fires with an
        // empty shelf too — hard starvation already forced hot victims
        // onto the shelf via include_hot).
        assert!(kick_idle_needed(&kv(PRESSURE_HARD_Q8, 0b10, false)));
        // Relief core active: the periodic steal is coming — no kick.
        assert!(!kick_idle_needed(&kv(PRESSURE_HARD_Q8, 0b10, true)));
        // Nobody idle to kick.
        assert!(!kick_idle_needed(&kv(PRESSURE_HARD_Q8 + 50, 0, false)));
        // Far past the threshold still kicks (hard starvation).
        assert!(kick_idle_needed(&kv(255, 0b01, false)));
    }

    #[test]
    fn kick_needed_live_shelf_below_hard() {
        // Sustained overload with a LIVE shelf must kick even below the
        // hard threshold: the showcase is full but every other core is
        // asleep — without a kick nobody ever scans the shelf (the
        // steady oversubscription case measured in QEMU: pressure
        // saturates around 75-111 while candidates wait 3 slices).
        let mut v = kv(PRESSURE_HI_Q8, 0b10, false);
        v.offers_published = 2;
        assert!(kick_idle_needed(&v));
        // Same pressure, EMPTY shelf: nothing for a woken thief to
        // claim — a kick would just burn a C-state exit.
        v.offers_published = 0;
        assert!(!kick_idle_needed(&v));
        // Live shelf but an active underloaded runner exists: it pulls
        // on its own preempt boundary — kicking is redundant.
        v.offers_published = 2;
        v.active_relief = true;
        assert!(!kick_idle_needed(&v));
        // Below the publish threshold entirely.
        v.active_relief = false;
        v.pressure_q8 = PRESSURE_HI_Q8 - 1;
        assert!(!kick_idle_needed(&v));
    }

    #[test]
    fn kick_target_prefers_shallow_wake_class() {
        // cpu0: deep (class 3), SMT sibling; cpu1: C1 (class 1), far
        // away. The C-state dominates the topology tier: waking a deep
        // sleeper costs 50-100x a C1 exit.
        let t = select_kick_target(
            2,
            0b11,
            |c| if c == 0 { 3 } else { 1 },
            |c| if c == 0 { 0 } else { 2 },
            |_| 0,
        );
        assert_eq!(t, Some(1), "shallow C1 must beat the deep SMT sibling");
    }

    #[test]
    fn kick_target_tier_then_recency_within_class() {
        // Same wake class: SMT tier wins over LLC, recency breaks ties.
        let t = select_kick_target(
            3,
            0b111,
            |_| 1,
            |c| {
                if c == 0 {
                    0
                } else if c == 1 {
                    1
                } else {
                    1
                }
            },
            |c| if c == 1 { 500 } else { 100 },
        );
        assert_eq!(t, Some(0), "SMT sibling first");
        let t = select_kick_target(2, 0b11, |_| 1, |_| 1, |c| if c == 0 { 900 } else { 100 });
        assert_eq!(t, Some(0), "most recently slept wins the tie");
    }

    #[test]
    fn kick_target_ignores_non_idle_and_empty() {
        assert_eq!(select_kick_target(4, 0, |_| 1, |_| 0, |_| 0), None);
        // Only bit 3 idle among 0..4 -> picked despite worse keys.
        let t = select_kick_target(
            4,
            0b1000,
            |c| if c == 3 { 2 } else { 1 },
            |c| if c == 3 { 2 } else { 0 },
            |_| 0,
        );
        assert_eq!(t, Some(3), "the only idle cpu is the answer");
    }
}
