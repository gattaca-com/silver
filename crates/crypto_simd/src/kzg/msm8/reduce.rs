use std::arch::x86_64::{__m512i, __mmask8, _mm512_loadu_si512};

use blst::{
    blst_fp, blst_p1, blst_p1_add_or_double, blst_p1_add_or_double_affine, blst_p1_affine,
    blst_p1_double, blst_p1_is_inf,
};

use crate::{
    bls::{
        fp8::{Fp8, LANES},
        g1x8::G1x8,
        g1x8_lazy::Offsets,
    },
    kzg::msm8::{
        buckets::{Buckets, NEGATED},
        store::PointStore,
    },
};

/// Window groups summed in lockstep, so that every curve operation has an
/// independent sibling in flight.
const PAIR: usize = 2;

/// The sum S_j = Σ_b b·B_(j,b) of each window's buckets.
#[derive(Default)]
pub struct WindowSums {
    sums: Vec<blst_p1>,
}

impl WindowSums {
    /// Eight windows at a time, one per lane, with running sums T = Σ_(b' ≥ b)
    /// B_b' and S += T for b from the top bucket down to 1. False when a lane
    /// sums to infinity in blst, which the lanes cannot hold.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn compute(&mut self, buckets: &Buckets, store: &PointStore) -> bool {
        self.sums.clear();
        let groups = buckets.windows().div_ceil(LANES);
        let mut group = 0;
        while group < groups {
            let width = PAIR.min(groups - group);
            let summed = if width == PAIR {
                window_group_sums::<PAIR>(buckets, store, group)
                    .map(|s| self.push(&s, group, buckets))
            } else {
                window_group_sums::<1>(buckets, store, group).map(|s| self.push(&s, group, buckets))
            };
            if summed.is_none() {
                return false;
            }
            group += width;
        }
        true
    }

    fn push(&mut self, sums: &[[blst_p1; LANES]], first_group: usize, buckets: &Buckets) {
        for (k, lanes) in sums.iter().enumerate() {
            let first_window = (first_group + k) * LANES;
            self.sums.extend(&lanes[..LANES.min(buckets.windows() - first_window)]);
        }
    }

    /// Σ_j 2^(w·j)·S_j.
    pub fn combine(&self, window_bits: usize) -> blst_p1 {
        let mut total = blst_p1::default();
        for sum in self.sums.iter().rev() {
            for _ in 0..window_bits {
                let doubled = total;
                // SAFETY: valid pointers to single values.
                unsafe { blst_p1_double(&mut total, &doubled) };
            }
            let before = total;
            // SAFETY: valid pointers to single values.
            unsafe { blst_p1_add_or_double(&mut total, &before, sum) };
        }
        total
    }
}

struct Lanes {
    index: [i64; LANES],
    present: __mmask8,
    negated: __mmask8,
}

impl Lanes {
    fn of(buckets: &Buckets, first_window: usize, bucket: usize) -> Self {
        let mut lanes = Self { index: [0; LANES], present: 0, negated: 0 };
        for lane in 0..LANES {
            let window = first_window + lane;
            if window >= buckets.windows() {
                continue;
            }
            if let Some(reference) = buckets.first(window, bucket) {
                lanes.index[lane] = i64::from(reference & !NEGATED);
                lanes.present |= 1 << lane;
                if reference & NEGATED != 0 {
                    lanes.negated |= 1 << lane;
                }
            }
        }
        lanes
    }
}

/// `W` groups of eight windows, from window `8·first_group`.
#[target_feature(enable = "avx512f,avx512ifma")]
fn window_group_sums<const W: usize>(
    buckets: &Buckets,
    store: &PointStore,
    first_group: usize,
) -> Option<[[blst_p1; LANES]; W]> {
    let c = Offsets::new();
    let mut t: [G1x8; W] = std::array::from_fn(|_| G1x8::from_affine(&Fp8::zero(), &Fp8::zero()));
    let mut s: [G1x8; W] = std::array::from_fn(|_| G1x8::from_affine(&Fp8::zero(), &Fp8::zero()));
    let mut t_infinite = [0xffu8; W];
    let mut s_infinite = [0xffu8; W];
    for bucket in (1..=buckets.buckets_per_window()).rev() {
        let lanes: [Lanes; W] =
            std::array::from_fn(|w| Lanes::of(buckets, (first_group + w) * LANES, bucket));
        let b: [(Fp8, Fp8); W] = std::array::from_fn(|w| {
            let (bx, by) = store.load_points(load_indices(&lanes[w].index));
            (bx, Fp8::select(lanes[w].negated, &by, &c.neg(&by)))
        });
        let sums: [(G1x8, __mmask8); W] =
            std::array::from_fn(|w| t[w].add_affine(&b[w].0, &b[w].1));
        for w in 0..W {
            let present = lanes[w].present;
            if present == 0 {
                continue;
            }
            let (sum, undecided) = &sums[w];
            let (bx, by) = &b[w];
            let first = present & t_infinite[w];
            let adding = present & !t_infinite[w];
            let mut next = G1x8 {
                x: Fp8::select(adding, &Fp8::select(first, &t[w].x, bx), &sum.x),
                y: Fp8::select(adding, &Fp8::select(first, &t[w].y, by), &sum.y),
                z: Fp8::select(adding, &Fp8::select(first, &t[w].z, &Fp8::one()), &sum.z),
            };
            let exceptional = undecided & adding;
            if exceptional != 0 {
                next = add_affine_in_blst(store, &t[w], (bx, by), next, exceptional)?;
            }
            t[w] = next;
            t_infinite[w] &= !present;
        }

        let sums: [(G1x8, __mmask8); W] = std::array::from_fn(|w| s[w].add(&t[w]));
        for w in 0..W {
            let (sum, undecided) = &sums[w];
            let first = !t_infinite[w] & s_infinite[w];
            let adding = !t_infinite[w] & !s_infinite[w];
            let mut next = G1x8 {
                x: Fp8::select(adding, &Fp8::select(first, &s[w].x, &t[w].x), &sum.x),
                y: Fp8::select(adding, &Fp8::select(first, &s[w].y, &t[w].y), &sum.y),
                z: Fp8::select(adding, &Fp8::select(first, &s[w].z, &t[w].z), &sum.z),
            };
            let exceptional = undecided & adding;
            if exceptional != 0 {
                next = add_in_blst(store, &s[w], &t[w], next, exceptional)?;
            }
            s[w] = next;
            s_infinite[w] &= t_infinite[w];
        }
    }

    let mut out: [[blst_p1; LANES]; W] = [[blst_p1::default(); LANES]; W];
    for w in 0..W {
        let points = jacobian_lanes(&s[w]);
        for lane in 0..LANES {
            if s_infinite[w] & (1 << lane) == 0 {
                out[w][lane] = points[lane];
            }
        }
    }
    Some(out)
}

#[target_feature(enable = "avx512f,avx512ifma")]
pub(super) fn load_indices(indices: &[i64; LANES]) -> __m512i {
    // SAFETY: an unaligned load of the 64 bytes of `indices`.
    unsafe { _mm512_loadu_si512(indices.as_ptr().cast()) }
}

/// `next` with the `exceptional` lanes of `t + b` taken from blst's complete
/// addition. None when one is infinity, which the lanes cannot hold.
#[target_feature(enable = "avx512f,avx512ifma")]
fn add_affine_in_blst(
    store: &PointStore,
    t: &G1x8,
    b: (&Fp8, &Fp8),
    next: G1x8,
    exceptional: __mmask8,
) -> Option<G1x8> {
    let ts = jacobian_lanes(t);
    let bs = affine_lanes(b.0, b.1);
    let mut nexts = jacobian_lanes(&next);
    for lane in (0..LANES).filter(|lane| exceptional & (1 << lane) != 0) {
        let mut sum = blst_p1::default();
        // SAFETY: valid pointers to single values.
        unsafe { blst_p1_add_or_double_affine(&mut sum, &ts[lane], &bs[lane]) };
        // SAFETY: a valid pointer to a single value.
        if unsafe { blst_p1_is_inf(&sum) } {
            return None;
        }
        nexts[lane] = sum;
    }
    Some(jacobian_from_lanes(store, &nexts))
}

/// As `add_affine_in_blst`, for `s + t`.
#[target_feature(enable = "avx512f,avx512ifma")]
fn add_in_blst(
    store: &PointStore,
    s: &G1x8,
    t: &G1x8,
    next: G1x8,
    exceptional: __mmask8,
) -> Option<G1x8> {
    let ss = jacobian_lanes(s);
    let ts = jacobian_lanes(t);
    let mut nexts = jacobian_lanes(&next);
    for lane in (0..LANES).filter(|lane| exceptional & (1 << lane) != 0) {
        let mut sum = blst_p1::default();
        // SAFETY: valid pointers to single values.
        unsafe { blst_p1_add_or_double(&mut sum, &ss[lane], &ts[lane]) };
        // SAFETY: a valid pointer to a single value.
        if unsafe { blst_p1_is_inf(&sum) } {
            return None;
        }
        nexts[lane] = sum;
    }
    Some(jacobian_from_lanes(store, &nexts))
}

#[target_feature(enable = "avx512f,avx512ifma")]
pub(super) fn jacobian_lanes(point: &G1x8) -> [blst_p1; LANES] {
    let (x, y, z) = (point.x.to_blst_limbs(), point.y.to_blst_limbs(), point.z.to_blst_limbs());
    std::array::from_fn(|lane| blst_p1 {
        x: blst_fp { l: x[lane] },
        y: blst_fp { l: y[lane] },
        z: blst_fp { l: z[lane] },
    })
}

#[target_feature(enable = "avx512f,avx512ifma")]
fn affine_lanes(x: &Fp8, y: &Fp8) -> [blst_p1_affine; LANES] {
    let (x, y) = (x.to_blst_limbs(), y.to_blst_limbs());
    std::array::from_fn(|lane| blst_p1_affine {
        x: blst_fp { l: x[lane] },
        y: blst_fp { l: y[lane] },
    })
}

#[target_feature(enable = "avx512f,avx512ifma")]
fn jacobian_from_lanes(store: &PointStore, points: &[blst_p1; LANES]) -> G1x8 {
    G1x8 {
        x: store.fp8_from_blst(&std::array::from_fn(|lane| points[lane].x.l)),
        y: store.fp8_from_blst(&std::array::from_fn(|lane| points[lane].y.l)),
        z: store.fp8_from_blst(&std::array::from_fn(|lane| points[lane].z.l)),
    }
}
