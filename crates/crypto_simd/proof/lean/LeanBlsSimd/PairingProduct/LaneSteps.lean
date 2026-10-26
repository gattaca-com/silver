import LeanBlsSimd.Refines.G2x8

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.PairingProduct.Lanes

structure Lines where
  l0 : Fp2x8
  l1 : Fp2x8
  l2 : Fp2x8

structure State where
  t : G2x8
  qx : Fp2x8
  qy : Fp2x8
  minusTwoPx : Fp8
  twoPy : Fp8
  count : Usize
  degenerate : Mmask8

def ofState (s : lane_pairs.LanePairs) : State :=
  ⟨ofG2x8 s.t, ofFp2x8 s.qx, ofFp2x8 s.qy, ofFp8 s.minus_two_px,
    ofFp8 s.two_py, s.count, ofU8 s.degenerate⟩

def toState (s : State) : lane_pairs.LanePairs :=
  ⟨toG2x8 s.t, toFp2x8 s.qx, toFp2x8 s.qy, toFp8 s.minusTwoPx,
    toFp8 s.twoPy, s.count, toU8 s.degenerate⟩

def toLines (l : Lines) : lane_pairs.Lines :=
  ⟨toFp2x8 l.l0, toFp2x8 l.l1, toFp2x8 l.l2⟩

@[simp] theorem ofState_toState (s : State) : ofState (toState s) = s := by
  cases s
  simp [ofState, toState]

@[simp] theorem toState_ofState (s : lane_pairs.LanePairs) : toState (ofState s) = s := by
  cases s
  simp [ofState, toState]

def activeMask (count : Usize) : Mmask8 := UInt8.ofNat (2 ^ count.val - 1)

def atP (s : State) (l0 l1 l2 : Fp2x8) : Lines :=
  ⟨l0, ⟨l1.c0.mul s.minusTwoPx, l1.c1.mul s.minusTwoPx⟩,
    ⟨l2.c0.mul s.twoPy, l2.c1.mul s.twoPy⟩⟩

def double (s : State) : Lines × State :=
  let x := s.t.x
  let y := s.t.y
  let z := s.t.z
  let a := x.square
  let b := y.square
  let zz := z.square
  let c := b.square
  let d := ((x.add b).square.sub a).sub c
  let d := d.add d
  let e := (a.add a).add a
  let f := e.square
  let x3 := (f.sub d).sub d
  let z3 := ((y.add z).square.sub b).sub zz
  let c2 := c.add c
  let c4 := c2.add c2
  let y3 := (e.mul (d.sub x3)).sub (c4.add c4)
  let b2 := b.add b
  let l0 := (((e.add x).square.sub a).sub f).sub (b2.add b2)
  let l1 := e.mul zz
  let l2 := z3.mul zz
  let next := { s with
    t := ⟨x3, y3, z3⟩
    degenerate := s.degenerate ||| (z3.is_zero_mask &&& activeMask s.count) }
  (atP next l0 l1 l2, next)

def add (s : State) : Lines × State :=
  let x := s.t.x
  let y := s.t.y
  let z := s.t.z
  let z1z1 := z.square
  let u2 := s.qx.mul z1z1
  let s2 := (s.qy.mul z).mul z1z1
  let h := u2.sub x
  let hh := h.square
  let i2 := hh.add hh
  let i := i2.add i2
  let j := h.mul i
  let r := s2.sub y
  let r := r.add r
  let v := x.mul i
  let x3 := ((r.square.sub j).sub v).sub v
  let yj := y.mul j
  let y3 := (((v.sub x3).mul r).sub yj).sub yj
  let z3 := ((z.add h).square.sub z1z1).sub hh
  let l0 := (r.mul s.qx).sub (s.qy.mul z3)
  let l0 := l0.add l0
  let next := { s with
    t := ⟨x3, y3, z3⟩
    degenerate := s.degenerate ||| (z3.is_zero_mask &&& activeMask s.count) }
  (atP next l0 r z3, next)

theorem active_mask_refines (s : lane_pairs.LanePairs)
    (hlo : 1 ≤ s.count.val) (hhi : s.count.val ≤ 8) :
    lane_pairs.LanePairs.active_mask s = ok (toU8 (activeMask s.count)) := by
  unfold lane_pairs.LanePairs.active_mask
  rw [sub_ok _ _ (by simpa [limbs.LANES] using hhi)]
  simp only [limbs.LANES, bind_tc_ok]
  change UScalar.shiftRight core.num.U8.MAX (8 - s.count.val) = _
  interval_cases hv : s.count.val <;>
    simp [activeMask, hv, UScalar.shiftRight, core.num.U8.MAX, toU8]
  all_goals decide +kernel

theorem at_p_refines (s : lane_pairs.LanePairs) (l0 l1 l2 : fp2x8.Fp2x8) :
    lane_pairs.LanePairs.at_p s l0 l1 l2 =
      ok (toLines (atP (ofState s) (ofFp2x8 l0) (ofFp2x8 l1) (ofFp2x8 l2))) := by
  simp [lane_pairs.LanePairs.at_p, Fp8.mul_refines, atP, ofState, toLines, toFp2x8]

theorem double_refines (s : lane_pairs.LanePairs)
    (hlo : 1 ≤ s.count.val) (hhi : s.count.val ≤ 8) :
    lane_pairs.LanePairs.double s = ok (Prod.map toLines toState (double (ofState s))) := by
  simp [lane_pairs.LanePairs.double, Fp2x8.square_refines, Fp2x8.add_refines,
    Fp2x8.sub_refines, Fp2x8.mul_refines, Fp2x8.is_zero_mask_refines,
    active_mask_refines s hlo hhi, at_p_refines, double, atP, ofState,
    toState, toLines, toG2x8, toFp2x8, lift]
  rfl

theorem add_refines (s : lane_pairs.LanePairs)
    (hlo : 1 ≤ s.count.val) (hhi : s.count.val ≤ 8) :
    lane_pairs.LanePairs.add s = ok (Prod.map toLines toState (add (ofState s))) := by
  simp [lane_pairs.LanePairs.add, Fp2x8.square_refines, Fp2x8.add_refines,
    Fp2x8.sub_refines, Fp2x8.mul_refines, Fp2x8.is_zero_mask_refines,
    active_mask_refines s hlo hhi, at_p_refines, add, atP, ofState,
    toState, toLines, toG2x8, toFp2x8, lift]
  rfl

end LeanBlsSimd.PairingProduct.Lanes
