import LeanBlsSimd.PairingProduct.LaneSteps
import LeanBlsSimd.PairingProduct.StepField
import LeanBlsSimd.Proofs.G2x8

open Aeneas.Std
open EthLib.Cryptography Bls

namespace LeanBlsSimd.PairingProduct.Lanes

def scalar (a : Fp) : Fp2Field := ⟨a, 0⟩

structure State.Holds (s : State) (l : Fin 8) (t : Step.Point)
    (q : Fp2Field × Fp2Field) (xp yp : Fp) : Prop where
  t : s.t.Holds l t
  qx : s.qx.Holds l q.1
  qy : s.qy.Holds l q.2
  px : s.minusTwoPx.Holds l (-(xp + xp))
  py : s.twoPy.Holds l (yp + yp)

structure Lines.Holds (lines : Lines) (l : Fin 8) (coefficients : Fin 3 → Fp2Field)
    (xp yp : Fp) : Prop where
  l0 : lines.l0.Holds l (coefficients 0)
  l1 : lines.l1.Holds l (coefficients 1 * scalar (-(xp + xp)))
  l2 : lines.l2.Holds l (coefficients 2 * scalar (yp + yp))

private theorem scalar_mul_holds {v : Fp2x8} {a : Fp8} {l : Fin 8}
    {x : Fp2Field} {k : Fp} (hv : v.Holds l x) (ha : a.Holds l k) :
    (Fp2x8.mk (v.c0.mul a) (v.c1.mul a)).Holds l (x * scalar k) := by
  constructor
  · exact (hv.re.mul ha).of_eq (by simp [scalar, QuadraticAlgebra.re_mul])
  · exact (hv.im.mul ha).of_eq (by simp [scalar, QuadraticAlgebra.im_mul])

theorem activeMask_testBit (count : Usize) (hhi : count.val ≤ 8) (l : Fin 8) :
    (activeMask count).toNat.testBit l = decide (l.val < count.val) := by
  interval_cases hv : count.val <;> fin_cases l <;> simp [activeMask, hv]
  all_goals decide +kernel

theorem double_holds {s : State} {l : Fin 8} {t : Step.Point}
    {q : Fp2Field × Fp2Field} {xp yp : Fp} (h : s.Holds l t q xp yp)
    (hhi : s.count.val ≤ 8) :
    (double s).2.Holds l (Step.double t).point q xp yp ∧
      (double s).1.Holds l (Step.double t).line xp yp ∧
      (double s).2.degenerate.toNat.testBit l =
        (s.degenerate.toNat.testBit l ||
          (decide ((Step.double t).point 2 = 0) && decide (l.val < s.count.val))) := by
  have ha := h.t.x.square
  have hb := h.t.y.square
  have hzz := h.t.z.square
  have hc := hb.square
  have hd0 := ((h.t.x.add hb).square.sub ha).sub hc
  have hd := hd0.add hd0
  have he := (ha.add ha).add ha
  have hf := he.square
  have hx3 := (hf.sub hd).sub hd
  have hz3 := ((h.t.y.add h.t.z).square.sub hb).sub hzz
  have hc2 := hc.add hc
  have hc4 := hc2.add hc2
  have hy3 := (he.mul (hd.sub hx3)).sub (hc4.add hc4)
  have hb2 := hb.add hb
  have hl0 := (((he.add h.t.x).square.sub ha).sub hf).sub (hb2.add hb2)
  have hl1 := scalar_mul_holds (he.mul hzz) h.px
  have hl2 := scalar_mul_holds (hz3.mul hzz) h.py
  refine ⟨⟨⟨?_, ?_, ?_⟩, ?_, ?_, ?_, ?_⟩, ⟨?_, ?_, ?_⟩, ?_⟩
  · simpa only [double, Step.double, Matrix.cons_val_zero, pow_two] using hx3
  · simpa only [double, Step.double, Matrix.cons_val_one, pow_two] using hy3
  · simpa only [double, Step.double, Matrix.cons_val_two, pow_two] using hz3
  · exact h.qx
  · exact h.qy
  · exact h.px
  · exact h.py
  · simpa only [double, atP, Step.double, Matrix.cons_val_zero, pow_two] using hl0
  · simpa only [double, atP, Step.double, Matrix.cons_val_one, pow_two] using hl1
  · simpa only [double, atP, Step.double, Matrix.cons_val_two, pow_two] using hl2
  · simp only [double, Mmask8.testBit_or, Mmask8.testBit_and,
      hz3.testBit_is_zero_mask, activeMask_testBit s.count hhi,
      Step.double, Matrix.cons_val_two, Matrix.head_cons, Matrix.tail_cons, pow_two]

theorem add_holds {s : State} {l : Fin 8} {t : Step.Point}
    {q : Fp2Field × Fp2Field} {xp yp : Fp} (h : s.Holds l t q xp yp)
    (hhi : s.count.val ≤ 8) :
    (add s).2.Holds l (Step.add t q).point q xp yp ∧
      (add s).1.Holds l (Step.add t q).line xp yp ∧
      (add s).2.degenerate.toNat.testBit l =
        (s.degenerate.toNat.testBit l ||
          (decide ((Step.add t q).point 2 = 0) && decide (l.val < s.count.val))) := by
  have hzz := h.t.z.square
  have hu2 := h.qx.mul hzz
  have hs2 := (h.qy.mul h.t.z).mul hzz
  have hh := hu2.sub h.t.x
  have hhh := hh.square
  have hi2 := hhh.add hhh
  have hi := hi2.add hi2
  have hj := hh.mul hi
  have hr0 := hs2.sub h.t.y
  have hr := hr0.add hr0
  have hv := h.t.x.mul hi
  have hx3 := ((hr.square.sub hj).sub hv).sub hv
  have hyj := h.t.y.mul hj
  have hy3 := (((hv.sub hx3).mul hr).sub hyj).sub hyj
  have hz3 := ((h.t.z.add hh).square.sub hzz).sub hhh
  have hl0 := (hr.mul h.qx).sub (h.qy.mul hz3)
  have hl0 := hl0.add hl0
  have hl1 := scalar_mul_holds hr h.px
  have hl2 := scalar_mul_holds hz3 h.py
  refine ⟨⟨⟨?_, ?_, ?_⟩, ?_, ?_, ?_, ?_⟩, ⟨?_, ?_, ?_⟩, ?_⟩
  · simpa only [add, Step.add, Matrix.cons_val_zero, pow_two] using hx3
  · simpa only [add, Step.add, Matrix.cons_val_one, pow_two] using hy3
  · simpa only [add, Step.add, Matrix.cons_val_two, pow_two] using hz3
  · exact h.qx
  · exact h.qy
  · exact h.px
  · exact h.py
  · simpa only [add, atP, Step.add, Matrix.cons_val_zero, pow_two] using hl0
  · simpa only [add, atP, Step.add, Matrix.cons_val_one, pow_two] using hl1
  · simpa only [add, atP, Step.add, Matrix.cons_val_two, pow_two] using hl2
  · simp only [add, Mmask8.testBit_or, Mmask8.testBit_and,
      hz3.testBit_is_zero_mask, activeMask_testBit s.count hhi,
      Step.add, Matrix.cons_val_two, Matrix.head_cons, Matrix.tail_cons, pow_two]

theorem double_clear {s : State} {l : Fin 8} {t : Step.Point}
    {q : Fp2Field × Fp2Field} {xp yp : Fp} (h : s.Holds l t q xp yp)
    (hhi : s.count.val ≤ 8) (hl : l.val < s.count.val)
    (clear : (double s).2.degenerate = 0) : (Step.double t).point 2 ≠ 0 := by
  have flag := (double_holds h hhi).2.2
  intro hz
  simp [clear, hl, hz] at flag

theorem add_clear {s : State} {l : Fin 8} {t : Step.Point}
    {q : Fp2Field × Fp2Field} {xp yp : Fp} (h : s.Holds l t q xp yp)
    (hhi : s.count.val ≤ 8) (hl : l.val < s.count.val)
    (clear : (add s).2.degenerate = 0) : (Step.add t q).point 2 ≠ 0 := by
  have flag := (add_holds h hhi).2.2
  intro hz
  simp [clear, hl, hz] at flag

end LeanBlsSimd.PairingProduct.Lanes
