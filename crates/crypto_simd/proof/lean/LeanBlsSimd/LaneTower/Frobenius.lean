import LeanBlsSimd.LaneTower.Basic
import LeanBlsSimd.LaneTower.Layout

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.bls
open EthLib.Cryptography Bls

namespace LeanBlsSimd.LaneTower

set_option exponentiation.threshold 1024

abbrev Gamma := Array (Array (Array U64 8#usize) 2#usize) 6#usize

def coefficientStages (g : Gamma) (c : Fin 2) : Fin 7 → Array (Array U64 8#usize) 8#usize :=
  let z := Array.repeat 8#usize (Array.repeat 8#usize 0#u64)
  let a := z.set 0#usize g.val[0].val[c.val]
  let b := a.set 1#usize g.val[2].val[c.val]
  let d := b.set 2#usize g.val[4].val[c.val]
  let e := d.set 3#usize g.val[1].val[c.val]
  let f := e.set 4#usize g.val[3].val[c.val]
  let h := f.set 5#usize g.val[5].val[c.val]
  ![z, a, b, d, e, f, h]

def coefficientCounter (i : Fin 7) : Usize :=
  ![0#usize, 1#usize, 2#usize, 3#usize, 4#usize, 5#usize, 6#usize] i

theorem coefficient_body_step (g : Gamma) (i : Fin 6) :
    fp12.Fp12.times_coefficients_loop.body g
      (coefficientStages g 0 i.castSucc) (coefficientStages g 1 i.castSucc)
      (coefficientCounter i.castSucc) =
    ok (cont (coefficientStages g 0 i.succ, coefficientStages g 1 i.succ,
      coefficientCounter i.succ)) := by
  unfold fp12.Fp12.times_coefficients_loop.body fp12.POWER_OF_LANE
  fin_cases i <;>
    simp (disch := decide) [coefficientStages, coefficientCounter, index_usize_eq, update_eq, UScalar.lt_equiv]
  all_goals
    rw [add_ok _ _ (by scalar_tac)]
    rfl

theorem coefficient_body_end (g : Gamma) :
    fp12.Fp12.times_coefficients_loop.body g
      (coefficientStages g 0 6) (coefficientStages g 1 6) 6#usize =
    ok (done (coefficientStages g 0 6, coefficientStages g 1 6)) := by
  unfold fp12.Fp12.times_coefficients_loop.body
  rfl

theorem coefficient_loop (g : Gamma) :
    fp12.Fp12.times_coefficients_loop g
      (Array.repeat 8#usize (Array.repeat 8#usize 0#u64))
      (Array.repeat 8#usize (Array.repeat 8#usize 0#u64)) 0#usize =
      ok (coefficientStages g 0 6, coefficientStages g 1 6) := by
  have h0 := coefficient_body_step g 0
  change fp12.Fp12.times_coefficients_loop.body g (coefficientStages g 0 0)
    (coefficientStages g 1 0) (coefficientCounter 0) =
    ok (cont (coefficientStages g 0 1, coefficientStages g 1 1, coefficientCounter 1)) at h0
  have h1 := coefficient_body_step g 1
  change fp12.Fp12.times_coefficients_loop.body g (coefficientStages g 0 1)
    (coefficientStages g 1 1) (coefficientCounter 1) =
    ok (cont (coefficientStages g 0 2, coefficientStages g 1 2, coefficientCounter 2)) at h1
  have h2 := coefficient_body_step g 2
  change fp12.Fp12.times_coefficients_loop.body g (coefficientStages g 0 2)
    (coefficientStages g 1 2) (coefficientCounter 2) =
    ok (cont (coefficientStages g 0 3, coefficientStages g 1 3, coefficientCounter 3)) at h2
  have h3 := coefficient_body_step g 3
  change fp12.Fp12.times_coefficients_loop.body g (coefficientStages g 0 3)
    (coefficientStages g 1 3) (coefficientCounter 3) =
    ok (cont (coefficientStages g 0 4, coefficientStages g 1 4, coefficientCounter 4)) at h3
  have h4 := coefficient_body_step g 4
  change fp12.Fp12.times_coefficients_loop.body g (coefficientStages g 0 4)
    (coefficientStages g 1 4) (coefficientCounter 4) =
    ok (cont (coefficientStages g 0 5, coefficientStages g 1 5, coefficientCounter 5)) at h4
  have h5 := coefficient_body_step g 5
  change fp12.Fp12.times_coefficients_loop.body g (coefficientStages g 0 5)
    (coefficientStages g 1 5) (coefficientCounter 5) =
    ok (cont (coefficientStages g 0 6, coefficientStages g 1 6, coefficientCounter 6)) at h5
  have h6 := coefficient_body_end g
  change fp12.Fp12.times_coefficients_loop.body g (coefficientStages g 0 6)
    (coefficientStages g 1 6) (coefficientCounter 6) =
    ok (done (coefficientStages g 0 6, coefficientStages g 1 6)) at h6
  unfold fp12.Fp12.times_coefficients_loop
  change loop _ (coefficientStages g 0 0, coefficientStages g 1 0, coefficientCounter 0) = _
  rw [loop.eq_1]
  simp only [h0]
  rw [loop.eq_1]
  simp only [h1]
  rw [loop.eq_1]
  simp only [h2]
  rw [loop.eq_1]
  simp only [h3]
  rw [loop.eq_1]
  simp only [h4]
  rw [loop.eq_1]
  simp only [h5]
  rw [loop.eq_1]
  simp only [h6]


def tableLanes (c : Fin 2) : V Limbs :=
  ![FrobeniusConstants.laneLimbs 0 c, FrobeniusConstants.laneLimbs 2 c,
    FrobeniusConstants.laneLimbs 4 c, FrobeniusConstants.laneLimbs 1 c,
    FrobeniusConstants.laneLimbs 3 c, FrobeniusConstants.laneLimbs 5 c,
    Vector.replicate 8 0, Vector.replicate 8 0]

def tableValues : P F := (fun l => decode (tableLanes 0 l), fun l => decode (tableLanes 1 l))

def loadedCoefficient (c : Fin 2) : fp8.Fp8 :=
  toFp8 (Fp8.load (ofArray (ofArray ofU64) (coefficientStages constants.FROBENIUS_MONT c 6)))

theorem loadedCoefficient_lane (c : Fin 2) (l : Fin 8) :
    (ofFp8 (loadedCoefficient c)).lane l = tableLanes c l := by
  simp only [loadedCoefficient, ofFp8_toFp8, Fp8.lane_load]
  unfold tableLanes FrobeniusConstants.laneLimbs FrobeniusConstants.laneRow constants.FROBENIUS_MONT
  fin_cases c <;> fin_cases l <;> rfl

theorem table_bounds (c : Fin 2) (l : Fin 8) :
    SignedLimbs.Normalized (tableLanes c l) ∧ val (tableLanes c l) ≤ Bls.Fp.modulus := by
  fin_cases l
  · exact ⟨(FrobeniusConstants.lane_entry_bounds 0 c).1, (FrobeniusConstants.lane_entry_bounds 0 c).2.le⟩
  · exact ⟨(FrobeniusConstants.lane_entry_bounds 2 c).1, (FrobeniusConstants.lane_entry_bounds 2 c).2.le⟩
  · exact ⟨(FrobeniusConstants.lane_entry_bounds 4 c).1, (FrobeniusConstants.lane_entry_bounds 4 c).2.le⟩
  · exact ⟨(FrobeniusConstants.lane_entry_bounds 1 c).1, (FrobeniusConstants.lane_entry_bounds 1 c).2.le⟩
  · exact ⟨(FrobeniusConstants.lane_entry_bounds 3 c).1, (FrobeniusConstants.lane_entry_bounds 3 c).2.le⟩
  · exact ⟨(FrobeniusConstants.lane_entry_bounds 5 c).1, (FrobeniusConstants.lane_entry_bounds 5 c).2.le⟩
  · constructor
    · change SignedLimbs.Normalized (Vector.replicate 8 (0 : _root_.UInt64))
      intro j
      decide +revert +kernel
    · change val (Vector.replicate 8 (0 : _root_.UInt64)) ≤ _
      exact Nat.zero_le _
  · constructor
    · change SignedLimbs.Normalized (Vector.replicate 8 (0 : _root_.UInt64))
      intro j
      decide +revert +kernel
    · change val (Vector.replicate 8 (0 : _root_.UInt64)) ≤ _
      exact Nat.zero_le _

theorem loadedCoefficient_normal (c : Fin 2) :
    Normal (fun _ => 1) (loadedCoefficient c) (fun l => decode (tableLanes c l)) := by
  intro l
  constructor <;> rw [loadedCoefficient_lane]
  · exact (table_bounds c l).1
  · simpa only [one_mul] using (table_bounds c l).2

theorem times_coefficients_raw {x : fp2x8.Fp2x8} {a : P F}
    (hx : Normal2 (fun _ => 256, fun _ => 256) x a) :
    ∃ out, fp12.Fp12.times_coefficients x constants.FROBENIUS_MONT = ok out ∧
      Normal2 (fun _ => 4, fun _ => 6) out (mul2 a tableValues) := by
  obtain ⟨out, hout, rout⟩ := raw2_products hx
    (show Normal2 (fun _ => 1, fun _ => 1) ⟨loadedCoefficient 0, loadedCoefficient 1⟩ tableValues
      from ⟨loadedCoefficient_normal 0, loadedCoefficient_normal 1⟩)
    (by intro l; dsimp; decide) (by intro l; dsimp; decide)
  refine ⟨out, ?_, rout⟩
  simp only [fp12.Fp12.times_coefficients, coefficient_loop, bind_tc_ok, Fp8.load_refines]
  change (do let fx ← fp12.fp2_products x ⟨loadedCoefficient 0, loadedCoefficient 1⟩; ok fx) = _
  rw [hout]
  rfl

def conjugateCoefficients (a : P F) : P F := (a.1, fun l => -a.2 l)

theorem conjugate_coefficients_raw {x : fp2x8.Fp2x8} {a : P F}
    (hx : Normal2 (fun _ => 256, fun _ => 256) x a) :
    ∃ out, fp12.Fp12.conjugate_coefficients x = ok out ∧
      Normal2 (fun _ => 256, fun _ => 256) out (conjugateCoefficients a) := by
  obtain ⟨z, hz, rz⟩ := raw_zero
  obtain ⟨p, hp, rp⟩ := raw_offset 256#u64 (by decide)
  obtain ⟨s, hs, rs⟩ := raw_sub rz.raw hx.2.raw rp (by intro l; rfl) (by decide)
  obtain ⟨n, hn, rn⟩ := raw_normalise rs (by intro l; change 256 ≤ 5120; decide) (by decide)
  refine ⟨⟨x.c0, n⟩, ?_, hx.1, ?_⟩
  · simp only [fp12.Fp12.conjugate_coefficients, fp12.BOUND, hz, hp, hs, hn, bind_tc_ok]
  · simpa only [zero_sub] using rn

def frobeniusValues (a : P F) : P F := mul2 (conjugateCoefficients a) tableValues

theorem frobenius_raw {x : fp2x8.Fp2x8} {a : P F}
    (hx : Normal2 (fun _ => 256, fun _ => 256) x a) :
    ∃ out, fp12.Fp12.frobenius x = ok out ∧
      Normal2 (fun _ => 4, fun _ => 6) out (frobeniusValues a) := by
  obtain ⟨c, hc, rc⟩ := conjugate_coefficients_raw hx
  obtain ⟨out, hout, rout⟩ := times_coefficients_raw rc
  refine ⟨out, ?_, rout⟩
  simp only [fp12.Fp12.frobenius, hc, hout, bind_tc_ok]



def asFp2 (a : P F) (l : Fin 8) : Fp2Field := ⟨a.1 l, a.2 l⟩

theorem asFp2_mul2 (a b : P F) (l : Fin 8) :
    asFp2 (mul2 a b) l = asFp2 a l * asFp2 b l := by
  apply QuadraticAlgebra.ext <;>
    simp [asFp2, mul2]
  all_goals ring

theorem asFp2_conjugate (a : P F) (l : Fin 8) :
    asFp2 (conjugateCoefficients a) l = star (asFp2 a l) := by
  apply QuadraticAlgebra.ext <;> simp [asFp2, conjugateCoefficients]

def tablePower : Fin 6 → Fin 6 := ![0, 2, 4, 1, 3, 5]

theorem asFp2_table (l : Fin 6) :
    asFp2 tableValues ⟨l.val, by omega⟩ =
      Fp6Field.xi ^ ((tablePower l).val * ((Bls.Fp.modulus - 1) / 6)) := by
  fin_cases l
  · exact FrobeniusConstants.lane_entry_decodes 0
  · exact FrobeniusConstants.lane_entry_decodes 2
  · exact FrobeniusConstants.lane_entry_decodes 4
  · exact FrobeniusConstants.lane_entry_decodes 1
  · exact FrobeniusConstants.lane_entry_decodes 3
  · exact FrobeniusConstants.lane_entry_decodes 5

private theorem coeffs_ext {x y : Cyclotomic.Schedule.Coeffs Fp2Field}
    (h0 : x.c00 = y.c00) (h1 : x.c01 = y.c01) (h2 : x.c02 = y.c02)
    (h3 : x.c10 = y.c10) (h4 : x.c11 = y.c11) (h5 : x.c12 = y.c12) : x = y := by
  cases x; cases y; cases h0; cases h1; cases h2; cases h3; cases h4; cases h5; rfl

theorem frobenius_coefficients (a : P F) :
    Cyclotomic.specCoeffs (value (frobeniusValues a)) =
      Cyclotomic.frobeniusCoeffs (Cyclotomic.specCoeffs (value a)) := by
  have h (l : Fin 6) : asFp2 (frobeniusValues a) ⟨l.val, by omega⟩ =
      star (asFp2 a ⟨l.val, by omega⟩) *
        Fp6Field.xi ^ ((tablePower l).val * ((Bls.Fp.modulus - 1) / 6)) := by
    rw [frobeniusValues, asFp2_mul2, asFp2_conjugate, asFp2_table]
  apply coeffs_ext
  · simpa only [tablePower, Matrix.cons_val, Fin.val_zero, Fin.val_one, Fin.val_mk,
      zero_mul, one_mul, pow_zero, mul_one] using h 0
  · simpa only [tablePower, Matrix.cons_val, Fin.val_zero, Fin.val_one, Fin.val_mk,
      zero_mul, one_mul, pow_zero, mul_one] using h 1
  · simpa only [tablePower, Matrix.cons_val, Fin.val_zero, Fin.val_one, Fin.val_mk,
      zero_mul, one_mul, pow_zero, mul_one] using h 2
  · simpa only [tablePower, Matrix.cons_val, Fin.val_zero, Fin.val_one, Fin.val_mk,
      zero_mul, one_mul, pow_zero, mul_one] using h 3
  · simpa only [tablePower, Matrix.cons_val, Fin.val_zero, Fin.val_one, Fin.val_mk,
      zero_mul, one_mul, pow_zero, mul_one] using h 4
  · simpa only [tablePower, Matrix.cons_val, Fin.val_zero, Fin.val_one, Fin.val_mk,
      zero_mul, one_mul, pow_zero, mul_one] using h 5

theorem frobenius_value (a : P F) :
    value (frobeniusValues a) = Bls.Fp12.powNat (value a) Bls.Fp.modulus := by
  apply LeanBlsSimd.Fp12.toField.injective
  rw [← Cyclotomic.fieldDecode_spec, frobenius_coefficients,
    Cyclotomic.field_frobenius, Cyclotomic.fieldDecode_spec, LeanBlsSimd.Fp12.toField_powNat]

theorem frobenius_refines {x : fp2x8.Fp2x8} {a : Bls.Fp12} (hx : Rep x a) :
    ∃ out, fp12.Fp12.frobenius x = ok out ∧ Rep out (Bls.Fp12.powNat a Bls.Fp.modulus) := by
  obtain ⟨v, h0, h1, rfl⟩ := hx
  obtain ⟨out, hout, rout⟩ := frobenius_raw ⟨fun l => (h0 l).capped, fun l => (h1 l).capped⟩
  exact ⟨out, hout, frobeniusValues v,
    fun l => (rout.1 l).boundRep (by change 4 < 256; decide),
    fun l => (rout.2 l).boundRep (by change 6 < 256; decide), frobenius_value v⟩

end LeanBlsSimd.LaneTower
