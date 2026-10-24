import LeanBlsSimd.Spec.Cyclotomic.Field

namespace LeanBlsSimd.Controls.Cyclotomic

open LeanBlsSimd.Fp6Field (xi)
open LeanBlsSimd.Cyclotomic LeanBlsSimd.Cyclotomic.Schedule LeanBlsSimd.Cyclotomic.Bls

def minusOne : Coeffs K := ⟨-1,0,0,0,0,0⟩

theorem minusOne_decode : decode xi minusOne = (-1 : T) := by
  change assemble u (-1) 0 0 = -1
  simp [assemble]

theorem minusOne_unit : IsUnit (decode xi minusOne) := by
  rw [minusOne_decode]
  exact isUnit_neg_one

theorem minusOne_unitary : decode xi minusOne ^ (p^6+1) = 1 := by
  rw [minusOne_decode]
  exact (show Even (p^6+1) by decide +kernel).neg_one_pow

theorem minusOne_not_cyclotomic : decode xi minusOne ^ (p^4-p^2+1) ≠ 1 := by
  rw [minusOne_decode, (show Odd (p^4-p^2+1) by decide +kernel).neg_one_pow]
  intro h
  have h' : embed u (-1 : S) = embed u (1 : S) := by simpa using h
  have h'' := congrArg QuadraticAlgebra.re (embed_injective h')
  have h''' := congrArg QuadraticAlgebra.re h''
  norm_num at h'''
  exact (by decide +kernel : (-1 : ZMod p) ≠ 1) h'''

theorem minusOne_raw_wrong : decode xi (raw xi minusOne) ≠ decode xi minusOne ^ 2 := by
  rw [raw_decode,minusOne_decode]
  intro h
  have hcoords : assemble u (5 : S) 0 0 = assemble u (1 : S) 0 0 := by
    have ha : ca xi minusOne = (-1 : S) := rfl
    have hb : cb xi minusOne = (0 : S) := rfl
    have hc : cc xi minusOne = (0 : S) := rfl
    have hone : assemble u 1 0 0 = (1 : T) := by simp [assemble]
    rw [hone]
    simpa only [ha,hb,hc,neg_one_sq,star_neg,star_one,star_zero,zero_pow (by decide : 2 ≠ 0),
      mul_zero,add_zero,sub_zero,sub_neg_eq_add,mul_one,show (3:S)+2=5 by norm_num] using h
  have h5 := (assemble_injective u 5 0 0 1 0 0 hcoords).1
  have hK := congrArg QuadraticAlgebra.re h5
  have hFp := congrArg QuadraticAlgebra.re hK
  exact (by decide +kernel : (5 : ZMod p) ≠ 1) hFp

theorem field_formula_wrong_without_phi :
    fieldDecode (raw xi minusOne) ≠ fieldDecode minusOne ^ 2 := by
  intro h
  apply minusOne_raw_wrong
  simpa only [map_pow, toCubic_fieldDecode] using congrArg toCubic h

#print axioms field_formula_wrong_without_phi
end LeanBlsSimd.Controls.Cyclotomic
