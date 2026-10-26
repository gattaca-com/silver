import LeanBlsSimd.Pairing.LaneFinal
import LeanBlsSimd.Spec.Cyclotomic.Field
import LeanBlsSimd.LaneTower.Square

open Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd.bls

namespace LeanBlsSimd.PairingProduct

def FieldRep (raw : fp12.Fp12) (value : Fp12Field) : Prop :=
  LaneTower.Rep raw (Fp12.toField.symm value)

namespace FieldRep

theorem one : ∃ out, fp12.Fp12.one = ok out ∧ FieldRep out 1 := by
  obtain ⟨out, hout, hrep⟩ := LaneTower.one_refines
  refine ⟨out, hout, ?_⟩
  simpa only [FieldRep, ← Fp12.toField_one, RingEquiv.symm_apply_apply] using hrep

theorem mul {x y : fp12.Fp12} {a b : Fp12Field}
    (hx : FieldRep x a) (hy : FieldRep y b) :
    ∃ out, fp12.Fp12.mul x y = ok out ∧ FieldRep out (a * b) := by
  obtain ⟨out, hout, hrep⟩ := LaneTower.mul_refines hx hy
  refine ⟨out, hout, ?_⟩
  simpa only [FieldRep, map_mul] using hrep

theorem square {x : fp12.Fp12} {a : Fp12Field} (hx : FieldRep x a) :
    ∃ out, fp12.Fp12.square x = ok out ∧ FieldRep out (a * a) := by
  obtain ⟨out, hout, hrep⟩ := LaneTower.square_refines hx
  refine ⟨out, hout, ?_⟩
  have he : (Fp12.toField.symm a).square = Fp12.toField.symm (a * a) := by
    apply Fp12.toField.injective
    simp only [Fp12.toField_square, RingEquiv.apply_symm_apply, pow_two]
  unfold FieldRep
  rwa [he] at hrep

theorem conjugate {x : fp12.Fp12} {a : Fp12Field} (hx : FieldRep x a) :
    ∃ out, fp12.Fp12.conjugate x = ok out ∧ FieldRep out (a ^ (Fp.modulus ^ 6)) := by
  obtain ⟨out, hout, hrep⟩ := LaneTower.conjugate_refines hx
  refine ⟨out, hout, ?_⟩
  have he : (Fp12.toField.symm a).conjugate =
      Fp12.toField.symm (a ^ (Fp.modulus ^ 6)) := by
    apply Fp12.toField.injective
    simp only [Fp12.toField_conjugate, RingEquiv.apply_symm_apply,
      Cyclotomic.field_star]
  unfold FieldRep
  rwa [he] at hrep

theorem final_verdict {x : fp12.Fp12} {a : Fp12Field} (hx : FieldRep x a) :
    (do let out ← fp12.Fp12.final_exponentiation x
        fp12.Fp12.is_one out) = ok (decide (a ^ finalExpExponent = 1)) := by
  rw [Pairing.FinalExponent.Lanes.final_verdict hx]
  apply congrArg ok
  apply Bool.eq_iff_iff.mpr
  simp only [Fp12.isOne_iff, toField_finalExponentiation,
    RingEquiv.apply_symm_apply, decide_eq_true_eq]

end FieldRep

end LeanBlsSimd.PairingProduct
