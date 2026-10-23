import LeanBlsSimd.Msm8.SplitScalars
import LeanBlsSimd.Msm8.GlvGroup
import LeanBlsSimd.Kzg.G1Arithmetic

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.Msm8

open EthLib.Cryptography Bls

theorem glv_wordsValue_eq_limbs (xs : List U64) :
    GlvRefines.wordsValue xs = (Kzg.limbs xs : ℤ) := by
  induction xs with
  | nil => rfl
  | cons a xs ih =>
    simp only [GlvRefines.wordsValue, Kzg.limbs, List.foldr_cons]
    rw [ih]
    push_cast
    rfl

theorem glv_value_eq_limbs (s : ScalarWords) :
    GlvRefines.value s = (Kzg.limbs s.val : ℤ) := glv_wordsValue_eq_limbs s.val

def inputContribution (input : blst.blst_p1_affine × ScalarWords) : G1Spec.E.Point :=
  Kzg.limbs input.2.val • G1.toPoint (Kzg.g1ReadAffine input.1)

def finiteInput (input : blst.blst_p1_affine × ScalarWords) : Bool :=
  !(Kzg.g1ReadAffine input.1).isInfinity

theorem filter_infinity_preserves_sum (inputs : List (blst.blst_p1_affine × ScalarWords)) :
    ((inputs.filter finiteInput).map inputContribution).sum =
      (inputs.map inputContribution).sum := by
  induction inputs with
  | nil => rfl
  | cons input inputs ih =>
    by_cases hz : (Kzg.g1ReadAffine input.1).isInfinity = true
    · have hc : inputContribution input = 0 := by
        rw [inputContribution, Kzg.g1_toPoint_of_infinity hz, nsmul_zero]
      simp [finiteInput, hz, hc, ih]
    · simp [finiteInput, hz, ih]

theorem signed_magnitude_smul (magnitude : ℕ) (negative : Bool) (P : G1Spec.E.Point) :
    magnitude • (if negative then -P else P) =
      (if negative then -(magnitude : ℤ) else (magnitude : ℤ)) • P := by
  cases negative <;> simp

theorem signed_half_smul (half : msm8.glv.Half) (P : G1Spec.E.Point) :
    Kzg.limbs half.magnitude.val • (if half.negative then -P else P) =
      GlvRefines.signedValue half • P := by
  rw [signed_magnitude_smul, GlvRefines.signedValue, glv_value_eq_limbs]

theorem split_scalar_contribution (point : blst.blst_p1_affine) (scalar : ScalarWords)
    (first second : msm8.glv.Half) (hp : Kzg.G1AffineValid point)
    (hfirst : GlvRefines.signedValue first = Glv.first (GlvRefines.value scalar))
    (hsecond : GlvRefines.signedValue second = Glv.second (GlvRefines.value scalar)) :
    Kzg.limbs first.magnitude.val •
        (if first.negative then -G1.toPoint (Kzg.g1ReadAffine point)
          else G1.toPoint (Kzg.g1ReadAffine point)) +
      Kzg.limbs second.magnitude.val •
        (if second.negative then -G1Spec.sigma (G1.toPoint (Kzg.g1ReadAffine point))
          else G1Spec.sigma (G1.toPoint (Kzg.g1ReadAffine point))) =
      inputContribution (point, scalar) := by
  rw [signed_half_smul, signed_half_smul, hfirst, hsecond,
    G1Spec.glv_decomposition_smul _ (Kzg.g1Valid_subgroup hp.2)]
  rw [glv_value_eq_limbs]
  simp [inputContribution]

theorem chunk_sums (chunks : List (List (blst.blst_p1_affine × ScalarWords))) :
    (chunks.map (fun chunk => (chunk.map inputContribution).sum)).sum =
      (chunks.flatten.map inputContribution).sum := by
  simp only [List.map_flatten, List.sum_flatten, List.map_map, Function.comp_def]

end LeanBlsSimd.Msm8
