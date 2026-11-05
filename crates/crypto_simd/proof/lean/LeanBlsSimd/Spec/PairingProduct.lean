import LeanBlsSimd.Spec.FinalExponentiation
import LeanBlsSimd.Spec.PairingEquations
import Mathlib.Algebra.BigOperators.Group.List.Basic

/-! The actual pairing-check loop equals a product of individually reduced single-pair values. -/

namespace LeanBlsSimd

open EthLib.Cryptography.Bls

noncomputable section

/-- An infinity pair contributes the multiplicative identity before final exponentiation. -/
def pairingFactor (pair : G1 × G2) : Fp12 :=
  if pair.1.isInfinity || pair.2.isInfinity then Fp12.one
  else (millerLoop blsX (Embedded.ofG2 pair.2) (Embedded.ofG1 pair.1)).conjugate

/-- The executable single-pair value; this definition does not assert pairing laws. -/
def eSpec (p : G1) (q : G2) : Fp12 := finalExponentiation (pairingFactor (p, q))

theorem toField_pairingStep (acc : Fp12) (pair : G1 × G2) :
    Fp12.toField (SpecPairing.pairingFoldStep acc pair) = Fp12.toField acc * Fp12.toField (pairingFactor pair) := by
  unfold SpecPairing.pairingFoldStep pairingFactor
  split <;> simp [map_mul]

theorem toField_list_pairingFold (pairs : List (G1 × G2)) (acc : Fp12) :
    Fp12.toField (pairs.foldl SpecPairing.pairingFoldStep acc) =
      Fp12.toField acc * (pairs.map (fun pair => Fp12.toField (pairingFactor pair))).prod := by
  induction pairs generalizing acc with
  | nil => simp
  | cons pair pairs ih =>
    simp only [List.foldl_cons, List.map_cons, List.prod_cons]
    rw [ih, toField_pairingStep, mul_assoc]

theorem toField_pairingFold (pairs : Array (G1 × G2)) :
    Fp12.toField (SpecPairing.pairingFold pairs) =
      (pairs.toList.map (fun pair => Fp12.toField (pairingFactor pair))).prod := by
  rw [SpecPairing.pairingFold, ← Array.foldl_toList, toField_list_pairingFold, Fp12.toField_one, one_mul]

theorem toField_finalExponentiation_pairingFold (pairs : Array (G1 × G2)) :
    Fp12.toField (finalExponentiation (SpecPairing.pairingFold pairs)) =
      (pairs.toList.map (fun pair => Fp12.toField (eSpec pair.1 pair.2))).prod := by
  rw [toField_finalExponentiation, toField_pairingFold]
  simpa only [List.map_map, Function.comp_def, powMonoidHom_apply, eSpec,
    toField_finalExponentiation] using
      (List.prod_hom (pairs.toList.map (fun pair => Fp12.toField (pairingFactor pair)))
        (powMonoidHom finalExpExponent)).symm

/-- This is a fold/field theorem for arbitrary inputs, with no bilinearity or validity assumption. -/
theorem pairingCheck_iff (pairs : Array (G1 × G2)) :
    pairingCheck pairs = true ↔
      (pairs.toList.map (fun pair => Fp12.toField (eSpec pair.1 pair.2))).prod = 1 := by
  rw [SpecPairing.pairingCheck_eq, Fp12.isOne_iff, toField_finalExponentiation_pairingFold]

theorem pairingCheck_empty : pairingCheck #[] = true := by
  rw [pairingCheck_iff]
  simp

end

end LeanBlsSimd
