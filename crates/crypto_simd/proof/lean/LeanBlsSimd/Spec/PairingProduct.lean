import LeanBlsSimd.Spec.FinalExponentiation
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

theorem eSpec_def (p : G1) (q : G2) :
    eSpec p q = if p.isInfinity || q.isInfinity then Fp12.one
      else finalExponentiation ((millerLoop blsX (Embedded.ofG2 q) (Embedded.ofG1 p)).conjugate) := by
  unfold eSpec pairingFactor
  split <;> simp

theorem eSpec_of_left_infinity (p : G1) (q : G2) (hp : p.isInfinity = true) :
    eSpec p q = Fp12.one := by simp [eSpec_def, hp]

theorem eSpec_of_right_infinity (p : G1) (q : G2) (hq : q.isInfinity = true) :
    eSpec p q = Fp12.one := by simp [eSpec_def, hq]

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

/-- Group-valued factors require an explicit nonvanishing hypothesis for each contributing value. -/
def pairingTargets (pairs : Array (G1 × G2))
    (h : ∀ pair ∈ pairs.toList, pairingFactor pair ≠ Fp12.zero) :
    List (rootsOfUnity Fr.modulus Fp12Field) :=
  pairs.toList.attach.map fun pair => finalExponentiationTarget (pairingFactor pair.1) (h _ pair.2)

theorem pairingTargets_prod_val (pairs : Array (G1 × G2))
    (h : ∀ pair ∈ pairs.toList, pairingFactor pair ≠ Fp12.zero) :
    (((pairingTargets pairs h).prod : Fp12Fieldˣ) : Fp12Field) =
      (pairs.toList.map (fun pair => Fp12.toField (eSpec pair.1 pair.2))).prod := by
  let val := (Units.coeHom Fp12Field).comp (rootsOfUnity Fr.modulus Fp12Field).subtype
  change val (pairingTargets pairs h).prod = _
  rw [← List.prod_hom]
  simp only [pairingTargets, List.map_map, Function.comp_def]
  change (pairs.toList.attach.map (fun pair => Fp12.toField (eSpec pair.1.1 pair.1.2))).prod = _
  rw [List.attach_map_val (f := fun pair : G1 × G2 => Fp12.toField (eSpec pair.1 pair.2))]

theorem pairingCheck_iff_target_product (pairs : Array (G1 × G2))
    (h : ∀ pair ∈ pairs.toList, pairingFactor pair ≠ Fp12.zero) :
    pairingCheck pairs = true ↔ (pairingTargets pairs h).prod = 1 := by
  rw [pairingCheck_iff, ← pairingTargets_prod_val pairs h]
  constructor
  · intro hp
    exact Subtype.ext (Units.ext hp)
  · intro hp
    rw [hp]
    rfl

theorem pairingCheck_empty : pairingCheck #[] = true := by
  rw [pairingCheck_iff]
  simp

theorem pairingCheck_singleton (p : G1) (q : G2) :
    pairingCheck #[(p, q)] = true ↔ (eSpec p q).isOne = true := by
  rw [pairingCheck_iff, Fp12.isOne_iff]
  simp

end

end LeanBlsSimd
