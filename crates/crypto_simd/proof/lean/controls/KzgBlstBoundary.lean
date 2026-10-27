import LeanBlsSimd.Kzg.Statements

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.kzg
open LeanBlsSimd LeanBlsSimd.Kzg

namespace LeanBlsSimd.Controls.KzgBlstBoundary

private abbrev rejectsAll : KzgExternals where
  uncompressG1 := fun _ => none
  pairingCheck := fun _ _ _ _ => false

theorem rejectsAll_violates_decoder : ¬ @UncompressG1.BlstMatchesSpec rejectsAll := by
  intro h
  have hz := h (toArray toU8 G1Spec.infinity)
  change none = UncompressG1.specVerdict (toArray toU8 G1Spec.infinity) at hz
  simp [UncompressG1.specVerdict, ofArray_toArray, G1Spec.infinity_verdict] at hz

theorem rejectsAll_violates_pairing : ¬ @BlstPairing.BlstMatchesSpec rejectsAll := by
  intro h
  have hv : G1Valid (g1ReadJacobian (g1Jacobian G1.zero)) := by
    rw [g1ReadJacobian_g1Jacobian]
    exact g1Valid_zero
  have hz := h (g1Jacobian G1.zero) (g1Jacobian G1.zero)
    (g1Jacobian_reduced _) (g1Jacobian_reduced _) hv hv
  rw [g1ReadJacobian_g1Jacobian, Pairing.pairingCheck_two] at hz
  change false = (finalExponentiation (Fp12.one * Fp12.one)).isOne at hz
  rw [show Fp12.one * Fp12.one = Fp12.one by rfl, finalExponentiation_one] at hz
  cases hz

private abbrev specExternals : KzgExternals where
  uncompressG1 := UncompressG1.specVerdict
  pairingCheck := fun p1 q1 p2 q2 =>
    Bls.pairingCheck #[(g1ReadJacobian p1, g2ReadAffine q1),
      (g1ReadJacobian p2, g2ReadAffine q2)]

/-- This witness shows the two laws are consistent together; it does not show that blst satisfies them. -/
theorem laws_satisfiable : ∃ external : KzgExternals,
    @UncompressG1.BlstMatchesSpec external ∧ @BlstPairing.BlstMatchesSpec external := by
  refine ⟨specExternals, fun _ => rfl, ?_⟩
  intro p1 p2 _ _ _ _
  change Bls.pairingCheck #[(g1ReadJacobian p1, g2ReadAffine (g2Affine SetupPoints.g2Point64)),
    (g1ReadJacobian p2, g2ReadAffine (g2Affine (G2.neg SetupPoints.g2Point0)))] = _
  rw [setup_g2_cell_roundtrip, setup_g2_neg_zero_roundtrip]

/-- An arbitrary external dictionary still permits IFMA construction and repeated calls. -/
example [cpu : RuntimeFeatures] [KzgExternals] (h : cpu.simdAvailable = true) :
    ∃ initial, verify.CellBatchVerifier.new = ok initial ∧ StateInvariant initial ∧
      CurveWork.isLanes initial.curve_work = true ∧
      ∀ i : Input, i.Representable → ∃ verdict next,
        i.generated initial = ok (verdict, next) ∧ StateInvariant next ∧
        CurveWork.isLanes next.curve_work = true ∧
        Model.rejectErrors i.embeddedSpec = verdict := by
  obtain ⟨v, hn, hv, hr, hstep⟩ := verify_eq_spec_ifma h
  exact ⟨v, hn, hv, hr, hstep v hv hr⟩

/-- Scalar work remains admissible independently of the interpolation route and CPU features. -/
example [RuntimeFeatures] (v : verify.CellBatchVerifier) (h : StateInvariant v) :
    ∃ next, StateInvariant next ∧ next.kernel = v.kernel ∧
      CurveWork.isLanes next.curve_work = false := stateInvariant_allows_scalar v h

end LeanBlsSimd.Controls.KzgBlstBoundary
