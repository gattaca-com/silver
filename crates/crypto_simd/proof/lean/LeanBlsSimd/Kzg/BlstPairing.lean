import LeanBlsSimd.Kzg.PairingRepresentation
import LeanBlsSimd.Kzg.CurveWorkState
import LeanBlsSimd.Kzg.SetupLiterals
import LeanBlsSimd.Spec.G2Group

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.BlstPairing

/-- The boundary includes projective-to-affine conversion and infinity filtering.
G1 coordinates are reduced Montgomery values; G2 inputs use the canonical affine encoder. -/
def BlstMatchesSpec [KzgExternals] : Prop :=
  ∀ (p1 p2 : blst.blst_p1) (q1 q2 : G2),
    JacobianReduced p1 → JacobianReduced p2 →
    G1Valid (g1ReadJacobian p1) → G1Valid (g1ReadJacobian p2) →
    G2.Valid q1 → q1.inSubgroup = true → G2.Valid q2 → q2.inSubgroup = true →
    KzgExternals.pairingCheck p1 (g2Affine q1) p2 (g2Affine q2) =
      Bls.pairingCheck #[(g1ReadJacobian p1, q1), (g1ReadJacobian p2, q2)]

class Correct [KzgExternals] : Prop where
  matchesSpec : BlstMatchesSpec

/-- Only a stored scalar workspace calls the external pairing operation. -/
def FallbackCorrect [KzgExternals] (work : verify.CurveWork) : Prop :=
  CurveWork.isLanes work = false → BlstMatchesSpec

theorem fallbackCorrect_lanes [KzgExternals] {work : verify.CurveWork}
    (h : CurveWork.isLanes work = true) : FallbackCorrect work := by
  simp [FallbackCorrect, h]

set_option maxRecDepth 16000
set_option maxHeartbeats 2000000

private theorem g2_zero_valid : G2.Valid SetupPoints.g2Point0 :=
  G2.valid_mk_one (by
    rw [WeierstrassCurve.Affine.nonsingular_iff, WeierstrassCurve.Affine.equation_iff]
    decide +kernel)

private theorem g2_cell_valid : G2.Valid SetupPoints.g2Point64 :=
  G2.valid_mk_one (by
    rw [WeierstrassCurve.Affine.nonsingular_iff, WeierstrassCurve.Affine.equation_iff]
    decide +kernel)

private theorem g2_neg_subgroup : (G2.neg SetupPoints.g2Point0).inSubgroup = true := by
  apply (G2.inSubgroup_iff (G2.valid_neg g2_zero_valid)).mpr
  rw [G2.toPoint_neg g2_zero_valid, neg_nsmul,
    (G2.inSubgroup_iff g2_zero_valid).mp SetupPoints.g2_0_subgroup, neg_zero]

theorem pairing_check_refines [KzgExternals] (h : BlstMatchesSpec)
    (p1 p2 : blst.blst_p1) (p q : G1) (hp : G1Rep p1 p) (hq : G1Rep p2 q)
    (hvp : G1Valid p) (hvq : G1Valid q) :
    blst_pairing.pairing_check p1 setup.G2_S_POW_CELL p2 setup.G2_NEG_GENERATOR =
      ok (Bls.pairingCheck #[(p, SetupPoints.g2Point64), (q, G2.neg SetupPoints.g2Point0)]) := by
  rw [SetupLiterals.extracted_g2_s_pow_cell, SetupLiterals.extracted_g2_neg_generator,
    blst_pairing.pairing_check, h p1 p2 _ _ hp.1 hq.1
      (g1Valid_of_rep hp hvp) (g1Valid_of_rep hq hvq)
      g2_cell_valid SetupPoints.g2_64_subgroup (G2.valid_neg g2_zero_valid) g2_neg_subgroup]
  exact congrArg ok (pairingCheck_two_congr _ _ hp.2.1 hp.2.2 hq.2.1 hq.2.2)

end LeanBlsSimd.Kzg.BlstPairing
