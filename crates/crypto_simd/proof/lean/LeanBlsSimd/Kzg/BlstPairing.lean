import LeanBlsSimd.Kzg.PairingRepresentation
import LeanBlsSimd.Kzg.CurveWorkState
import LeanBlsSimd.Kzg.SetupLiterals

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.BlstPairing

/-- The boundary includes Jacobian-to-affine conversion and infinity filtering.
G1 coordinates are reduced Montgomery values; G2 inputs are the two KZG setup points. -/
def BlstMatchesSpec [KzgExternals] : Prop :=
  ∀ (p1 p2 : blst.blst_p1),
    JacobianReduced p1 → JacobianReduced p2 →
    G1Valid (g1ReadJacobian p1) → G1Valid (g1ReadJacobian p2) →
    KzgExternals.pairingCheck p1 (g2Affine SetupPoints.g2Point64)
      p2 (g2Affine (G2.neg SetupPoints.g2Point0)) =
      Bls.pairingCheck #[(g1ReadJacobian p1, SetupPoints.g2Point64),
        (g1ReadJacobian p2, G2.neg SetupPoints.g2Point0)]

class Correct [KzgExternals] : Prop where
  matchesSpec : BlstMatchesSpec

/-- Only a stored scalar workspace calls the external pairing operation. -/
def CorrectFor [KzgExternals] (work : verify.CurveWork) : Prop :=
  CurveWork.isLanes work = false → BlstMatchesSpec

theorem correctFor_lanes [KzgExternals] {work : verify.CurveWork}
    (h : CurveWork.isLanes work = true) : CorrectFor work := by
  simp [CorrectFor, h]

theorem pairing_check_refines [KzgExternals] (h : BlstMatchesSpec)
    (p1 p2 : blst.blst_p1) (p q : G1) (hp : G1Rep p1 p) (hq : G1Rep p2 q)
    (hvp : G1Valid p) (hvq : G1Valid q) :
    blst_pairing.pairing_check p1 setup.G2_S_POW_CELL p2 setup.G2_NEG_GENERATOR =
      ok (Bls.pairingCheck #[(p, SetupPoints.g2Point64), (q, G2.neg SetupPoints.g2Point0)]) := by
  rw [SetupLiterals.extracted_g2_s_pow_cell, SetupLiterals.extracted_g2_neg_generator,
    blst_pairing.pairing_check, h p1 p2 hp.1 hq.1
      (g1Valid_of_rep hp hvp) (g1Valid_of_rep hq hvq)]
  exact congrArg ok (pairingCheck_two_congr _ _ hp.2.1 hp.2.2 hq.2.1 hq.2.2)

end LeanBlsSimd.Kzg.BlstPairing
