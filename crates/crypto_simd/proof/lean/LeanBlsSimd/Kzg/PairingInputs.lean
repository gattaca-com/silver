import LeanBlsSimd.Kzg.LanePairingInputs
import LeanBlsSimd.Kzg.PortablePairingInputs
import LeanBlsSimd.Kzg.PairingRepresentation

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg

theorem curveWork_pairing_check_refinement [RuntimeFeatures]
    (hfp : PortableFpCorrect) (hpairing : PairingCorrect)
    (work : verify.CurveWork) (hwork : CurveWorkInvariant work)
    (sums : verify.PairingSums) (ll rlc rli rlp : G1)
    (hll : G1Rep sums.ll ll) (hrlc : G1Rep sums.rlc rlc)
    (hrli : G1Rep sums.rli rli) (hrlp : G1Rep sums.rlp rlp)
    (hvll : G1Valid ll) (hvlc : G1Valid rlc) (hvli : G1Valid rli) (hvlp : G1Valid rlp) :
    work.pairing_check sums =
      ok (Bls.pairingCheck #[(ll, embeddedSetup.g2Monomial[64]!),
        (G1.add (G1.add rlc (G1.neg rli)) rlp, G2.neg embeddedSetup.g2Monomial[0]!)]) := by
  rw [embedded_g2_cell, embedded_g2_zero]
  have hvright := g1Valid_add (g1Valid_add hvlc (g1Valid_neg hvli)) hvlp
  cases work with
  | Lanes msm words =>
    obtain ⟨points,hpoints,hrep⟩ := pairing_points_in_lanes_refinement sums ll rlc rli rlp
      hll hrlc hrli hrlp hvll hvlc hvli hvlp
    simp only [verify.CurveWork.pairing_check, hpoints, bind_tc_ok,
      hpairing.lanes points ll _ hrep hvll hvright]
  | Portable msm lines words =>
    obtain ⟨points,hpoints,hrep⟩ := pairing_points_refinement hfp sums ll rlc rli rlp
      hll hrlc hrli hrlp hvlc hvli hvlp
    have hlines : PortableLinesRep lines := hwork
    simp only [verify.CurveWork.pairing_check, hpoints, bind_tc_ok,
      hpairing.portable lines points ll _ hlines hrep hvll hvright]

end LeanBlsSimd.Kzg
