import LeanBlsSimd.Kzg.BlstPairing
import LeanBlsSimd.Portable.Fp.Correct
import LeanBlsSimd.Kzg.LanePairingInputs
import LeanBlsSimd.Kzg.ScalarPairingInputs
import LeanBlsSimd.Kzg.PairingRepresentation
import LeanBlsSimd.Kzg.PairingCorrect

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg

theorem curveWork_pairing_check_refinement [RuntimeFeatures] [KzgExternals]
    (work : verify.CurveWork) (hblst : BlstPairing.FallbackCorrect work)
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
      pairing_correct.lanes points ll _ hrep hvll hvright]
  | Scalar msm words =>
    obtain ⟨points,hpoints,hrep⟩ := pairing_points_refinement sums ll rlc rli rlp
      hll hrlc hrli hrlp hvlc hvli hvlp
    have hp := hrep (0 : Fin 2)
    have hq := hrep (1 : Fin 2)
    simp only [verify.CurveWork.pairing_check, hpoints, bind_tc_ok,
      index_usize_eq points 0#usize (by decide), index_usize_eq points 1#usize (by decide),
      PortableG1.to_blst_eq]
    exact BlstPairing.pairing_check_refines (hblst rfl) _ _ ll _ hp hq hvll hvright

end LeanBlsSimd.Kzg
