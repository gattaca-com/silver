import LeanBlsSimd.Kzg.PairingContract
import LeanBlsSimd.Pairing.Verdict
import LeanBlsSimd.Pairing.LaneMiller
import LeanBlsSimd.Pairing.LaneFinal

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Pairing

theorem LaneLines.pairing_check (raw : bls.g1x8.G1x8)
    (points : Fin 8 → G1) (hp : LaneLines.PointsRep raw points) :
    bls.pairing.MillerLines.pairing_check pairing_lines.PAIRING_LINES raw =
      ok (Bls.pairingCheck #[(points 0, Kzg.SetupPoints.g2Point64),
        (points 1, G2.neg Kzg.SetupPoints.g2Point0)]) := by
  obtain ⟨out, hout, hrep⟩ := LaneLines.miller_refines raw points hp
  simp only [bls.pairing.MillerLines.pairing_check, hout, bind_tc_ok]
  rw [FinalExponent.Lanes.final_verdict hrep, combined_verdict]
  rfl

end LeanBlsSimd.Pairing

namespace LeanBlsSimd.Kzg

open LeanBlsSimd.Pairing

theorem lanes_pairing_correct (raw : bls.g1x8.G1x8) (p q : G1) (hr : LanesPairRep raw p q) :
    bls.pairing.MillerLines.pairing_check pairing_lines.PAIRING_LINES raw =
      ok (Bls.pairingCheck #[(p, SetupPoints.g2Point64), (q, G2.neg SetupPoints.g2Point0)]) := by
  classical
  unfold LanesPairRep LaneG1Rep at hr
  choose points hcoords hinf haff using hr
  have hp : LaneLines.PointsRep raw points := by
    intro i
    rcases hcoords i with ⟨hx, hy, hz⟩
    exact ⟨hx, hy, hz⟩
  rw [LaneLines.pairing_check raw points hp]
  exact congrArg ok (pairingCheck_two_congr _ _ (hinf 0) (haff 0) (hinf 1) (haff 1))

theorem pairing_correct : PairingCorrect where
  lanes := fun raw p q hr _ _ => lanes_pairing_correct raw p q hr

end LeanBlsSimd.Kzg
