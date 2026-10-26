import LeanBlsSimd.Kzg.PairingContract
import LeanBlsSimd.Pairing.Verdict
import LeanBlsSimd.Pairing.PortableMiller
import LeanBlsSimd.Pairing.LaneMiller
import LeanBlsSimd.Pairing.PortableFinal
import LeanBlsSimd.Pairing.LaneFinal

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Pairing

theorem PortableLines.pairing_check [RuntimeFeatures] (lines : portable.pairing.PairingLines)
    (hl : Kzg.PortableLinesRep lines) (raw : Array portable.g1.G1 2#usize)
    (points : Fin 2 → G1) (hp : PortableLines.PointsRep raw points) :
    portable.pairing.PairingLines.pairing_check lines raw =
      ok (Bls.pairingCheck #[(points 0, Kzg.SetupPoints.g2Point64),
        (points 1, G2.neg Kzg.SetupPoints.g2Point0)]) := by
  simp only [portable.pairing.PairingLines.pairing_check,
    PortableLines.miller_encoded lines hl raw points hp, bind_tc_ok]
  rw [FinalExponent.Portable.final_verdict, combined_verdict]

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

theorem portable_pairing_correct [RuntimeFeatures] (lines : portable.pairing.PairingLines)
    (raw : Array portable.g1.G1 2#usize) (p q : G1)
    (hl : PortableLinesRep lines) (hr : PortablePairRep raw p q) :
    portable.pairing.PairingLines.pairing_check lines raw =
      ok (Bls.pairingCheck #[(p, SetupPoints.g2Point64), (q, G2.neg SetupPoints.g2Point0)]) := by
  let points : Fin 2 → G1 := fun i => PortableG1.read (raw.val[i.val]'(by simp; omega))
  have hp : PortableLines.PointsRep raw points := fun i =>
    Portable.G1.coords_eq_encode (PortableG1.Rep.coords (hr i))
  rw [PortableLines.pairing_check lines hl raw points hp]
  exact congrArg ok (pairingCheck_two_congr _ _ (hr 0).2.1 (hr 0).2.2 (hr 1).2.1 (hr 1).2.2)

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

theorem pairing_correct [RuntimeFeatures] : PairingCorrect where
  lanes := fun raw p q hr _ _ => lanes_pairing_correct raw p q hr
  portable := fun lines raw p q hl hr _ _ => portable_pairing_correct lines raw p q hl hr

end LeanBlsSimd.Kzg
