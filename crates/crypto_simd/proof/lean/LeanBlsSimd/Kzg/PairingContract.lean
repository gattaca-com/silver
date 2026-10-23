import LeanBlsSimd.Kzg.PairingTable
import LeanBlsSimd.Kzg.SetupPoints
import LeanBlsSimd.Refines.G1x8
import LeanBlsSimd.Proofs.G1x8

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg

/-- Canonical lane coordinates with the same projective point as the spec value. -/
def LaneG1Rep (raw : g1x8.G1x8) (lane : Fin 8) (p : G1) : Prop :=
  ∃ q, (ofG1x8 raw).Holds lane q ∧
    q.isInfinity = p.isInfinity ∧ q.toAffine = p.toAffine

def LanesPairRep (raw : g1x8.G1x8) (p q : G1) : Prop :=
  ∀ lane, LaneG1Rep raw lane (if lane.val = 0 then p else if lane.val = 1 then q else G1.zero)

def PortablePairRep (raw : Array portable.g1.G1 2#usize) (p q : G1) : Prop :=
  ∀ lane : Fin 2,
    let point := raw.val[lane.val]'(by simpa using lane.isLt)
    G1Rep ⟨⟨point.x⟩, ⟨point.y⟩, ⟨point.z⟩⟩ (if lane.val = 0 then p else q)

/-- Pending pairing-module obligations for the two fixed-G2 pairings on either execution path. -/
structure PairingCorrect [RuntimeFeatures] : Prop where
  lanes : ∀ raw p q, LanesPairRep raw p q → G1Valid p → G1Valid q →
    pairing.MillerLines.pairing_check pairing_lines.PAIRING_LINES raw =
      ok (Bls.pairingCheck #[(p, SetupPoints.g2Point64), (q, G2.neg SetupPoints.g2Point0)])
  portable : ∀ lines raw p q, PortableLinesRep lines → PortablePairRep raw p q →
    G1Valid p → G1Valid q →
    portable.pairing.PairingLines.pairing_check lines raw =
      ok (Bls.pairingCheck #[(p, SetupPoints.g2Point64), (q, G2.neg SetupPoints.g2Point0)])

end LeanBlsSimd.Kzg
