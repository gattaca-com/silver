import LeanBlsSimd.PairingProduct.Headline

open Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls
open EthLib.Cryptography Bls
open LeanBlsSimd LeanBlsSimd.PairingProduct

namespace PairingSmoke

def verifyMany (features : RuntimeFeatures) (external : PairingExternals)
    (pairs : List pairing_product.AffinePair) : Result Bool := do
  let owner ← build pairs
  @pairing_product.PairingProduct.is_one features external owner

theorem verifyMany_correct (features : RuntimeFeatures) (external : PairingExternals)
    (agreement : @BlstMatchesSpec external) (pairs : List pairing_product.AffinePair)
    (valid : ∀ p ∈ pairs, Kzg.G1AffineValid p.p ∧ Kzg.G2AffineValid p.q)
    (room : (pairs.filter finitePair).length ≤ Usize.max) :
    verifyMany features external pairs =
      ok (pairingCheck (pairs.map
        (fun p => (Kzg.g1ReadAffine p.p, Kzg.g2ReadAffine p.q))).toArray) :=
  @build_is_one_correct features external agreement pairs valid room

def verifyTwo (features : RuntimeFeatures) (external : PairingExternals)
    (first second : g1_point.G1Point × g2_point.G2Point) : Result Bool :=
  @pairing_product.PairingProduct.two_pairs_are_one features external first second

theorem verifyTwo_correct (features : RuntimeFeatures) (external : PairingExternals)
    (agreement : @BlstMatchesSpec external)
    (first second : g1_point.G1Point × g2_point.G2Point)
    (hp : Kzg.G1AffineValid first.1) (hq : Kzg.G2AffineValid first.2)
    (hp' : Kzg.G1AffineValid second.1) (hq' : Kzg.G2AffineValid second.2) :
    verifyTwo features external first second =
      ok (pairingCheck #[(Kzg.g1ReadAffine first.1, Kzg.g2ReadAffine first.2),
        (Kzg.g1ReadAffine second.1, Kzg.g2ReadAffine second.2)]) :=
  @two_pairs_are_one_correct features external agreement first second hp hq hp' hq'

example (features : RuntimeFeatures) (external : PairingExternals)
    (owner : pairing_product.PairingProduct) :
    (do let empty ← pairing_product.PairingProduct.clear owner
        @pairing_product.PairingProduct.is_one features external empty) = ok true := by
  rw [clear_empty]
  exact @is_one_empty features external emptyOwner rfl

end PairingSmoke
