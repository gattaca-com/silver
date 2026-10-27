import LeanBlsSimd.PairingProduct.Headline
import LeanBlsSimd.Kzg.SetupValidity
import LeanBlsSimd.Kzg.PointValidity

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

private instance : RuntimeFeatures := ⟨true, false, false⟩

private instance : PairingExternals where
  check pairs := pairingCheck (specPairs pairs)

private def finiteExample : pairing_product.AffinePair :=
  ⟨Kzg.g1Affine Kzg.SetupPoints.g1Points[0]!, Kzg.g2Affine Kzg.SetupPoints.g2Point0⟩

private def infinityExample : pairing_product.AffinePair :=
  ⟨finiteExample.p, Kzg.g2Affine G2.zero⟩

private def concretePairs := [finiteExample, infinityExample]

private theorem infinity_decoded :
    G2.uncompress ⟨G2Spec.infinity.toArray⟩ = .ok G2.zero := by
  decide +kernel

example : finitePair finiteExample = true := by
  unfold finitePair finiteExample
  rw [Kzg.setup_g1_roundtrip ⟨0, by decide⟩, Kzg.setup_g2_zero_roundtrip]
  decide +kernel

example : finitePair infinityExample = false := by
  simp only [finitePair, infinityExample, Kzg.g2ReadAffine_decoded infinity_decoded,
    show G2.zero.isInfinity = true from rfl, Bool.or_true, Bool.not_true]

example :
    (do let owner ← build concretePairs; pairing_product.PairingProduct.is_one owner) =
      ok (pairingCheck (concretePairs.map
        (fun p => (Kzg.g1ReadAffine p.p, Kzg.g2ReadAffine p.q))).toArray) := by
  apply build_is_one_correct ⟨by intros; rfl⟩
  · intro p hp
    simp only [concretePairs, List.mem_cons, List.not_mem_nil, or_false] at hp
    rcases hp with rfl | rfl
    · exact ⟨Kzg.setup_g1_affine_valid ⟨0, by decide⟩, Kzg.setup_g2_zero_valid⟩
    · exact ⟨Kzg.setup_g1_affine_valid ⟨0, by decide⟩,
        Kzg.g2Affine_decoded_valid infinity_decoded rfl⟩
  · have bound := List.length_filter_le finitePair concretePairs
    have := two_pow_32_le_usize
    simp only [concretePairs, List.length_cons, List.length_nil] at bound ⊢
    simp only [Usize.max_def, Usize.numBits_def]
    omega

end PairingSmoke
