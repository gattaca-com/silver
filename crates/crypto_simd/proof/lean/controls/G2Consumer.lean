import LeanBlsSimd.Refines.UncompressG2

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls LeanBlsSimd

example [RuntimeFeatures] [BlsExternals] (hblst : UncompressG2.BlstMatchesSpec)
    (inputs : Slice (Array U8 96#usize)) (out : Slice (Option g2_point.G2Point))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g2 inputs out = ok result ∧
      result.val = inputs.val.map UncompressG2.specVerdict ∧
      ∀ p, some p ∈ result.val → Kzg.G2AffineValid p :=
  UncompressG2.uncompress_in_g2_eq_spec_list hblst inputs out hlen

@[reducible] def g2SpecExternals : BlsExternals := ⟨UncompressG2.specVerdict⟩

example :
    @UncompressG2.BlstMatchesSpec g2SpecExternals := fun _ => rfl

example [RuntimeFeatures] [BlsExternals] (hblst : UncompressG2.BlstMatchesSpec)
    (inputs : Slice (Array U8 96#usize)) (out : Slice (Option g2_point.G2Point))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g2 inputs out = ok result ∧
      result.val.map (Option.map DecompressG2.ofBlstP2Affine) =
        inputs.val.map (G2Spec.verdict ∘ ofArray ofU8) :=
  UncompressG2.uncompress_in_g2_eq_spec_model_list hblst inputs out hlen

example [RuntimeFeatures] [BlsExternals] (inputs : Slice (Array U8 96#usize))
    (out : Slice (Option g2_point.G2Point)) (hlen : out.val.length ≠ inputs.val.length) :
    silver_crypto_simd.bls.uncompress_in_g2 inputs out = fail .assertionFailure :=
  UncompressG2.uncompress_in_g2_length_mismatch inputs out hlen
