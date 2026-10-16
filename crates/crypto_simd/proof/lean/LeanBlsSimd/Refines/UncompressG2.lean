import LeanBlsSimd.Refines.Complete
import LeanBlsSimd.Refines.WrapperLengths
import LeanBlsSimd.Model.UncompressG2
import LeanBlsSimd.Spec.G2Encoding

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.UncompressG2

open DecompressG2

def modelBlst [BlsExternals] (bytes : Encoding) : Option BlstP2Affine :=
  (BlsExternals.uncompressG2 (toArray toU8 bytes)).map ofBlstP2Affine

def specVerdict (bytes : Array U8 96#usize) : Option blst.blst_p2_affine :=
  (G2Spec.verdict (ofArray ofU8 bytes)).map toBlstP2Affine

/-- Agreement includes acceptance and every affine limb, including infinity's zero limbs. -/
def BlstMatchesSpec [BlsExternals] : Prop :=
  ∀ bytes : Array U8 96#usize, BlsExternals.uncompressG2 bytes = specVerdict bytes

def usesKernelAt [BlsExternals] (inputs : Slice (Array U8 96#usize)) (i : ℕ) : Bool :=
  usesKernel BlsExternals.simdAvailable (inputs.val.map (ofArray ofU8)) i

theorem usesKernelAt_iff [BlsExternals] (inputs : Slice (Array U8 96#usize)) (i : ℕ) :
    usesKernelAt inputs i = true ↔
      BlsExternals.simdAvailable = true ∧ i < inputs.val.length ∧
      3 ≤ min 8 (inputs.val.length - i / 8 * 8) ∧
      (decompress (chunkAt (inputs.val.map (ofArray ofU8)) i)).undecided.toNat.testBit
        (i % 8) = false := by
  sorry

theorem uncompress_refines [BlsExternals] (inputs : Slice (Array U8 96#usize))
    (out : Slice (Option blst.blst_p2_affine)) (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g2 inputs out = ok result ∧
      result.val = (uncompress BlsExternals.simdAvailable modelBlst
        (inputs.val.map (ofArray ofU8))).map (Option.map toBlstP2Affine) := by
  sorry

/-- Every slot is overwritten. Decided kernel lanes use the specification; all other
lanes preserve the arbitrary scalar external's result. -/
theorem uncompress_in_g2_eq_spec_or_blst [BlsExternals]
    (inputs : Slice (Array U8 96#usize)) (out : Slice (Option blst.blst_p2_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g2 inputs out = ok result ∧
      result.val.length = inputs.val.length ∧
      ∀ i : Fin inputs.val.length,
        result.val[i.val]? = some
          (if usesKernelAt inputs i.val then specVerdict inputs.val[i.val]
           else BlsExternals.uncompressG2 inputs.val[i.val]) := by
  sorry

theorem uncompress_in_g2_eq_blst [BlsExternals] (hblst : BlstMatchesSpec)
    (inputs : Slice (Array U8 96#usize)) (out : Slice (Option blst.blst_p2_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g2 inputs out = ok result ∧
      result.val = inputs.val.map BlsExternals.uncompressG2 := by
  sorry

theorem uncompress_in_g2_eq_spec [BlsExternals] (hblst : BlstMatchesSpec)
    (inputs : Slice (Array U8 96#usize)) (out : Slice (Option blst.blst_p2_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g2 inputs out = ok result ∧
      result.val.length = inputs.val.length ∧
      ∀ i : Fin inputs.val.length,
        result.val[i.val]? = some (specVerdict inputs.val[i.val]) := by
  sorry

theorem uncompress_in_g2_eq_spec_list [BlsExternals] (hblst : BlstMatchesSpec)
    (inputs : Slice (Array U8 96#usize)) (out : Slice (Option blst.blst_p2_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g2 inputs out = ok result ∧
      result.val = inputs.val.map specVerdict := by
  sorry

theorem uncompress_in_g2_eq_spec_model_list [BlsExternals] (hblst : BlstMatchesSpec)
    (inputs : Slice (Array U8 96#usize)) (out : Slice (Option blst.blst_p2_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g2 inputs out = ok result ∧
      result.val.map (Option.map ofBlstP2Affine) =
        inputs.val.map (G2Spec.verdict ∘ ofArray ofU8) := by
  sorry

end LeanBlsSimd.UncompressG2
