import LeanBlsSimd.Refines.G1
import LeanBlsSimd.Proofs.G1

open Aeneas Aeneas.Std Result
open silver_bls_simd

namespace LeanBlsSimd.UncompressG1

open DecompressG1

def specVerdict (bytes : Array U8 48#usize) : Option blst.blst_p1_affine :=
  (G1Spec.verdict (ofArray ofU8 bytes)).map toBlstP1Affine

def usesKernelAt [G1Externals] (inputs : Slice (Array U8 48#usize)) (i : ℕ) : Bool :=
  usesKernel G1Externals.simdAvailable (inputs.val.map (ofArray ofU8)) i

theorem usesKernelAt_iff [G1Externals] (inputs : Slice (Array U8 48#usize)) (i : ℕ) :
    usesKernelAt inputs i = true ↔
      G1Externals.simdAvailable = true ∧ i < inputs.val.length / 8 * 8 ∧
      (decompress (chunkAt (inputs.val.map (ofArray ofU8)) i)).undecided.toNat.testBit
        (i % 8) = false := by
  sorry

/-- All slots are overwritten. The route is determined by SIMD, chunk size, and the
kernel's actual undecided mask; the scalar external is otherwise unconstrained. -/
theorem uncompress_in_g1_eq_spec_or_blst [G1Externals]
    (inputs : Slice (Array U8 48#usize)) (out : Slice (Option blst.blst_p1_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_bls_simd.uncompress_in_g1 inputs out = ok result ∧
      result.val.length = inputs.val.length ∧
      ∀ i : Fin inputs.val.length,
        result.val[i.val]? = some
          (if usesKernelAt inputs i.val then specVerdict inputs.val[i.val]
           else G1Externals.uncompress inputs.val[i.val]) := by
  sorry

/-- The sole extra premise relates the total blst external to the KZG verdict on all
48-byte inputs. No completeness, decided-lane, or CPU premise is required. -/
theorem uncompress_in_g1_eq_spec [G1Externals]
    (hblst : ∀ bytes : Array U8 48#usize, G1Externals.uncompress bytes = specVerdict bytes)
    (inputs : Slice (Array U8 48#usize)) (out : Slice (Option blst.blst_p1_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_bls_simd.uncompress_in_g1 inputs out = ok result ∧
      result.val.length = inputs.val.length ∧
      ∀ i : Fin inputs.val.length,
        result.val[i.val]? = some (specVerdict inputs.val[i.val]) := by
  sorry

#print axioms silver_bls_simd.uncompress_in_g1
#print axioms uncompress_in_g1_eq_spec_or_blst
#print axioms uncompress_in_g1_eq_spec

end LeanBlsSimd.UncompressG1
