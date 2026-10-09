import LeanBlsSimd.Refines.DecompressG2
import LeanBlsSimd.Proofs.Kernel

/-!
# The generated `decompress` against the spec's signature check

`decompress_extracted_eq_spec` is `decompress_eq_spec` for the generated
`silver_bls_simd.decompress_g2.decompress`, which Aeneas translates from the Rust. It also states,
with no hypothesis, that this function returns `ok` on every input: it neither panics nor
diverges.

Both sides of the statement read the generated values through the conversions of `Refines/`.
`ofBatch` reads the returned `Batch` field by field, and `ofArray (ofArray ofU8)` reads the input
bytes as the model's `Vector`s. The proof is `decompress_refines` followed by
`decompress_eq_spec`.
-/

namespace LeanBlsSimd

open Aeneas Aeneas.Std Result
open EthCryptographySpecs.Bls Kernel

namespace DecompressG2

/-- The generated `decompress` returns a batch on every input. Given Scott completeness, each lane
of that batch that is not undecided gives the spec's result. The left side is
`decompress_g2_chunk`'s reading of the returned batch in `lib.rs`, past its `undecided` test. The
right side is `coreVerify`'s reading of the lane's bytes, as in `decompress_eq_spec`. -/
theorem decompress_extracted_eq_spec (inputs : Array (Array U8 96#usize) 8#usize) :
    ∃ batch, silver_bls_simd.decompress_g2.decompress inputs = ok batch ∧
      (ScottComplete → ∀ l : Fin 8, (ofBatch batch).undecided.toNat.testBit l = false →
        (if (ofBatch batch).valid.toNat.testBit l then some (ofBatch batch).points[l]
          else none) =
        (match G2.uncompress (toBytes (ofArray (ofArray ofU8) inputs (m := 8))[l]) with
          | .error _ => none
          | .ok P => if G2.inSubgroup P then some (blstLimbs P) else none)) :=
  ⟨_, decompress_refines inputs, fun hC l hu => by
    rw [ofBatch_toBatch] at hu ⊢
    exact decompress_eq_spec hC _ l hu⟩

end DecompressG2

end LeanBlsSimd
