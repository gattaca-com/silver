import LeanBlsSimd.Refines.Kernel
import LeanBlsSimd.Spec.CubicHasse

/-! Extracted decompression correctness with Scott completeness discharged. -/

namespace LeanBlsSimd

open Aeneas Aeneas.Std Result
open EthCryptographySpecs.Bls Kernel

namespace DecompressG2

/-- The generated function returns a batch on every input, and each decided lane agrees with
the specification. `scott_complete` discharges the completeness premise of the conditional API. -/
theorem decompress_extracted_eq_spec_complete (inputs : Array (Array U8 96#usize) 8#usize) :
    ∃ batch, silver_crypto_simd.bls.decompress_g2.decompress inputs = ok batch ∧
      (∀ l : Fin 8, (ofBatch batch).undecided.toNat.testBit l = false →
        (if (ofBatch batch).valid.toNat.testBit l then some (ofBatch batch).points[l]
          else none) =
        (match G2.uncompress (toBytes (ofArray (ofArray ofU8) inputs (m := 8))[l]) with
          | .error _ => none
          | .ok P => if G2.inSubgroup P then some (blstLimbs P) else none)) := by
  obtain ⟨batch, hb, hs⟩ := decompress_extracted_eq_spec inputs
  exact ⟨batch, hb, hs scott_complete⟩

end DecompressG2

end LeanBlsSimd
