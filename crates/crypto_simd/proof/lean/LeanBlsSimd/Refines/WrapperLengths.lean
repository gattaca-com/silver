import LeanBlsSimd.Extracted.Funs

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.UncompressG1

/-- Aeneas represents the Rust assertion failure without its panic message. -/
theorem uncompress_in_g1_length_mismatch [RuntimeFeatures] [KzgExternals]
    (inputs : Slice (Array U8 48#usize)) (out : Slice (Option blst.blst_p1_affine))
    (hlen : out.val.length ≠ inputs.val.length) :
    silver_crypto_simd.bls.uncompress_in_g1 inputs out = fail .assertionFailure := by
  have hne : Slice.len out ≠ Slice.len inputs := by
    intro h
    apply hlen
    simpa using congrArg UScalar.val h
  simp [silver_crypto_simd.bls.uncompress_in_g1, massert, hne]

end LeanBlsSimd.UncompressG1

namespace LeanBlsSimd.UncompressG2

/-- Aeneas represents the Rust assertion failure without its panic message. -/
theorem uncompress_in_g2_length_mismatch [RuntimeFeatures] [BlsExternals]
    (inputs : Slice (Array U8 96#usize)) (out : Slice (Option blst.blst_p2_affine))
    (hlen : out.val.length ≠ inputs.val.length) :
    silver_crypto_simd.bls.uncompress_in_g2 inputs out = fail .assertionFailure := by
  have hne : Slice.len out ≠ Slice.len inputs := by
    intro h
    apply hlen
    simpa using congrArg UScalar.val h
  simp [silver_crypto_simd.bls.uncompress_in_g2, massert, hne]

end LeanBlsSimd.UncompressG2
