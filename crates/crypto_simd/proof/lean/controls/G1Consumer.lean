import LeanBlsSimd.Refines.UncompressG1

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls LeanBlsSimd

example [RuntimeFeatures] [KzgExternals] [UncompressG1.FallbackCorrect] (inputs : Slice (Aeneas.Std.Array U8 48#usize))
    (out : Slice (Option blst.blst_p1_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_crypto_simd.bls.uncompress_in_g1 inputs out = ok result ∧
      result.val.length = inputs.val.length ∧
      ∀ i : Fin inputs.val.length,
        result.val[i.val]? = some (UncompressG1.specVerdict inputs.val[i.val]) :=
  UncompressG1.uncompress_in_g1_eq_spec inputs out hlen

@[reducible] def scalarFeatures : RuntimeFeatures := ⟨false, false, false⟩

example (bytes : Aeneas.Std.Array U8 48#usize) :
    @portable.decompress.uncompress_in_g1 scalarFeatures bytes =
      ok (UncompressG1.specVerdict bytes) := @G1DecoderCorrect.singleton scalarFeatures (@Portable.Decode.g1_decoder_correct scalarFeatures) bytes

example [RuntimeFeatures] (a b : Aeneas.Std.Array U8 48#usize)
    (hne : UncompressG1.specVerdict a ≠ UncompressG1.specVerdict b) :
    portable.decompress.uncompress_pair_in_g1 a b ≠
      ok (Aeneas.Std.Array.make 2#usize
        [UncompressG1.specVerdict b, UncompressG1.specVerdict a] (by rfl)) := by
  rw [Portable.Decode.g1_decoder_correct.pair]
  intro h
  have hfirst := congrArg (fun xs : Aeneas.Std.Array (Option blst.blst_p1_affine) 2#usize =>
    xs.val[0]!) (Result.ok.inj h)
  exact hne (by simpa [Aeneas.Std.Array.make] using hfirst)
