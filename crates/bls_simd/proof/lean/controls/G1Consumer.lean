import LeanBlsSimd.Refines.UncompressG1

open Aeneas Aeneas.Std Result
open silver_bls_simd LeanBlsSimd

example [G1Externals]
    (hblst : ∀ bytes : Aeneas.Std.Array U8 48#usize,
      G1Externals.uncompress bytes = UncompressG1.specVerdict bytes)
    (inputs : Slice (Aeneas.Std.Array U8 48#usize))
    (out : Slice (Option blst.blst_p1_affine))
    (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_bls_simd.uncompress_in_g1 inputs out = ok result ∧
      result.val.length = inputs.val.length ∧
      ∀ i : Fin inputs.val.length,
        result.val[i.val]? = some (UncompressG1.specVerdict inputs.val[i.val]) :=
  UncompressG1.uncompress_in_g1_eq_spec hblst inputs out hlen

@[reducible] def specExternals : G1Externals := ⟨true, UncompressG1.specVerdict⟩

example (bytes : Aeneas.Std.Array U8 48#usize) :
    @G1Externals.uncompress specExternals bytes = UncompressG1.specVerdict bytes := rfl
