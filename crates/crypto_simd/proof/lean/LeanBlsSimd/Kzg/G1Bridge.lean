import LeanBlsSimd.Kzg.Decoder

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg

def mapSlice {α β : Type} (f : α → β) (xs : Slice α) : Slice β :=
  ⟨xs.val.map f, by simpa using xs.property⟩

def transportDecoder {ForeignAffine : Type}
    (toLocal : ForeignAffine → blst.blst_p1_affine)
    (fromLocal : blst.blst_p1_affine → ForeignAffine)
    (decode : Slice (Aeneas.Std.Array U8 48#usize) → Slice (Option ForeignAffine) →
      Result (Slice (Option ForeignAffine)))
    (inputs : Slice (Aeneas.Std.Array U8 48#usize))
    (out : Slice (Option blst.blst_p1_affine)) : Result (Slice (Option blst.blst_p1_affine)) := do
  let result ← decode inputs (mapSlice (Option.map fromLocal) out)
  ok (mapSlice (Option.map toLocal) result)

theorem decoder_transport {ForeignAffine : Type}
    (toLocal : ForeignAffine → blst.blst_p1_affine)
    (fromLocal : blst.blst_p1_affine → ForeignAffine)
    (decode : Slice (Aeneas.Std.Array U8 48#usize) → Slice (Option ForeignAffine) →
      Result (Slice (Option ForeignAffine)))
    (verdict : Aeneas.Std.Array U8 48#usize → Option ForeignAffine)
    (hdecode : ∀ inputs out, out.val.length = inputs.val.length →
      ∃ result, decode inputs out = ok result ∧ result.val = inputs.val.map verdict)
    (hverdict : ∀ b, (verdict b).map toLocal = specVerdict b)
    (inputs : Slice (Aeneas.Std.Array U8 48#usize))
    (out : Slice (Option blst.blst_p1_affine)) (hlen : out.val.length = inputs.val.length) :
    ∃ result, transportDecoder toLocal fromLocal decode inputs out = ok result ∧
      result.val = inputs.val.map specVerdict := by
  obtain ⟨result, hcall, hresult⟩ := hdecode inputs (mapSlice (Option.map fromLocal) out)
    (by simpa only [mapSlice, List.length_map] using hlen)
  refine ⟨mapSlice (Option.map toLocal) result, ?_, ?_⟩
  · simp only [transportDecoder, hcall, bind_tc_ok]
  · simp only [mapSlice, hresult, List.map_map, Function.comp_def, hverdict]

end LeanBlsSimd.Kzg
