import LeanBlsSimd.Sha256.Correct

open Aeneas Aeneas.Std
open LeanBlsSimd LeanBlsSimd.Sha256 Generated

namespace LeanBlsSimd.Controls.ShaGenerated

private def oneByte : Slice U8 := ⟨[0#u8],by scalar_tac⟩

theorem dropped_length_wrap_rejected :
    (ofU64 (absorbedLength 18446744073709551615#u64 oneByte)).toNat ≠ 2^64 := by
  rw [absorbedLength_model]
  decide +kernel

theorem missing_padding_marker_rejected :
    ofU8 (paddedBytes (Array.repeat 64#usize 0#u8) 0#usize 0#u64).val[0]! ≠ 0 := by
  rw [paddedBytes_get _ _ _ (by decide) _ (by decide +kernel)]
  decide +kernel

theorem reversed_digest_bytes_rejected :
    (writtenBytes (Array.repeat 8#usize 1#u32)).val[0]! ≠
      (writtenBytes (Array.repeat 8#usize 1#u32)).val[3]! := by
  have h0 := writtenBytes_get (Array.repeat 8#usize 1#u32) 0 0 (by decide) (by decide)
  have h3 := writtenBytes_get (Array.repeat 8#usize 1#u32) 0 3 (by decide) (by decide)
  rw [h0,h3]
  decide +kernel

theorem generated_sha_contract : Kzg.ShaCorrect := sha_correct

end LeanBlsSimd.Controls.ShaGenerated

#print axioms LeanBlsSimd.Sha256.Generated.finish_refines
#print axioms LeanBlsSimd.Sha256.sha_correct
