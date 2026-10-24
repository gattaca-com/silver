import LeanBlsSimd.Sha256.GeneratedPadding
import LeanBlsSimd.Sha256.GeneratedUpdateRefines
import LeanBlsSimd.Sha256.ExtensionCompress
import LeanBlsSimd.Sha256.ContractAdapter

open Aeneas Aeneas.Std Result
open silver_crypto_simd

namespace LeanBlsSimd.Sha256

open Generated

attribute [local irreducible] Streaming.finish EthLib.Cryptography.Bls.sha256

private theorem bytes_bridge (xs : List U8) : Spec.bytes (xs.map ofU8) = Kzg.bytes xs := by
  apply ByteArray.ext
  simp [Spec.bytes,Kzg.bytes,ofU8]

private def Represents (state : Array U32 8#usize) (pending : Array U8 64#usize)
    (p : Usize) (length : U64) (pre : List U8) : Prop :=
  p.val < 64 ∧ Streaming.Represents (view state pending p length) (pre.map ofU8)

private theorem initial_represents :
    Represents sha256.INITIAL_STATE (Array.repeat 64#usize 0#u8) 0#usize 0#u64 [] := by
  refine ⟨by decide,?_,rfl,rfl⟩
  change words sha256.INITIAL_STATE = Spec.initialState
  decide +kernel

private theorem update_represents {S : Type}
    (mk : Array U32 8#usize → Array U8 64#usize → Usize → U64 → S)
    (compress : Compressor) (hc : CompressorRefines compress)
    (state : Array U32 8#usize) (pending : Array U8 64#usize) (p : Usize) (length : U64)
    (pre : List U8) (data : Slice U8) (h : Represents state pending p length pre) :
    ∃ out pending' next,
      update mk compress state pending p length data = ok (mk out pending' next (absorbedLength length data)) ∧
      Represents out pending' next (absorbedLength length data) (pre++data.val) := by
  obtain ⟨out,pending',next,he,hp,hm⟩ := update_refines mk compress hc state pending p length data h.1
  refine ⟨out,pending',next,he,hp,?_⟩
  rw [hm]
  simpa only [List.map_append] using Streaming.update_append _ _ (data.val.map ofU8) h.2

private theorem finish_represents (compress : Compressor) (hc : CompressorRefines compress)
    (state : Array U32 8#usize) (pending : Array U8 64#usize) (p : Usize) (length : U64)
    (pre : List U8) (h : Represents state pending p length pre) :
    ∃ out, finish compress state pending p length = ok out ∧
      Kzg.arrayBytes out = EthLib.Cryptography.Bls.sha256 (Kzg.bytes pre) := by
  obtain ⟨out,he,hm⟩ := finish_refines compress hc state pending p length h.1
  refine ⟨out,he,?_⟩
  have heq := hm.trans (Streaming.finish_eq_hash _ _ h.2)
  simpa only [bytes_bridge,Kzg.arrayBytes] using heq

theorem portable_correct : Kzg.ShaPathCorrect sha256.portable.Sha256.new
    sha256.portable.Sha256.update sha256.portable.Sha256.finish := by
  apply Kzg.shaPathCorrect_of_invariant sha256.portable.Sha256.new
    (fun s pre => Represents s.state s.pending s.pending_len s.length pre)
  · exact ⟨_,rfl,initial_represents⟩
  · intro s pre data h
    obtain ⟨out,pending',next,he,hr⟩ := update_represents sha256.portable.Sha256.mk
      sha256.portable.compress_blocks Portable.compress_blocks_refines
      s.state s.pending s.pending_len s.length pre data h
    exact ⟨_,(portable_update_eq _ _).trans he,hr⟩
  · intro s pre h
    simpa only [portable_finish_eq] using finish_represents sha256.portable.compress_blocks
      Portable.compress_blocks_refines s.state s.pending s.pending_len s.length pre h

theorem extensions_correct : Kzg.ShaPathCorrect sha256.extensions.Sha256.new
    sha256.extensions.Sha256.update sha256.extensions.Sha256.finish := by
  apply Kzg.shaPathCorrect_of_invariant sha256.extensions.Sha256.new
    (fun s pre => Represents s.state s.pending s.pending_len s.length pre)
  · exact ⟨_,rfl,initial_represents⟩
  · intro s pre data h
    obtain ⟨out,pending',next,he,hr⟩ := update_represents sha256.extensions.Sha256.mk
      sha256.extensions.compress_blocks Extensions.compress_blocks_refines
      s.state s.pending s.pending_len s.length pre data h
    exact ⟨_,(extensions_update_eq _ _).trans he,hr⟩
  · intro s pre h
    simpa only [extensions_finish_eq] using finish_represents sha256.extensions.compress_blocks
      Extensions.compress_blocks_refines s.state s.pending s.pending_len s.length pre h

theorem sha_correct : Kzg.ShaCorrect := ⟨extensions_correct,portable_correct⟩

end LeanBlsSimd.Sha256
