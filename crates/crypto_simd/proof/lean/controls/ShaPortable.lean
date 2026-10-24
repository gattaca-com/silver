import LeanBlsSimd.Sha256.PortableCompress
import LeanBlsSimd.Sha256.ContractAdapter

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd
open LeanBlsSimd.Sha256

namespace LeanBlsSimd.Controls.ShaPortable

theorem reversed_load_rejected :
    core.num.U32.from_be_bytes (Array.make 4#usize [0#u8,1#u8,2#u8,3#u8] (by rfl)) ≠
      word 0x03020100 := by decide +kernel

private def seed : Array U32 64#usize :=
  (Array.repeat 64#usize 0#u32).set 1#usize (word 1)

private def observedCont {α β : Type} (f : α → UInt32) : Result (ControlFlow α β) → Option UInt32
  | ok (cont v) => some (f v)
  | _ => none

private theorem zero_words : words (Array.repeat 64#usize 0#u32) = _root_.Array.replicate 64 0 := by
  simp [words,Array.repeat]
  rfl

theorem wrong_schedule_sigma_rejected :
    observedCont (fun (v : Array U32 64#usize × Usize) => (words v.1)[16]!)
      (sha256.portable.schedule_loop1.body seed 16#usize) ≠ some (Spec.smallSigma1 1) := by
  obtain ⟨out,next,hbody,hwords,_⟩ := Portable.schedule_expand_step seed 16#usize (by decide) (by decide)
  rw [hbody]
  change some (words out)[16]! ≠ _
  rw [hwords]
  have hs : words seed = (_root_.Array.replicate 64 0).set! 1 1 := by
    unfold seed
    rw [words_set,zero_words]
    rfl
  rw [hs]
  norm_num only [UScalar.ofNatCore_val_eq]
  decide +kernel

theorem zero_round_constant_rejected :
    observedCont (ofWord ∘ Prod.fst) (sha256.portable.compress_loop.body (Array.repeat 64#usize 0#u32)
      0#u32 0#u32 0#u32 0#u32 0#u32 0#u32 0#u32 0#u32 0#usize) ≠ some 0 := by
  obtain ⟨next,_,hbody⟩ := Portable.round_step (Array.repeat 64#usize 0#u32)
    ⟨0,0,0,0,0,0,0,0⟩ 0#usize (by decide)
  dsimp only at hbody
  simp only [show word 0 = 0#u32 from rfl] at hbody
  rw [hbody,zero_words]
  norm_num only [UScalar.ofNatCore_val_eq]
  change some (Spec.round Spec.constants[0]! 0 ⟨0,0,0,0,0,0,0,0⟩).1 ≠ some 0
  decide +kernel

end LeanBlsSimd.Controls.ShaPortable

#print axioms LeanBlsSimd.Sha256.from_be_bytes_model
#print axioms LeanBlsSimd.Sha256.Portable.schedule_refines
#print axioms LeanBlsSimd.Sha256.Portable.rounds_refines
#print axioms LeanBlsSimd.Sha256.Portable.compress_blocks_refines
#print axioms LeanBlsSimd.Kzg.shaPathCorrect_of_invariant
