import LeanBlsSimd.Sha256.Streaming

open LeanBlsSimd.Sha256 Streaming

namespace LeanBlsSimd.Controls.ShaStreaming

theorem empty_update_preserves_state : update initial [] = initial :=
  update_empty initial [] initial_represents

theorem split_update_preserves_state (a b : List UInt8) :
    update (update initial a) b = update initial (a++b) :=
  update_split initial [] a b initial_represents

theorem dropped_pending_byte_rejected (s : State) :
    ¬ Represents { s with pending := [] } [1] := by
  intro h
  have hp := pending_length _ _ h
  exact (by decide : ¬ (0 : Nat) = 1%64) hp

theorem wrong_stored_length_rejected : ¬ Represents { initial with length := 1 } [] := by
  intro h
  exact (by decide : (1 : UInt64) ≠ 0) h.2.2

end LeanBlsSimd.Controls.ShaStreaming

#print axioms LeanBlsSimd.Sha256.Streaming.update_append
#print axioms LeanBlsSimd.Sha256.Streaming.finish_eq_hash
