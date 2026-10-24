import LeanBlsSimd.Sha256.Padding
import LeanBlsSimd.Sha256.Blocks

namespace LeanBlsSimd.Sha256.Streaming

open Spec
attribute [local irreducible] Spec.compressBlock Spec.schedule Spec.padded

structure State where
  state : Array UInt32
  pending : List UInt8
  length : UInt64

def initial : State := ⟨initialState, [], 0⟩

def Represents (s : State) (pre : List UInt8) : Prop :=
  s.state = compressBlocks initialState (bytes pre) 0 (pre.length/64) ∧
  s.pending = pre.drop (64*(pre.length/64)) ∧
  s.length = UInt64.ofNat pre.length

theorem initial_represents : Represents initial [] := by
  exact ⟨rfl,rfl,rfl⟩

theorem pending_length (s : State) (pre : List UInt8) (h : Represents s pre) :
    s.pending.length = pre.length%64 := by
  rw [h.2.1,List.length_drop]
  omega

theorem pending_lt (s : State) (pre : List UInt8) (h : Represents s pre) :
    s.pending.length < 64 := by
  rw [pending_length s pre h]
  exact Nat.mod_lt _ (by decide)

def update (s : State) (input : List UInt8) : State :=
  let joined := s.pending++input
  let blocks := joined.length/64
  ⟨compressBlocks s.state (bytes joined) 0 blocks,
    joined.drop (64*blocks), s.length + UInt64.ofNat input.length⟩

theorem update_append (s : State) (pre input : List UInt8) (hs : Represents s pre) :
    Represents (update s input) (pre++input) := by
  have hpre : 64*(pre.length/64) ≤ pre.length := by omega
  have hp : s.pending.length = pre.length%64 := pending_length s pre hs
  have hn : (pre++input).length/64 = pre.length/64 + (s.pending++input).length/64 := by
    simp only [List.length_append]
    omega
  have hd : (pre++input).drop (64*(pre.length/64)) = s.pending++input := by
    rw [List.drop_append, Nat.sub_eq_zero_of_le hpre, List.drop_zero, ← hs.2.1]
  refine ⟨?_,?_,?_⟩
  · change compressBlocks s.state (bytes (s.pending++input)) 0 ((s.pending++input).length/64) = _
    rw [hn, compressBlocks_append, compressBlocks_prefix _ _ _ _ hpre]
    simp only [Nat.zero_add]
    rw [compressBlocks_drop _ (pre++input) (64*(pre.length/64)) _, hd, hs.1]
  · change (s.pending++input).drop (64*((s.pending++input).length/64)) = _
    have he := congrArg (fun xs : List UInt8 => xs.drop (64*((s.pending++input).length/64))) hd
    simp only [List.drop_drop] at he
    have hindex : 64*(pre.length/64)+64*((s.pending++input).length/64) =
        64*((pre++input).length/64) := by omega
    simpa only [hindex] using he.symm
  · change s.length + UInt64.ofNat input.length = _
    rw [hs.2.2, ← UInt64.ofNat_add, List.length_append]

theorem tail_matches (s : State) (pre : List UInt8) (hs : Represents s pre)
    (i : Nat) (hi : i < paddedLength s.pending.length) :
    (padded (bytes pre))[64*(pre.length/64)+i]! =
      (padWithBits (bytes s.pending) (s.length <<< (3 : UInt64)))[i]! := by
  have hp := pending_length s pre hs
  have hn : pre.length = 64*(pre.length/64)+s.pending.length := by omega
  have hpad : paddedLength pre.length = 64*(pre.length/64)+paddedLength s.pending.length := by
    rw [paddedLength_prefix, hp]
  have hspace : 8 ≤ paddedLength s.pending.length := by unfold paddedLength; omega
  have hindex : 64*(pre.length/64)+i-(paddedLength pre.length-8) =
      i-(paddedLength s.pending.length-8) := by omega
  rw [padded_get _ _ (by rw [bytes_size]; omega),
    padWithBits_get _ _ _ (by rw [bytes_size]; exact hi)]
  simp only [bytes_size]
  rw [hs.2.2, bitLength_eq]
  by_cases hlt : i < s.pending.length
  · rw [if_pos (by omega), if_pos hlt, hs.2.1]
    exact bytes_drop_get pre (64*(pre.length/64)) i
  · rw [if_neg (by omega), if_neg hlt]
    by_cases he : i = s.pending.length
    · rw [if_pos (by omega), if_pos he]
    · rw [if_neg (by omega), if_neg he]
      by_cases hlast : paddedLength s.pending.length-8 ≤ i
      · rw [if_pos (by omega), if_pos hlast, hindex]
      · rw [if_neg (by omega), if_neg hlast]

def finish (s : State) : ByteArray :=
  digest (compressBlocks s.state
    (padWithBits (bytes s.pending) (s.length <<< (3 : UInt64))) 0
    (tailBlocks s.pending.length))

theorem finish_eq_hash (s : State) (pre : List UInt8) (hs : Represents s pre) :
    finish s = EthLib.Cryptography.Bls.sha256 (bytes pre) := by
  have hp := pending_length s pre hs
  have hshort := pending_lt s pre hs
  have htail : paddedLength s.pending.length = 64*tailBlocks s.pending.length :=
    paddedLength_short _ hshort
  have htotal : paddedLength pre.length =
      64*(pre.length/64)+64*tailBlocks s.pending.length := by
    rw [paddedLength_prefix, ← hp, htail]
  have hcount : (paddedLength pre.length+63)/64 = pre.length/64+tailBlocks s.pending.length := by
    omega
  have hprefix : compressBlocks initialState (padded (bytes pre)) 0 (pre.length/64) = s.state := by
    rw [hs.1]
    apply compressBlocks_congr
    intro i hi
    simp only [Nat.zero_add]
    rw [padded_get _ i (by rw [bytes_size]; unfold paddedLength; omega)]
    rw [if_pos (by rw [bytes_size]; omega)]
  unfold finish
  rw [hash_eq, padded_size, bytes_size, hcount, compressBlocks_append, hprefix]
  apply congrArg digest
  symm
  apply compressBlocks_congr
  intro i hi
  simpa only [Nat.zero_add] using tail_matches s pre hs i (by omega)

theorem represents_unique (s t : State) (pre : List UInt8)
    (hs : Represents s pre) (ht : Represents t pre) : s = t := by
  cases s
  cases t
  simp only [State.mk.injEq]
  exact ⟨hs.1.trans ht.1.symm, hs.2.1.trans ht.2.1.symm, hs.2.2.trans ht.2.2.symm⟩

theorem update_empty (s : State) (pre : List UInt8) (hs : Represents s pre) :
    update s [] = s := by
  apply represents_unique _ _ pre _ hs
  simpa only [List.append_nil] using update_append s pre [] hs

theorem update_split (s : State) (pre a b : List UInt8) (hs : Represents s pre) :
    update (update s a) b = update s (a++b) := by
  apply represents_unique _ _ (pre++(a++b))
  · simpa only [List.append_assoc] using
      update_append (update s a) (pre++a) b (update_append s pre a hs)
  · exact update_append s pre (a++b) hs

end LeanBlsSimd.Sha256.Streaming
