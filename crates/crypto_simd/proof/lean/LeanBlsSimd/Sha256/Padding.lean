import LeanBlsSimd.Spec.Sha256

namespace LeanBlsSimd.Sha256.Spec

def writeBytes (b : ByteArray) (start count : Nat) (f : Nat → UInt8) : ByteArray :=
  (List.range' 0 count).foldl (fun b i => b.set! (start+i) (f i)) b

private theorem set_size (b : ByteArray) (i : Nat) (v : UInt8) :
    (b.set! i v).size = b.size := Array.size_setIfInBounds

private theorem set_get (b : ByteArray) (i j : Nat) (v : UInt8) (hj : j < b.size) :
    (b.set! j v)[i]! = if i=j then v else b[i]! := by
  by_cases hi : i < b.size
  · rw [getElem!_pos _ _ (by rw [set_size]; exact hi), getElem!_pos b i hi]
    change (b.data.setIfInBounds j v)[i]'(by simpa only [Array.size_setIfInBounds] using hi) = if i=j then v else b.data[i]
    by_cases he : i=j
    · subst i
      simp
    · simp only [if_neg he]
      exact Array.getElem_setIfInBounds_ne hi (fun hh => he hh.symm)
  · rw [getElem!_neg _ _ (by rw [set_size]; exact hi), getElem!_neg b i hi,
      if_neg (show i ≠ j by omega)]

theorem writeBytes_succ (b : ByteArray) (start n : Nat) (f : Nat → UInt8) :
    writeBytes b start (n+1) f = (writeBytes b start n f).set! (start+n) (f n) := by
  simp [writeBytes, List.range'_1_concat, List.foldl_append]

theorem writeBytes_size (b : ByteArray) (start n : Nat) (f : Nat → UInt8) :
    (writeBytes b start n f).size = b.size := by
  induction n with
  | zero => rfl
  | succ n ih => rw [writeBytes_succ, set_size, ih]

theorem writeBytes_get (b : ByteArray) (start n : Nat) (f : Nat → UInt8)
    (h : start+n ≤ b.size) (i : Nat) :
    (writeBytes b start n f)[i]! =
      if start ≤ i ∧ i < start+n then f (i-start) else b[i]! := by
  induction n with
  | zero => simp [writeBytes]
  | succ n ih =>
    rw [writeBytes_succ, set_get _ _ _ _ (by rw [writeBytes_size]; omega), ih (by omega)]
    by_cases he : i=start+n
    · subst i
      simp
    · simp only [if_neg he]
      by_cases hin : start ≤ i ∧ i < start+n
      · rw [if_pos hin, if_pos (show start ≤ i ∧ i < start+(n+1) by omega)]
      · rw [if_neg hin, if_neg (show ¬ (start ≤ i ∧ i < start+(n+1)) by omega)]

open private EthLib.Cryptography.Bls.Sha256.padded from EthLib.Cryptography.Bls.Sha256
open EthLib.Cryptography.IdLoops

def paddedLength (n : Nat) : Nat := n+1+paddingZeros n+8

def wordByte (bits : UInt64) (i : Nat) : UInt8 :=
  UInt8.ofNat ((bits >>> UInt64.ofNat ((7-i)*8)).toNat)

def padWithBits (msg : ByteArray) (bits : UInt64) : ByteArray :=
  writeBytes
    ((writeBytes (ByteArray.mk (Array.replicate (paddedLength msg.size) 0))
      0 msg.size (fun i => msg[i]!)).set! msg.size 128)
    (paddedLength msg.size-8) 8 (wordByte bits)

theorem padded_eq_padWithBits (msg : ByteArray) :
    padded msg = padWithBits msg (UInt64.ofNat (msg.size*8)) := by
  unfold padded EthLib.Cryptography.Bls.Sha256.padded padWithBits writeBytes paddedLength paddingZeros wordByte
  simp only [Id.run, id_bind, id_pure, Std.Legacy.Range.forIn_eq_forIn_range', forIn_list_yield,
    Std.Legacy.Range.size, Nat.sub_zero, Nat.add_sub_cancel, Nat.div_one, Nat.zero_add]

theorem padWithBits_size (msg : ByteArray) (bits : UInt64) : (padWithBits msg bits).size = paddedLength msg.size := by
  rw [padWithBits, writeBytes_size, set_size, writeBytes_size]
  exact Array.size_replicate

theorem padWithBits_get (msg : ByteArray) (bits : UInt64) (i : Nat) (hi : i < paddedLength msg.size) :
    (padWithBits msg bits)[i]! =
      if i < msg.size then msg[i]!
      else if i = msg.size then 128
      else if paddedLength msg.size-8 ≤ i then wordByte bits (i-(paddedLength msg.size-8))
      else 0 := by
  have hlen : msg.size < paddedLength msg.size-8 := by simp [paddedLength]; omega
  have he : paddedLength msg.size-8+8 = paddedLength msg.size := by simp [paddedLength]
  have hz : (ByteArray.mk (Array.replicate (paddedLength msg.size) 0)).size =
      paddedLength msg.size := Array.size_replicate
  rw [padWithBits, writeBytes_get _ _ _ _ (by
    rw [set_size, writeBytes_size, hz]; omega)]
  by_cases hend : paddedLength msg.size-8 ≤ i
  · rw [if_pos ⟨hend,by omega⟩, if_neg (by omega), if_neg (by omega), if_pos hend]
  · rw [if_neg (by omega), set_get _ _ _ _ (by
      rw [writeBytes_size, hz]; omega),
      writeBytes_get _ _ _ _ (by rw [hz]; omega)]
    by_cases hlt : i < msg.size
    · simp [hlt, show i ≠ msg.size by omega]
    · by_cases heq : i = msg.size
      · simp [heq]
      · simp only [if_neg heq, if_neg hlt, if_neg hend]
        rw [if_neg (by omega), getElem!_pos _ _ (by rw [hz]; exact hi)]
        change (Array.replicate (paddedLength msg.size) (0 : UInt8))[i]'(by simpa only [Array.size_replicate] using hi) = 0
        simp

theorem padded_size (msg : ByteArray) : (padded msg).size = paddedLength msg.size := by
  rw [padded_eq_padWithBits, padWithBits_size]

theorem padded_get (msg : ByteArray) (i : Nat) (hi : i < paddedLength msg.size) :
    (padded msg)[i]! =
      if i < msg.size then msg[i]!
      else if i = msg.size then 128
      else if paddedLength msg.size-8 ≤ i then wordByte (UInt64.ofNat (msg.size*8)) (i-(paddedLength msg.size-8))
      else 0 := by
  rw [padded_eq_padWithBits, padWithBits_get msg _ i hi]

def tailBlocks (n : Nat) : Nat := if n < 56 then 1 else 2

theorem paddedLength_short (n : Nat) (hn : n < 64) :
    paddedLength n = 64*tailBlocks n := by
  unfold paddedLength
  rw [padded_length_eq, Nat.mod_eq_of_lt hn]
  simp [tailBlocks]

theorem paddedLength_prefix (n : Nat) :
    paddedLength n = 64*(n/64)+paddedLength (n%64) := by
  rw [paddedLength_short _ (Nat.mod_lt _ (by decide))]
  unfold paddedLength
  rw [padded_length_eq]
  unfold tailBlocks
  omega

end LeanBlsSimd.Sha256.Spec
