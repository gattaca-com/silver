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
    change (b.data.setIfInBounds j v)[i]'(by rw [Array.size_setIfInBounds]; exact hi) =
      if i=j then v else b.data[i]
    by_cases he : i=j
    · subst i
      simp
    · simp only [ite_eq_right he]
      exact Array.getElem_setIfInBounds_ne hi (fun hh => he hh.symm)
  · rw [getElem!_neg _ _ (by rw [set_size]; exact hi), getElem!_neg b i hi,
      ite_eq_right (show i ≠ j by omega)]

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
    · simp only [ite_eq_right he]
      by_cases hin : start ≤ i ∧ i < start+n
      · rw [ite_eq_left hin, ite_eq_left (show start ≤ i ∧ i < start+(n+1) by omega)]
      · rw [ite_eq_right hin, ite_eq_right (show ¬ (start ≤ i ∧ i < start+(n+1)) by omega)]

open EthLib.Cryptography

def paddedLength (n : Nat) : Nat := n+1+paddingZeros n+8

def wordByte (bits : UInt64) (i : Nat) : UInt8 :=
  UInt8.ofNat ((bits >>> UInt64.ofNat ((7-i)*8)).toNat)

def padWithBits (msg : ByteArray) (bits : UInt64) : ByteArray :=
  writeBytes
    ((writeBytes (ByteArray.mk (Array.replicate (paddedLength msg.size) 0))
      0 msg.size (fun i => msg[i]!)).set! msg.size 128)
    (paddedLength msg.size-8) 8 (wordByte bits)

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
  · rw [ite_eq_left ⟨hend,by omega⟩, ite_eq_right (by omega), ite_eq_right (by omega), ite_eq_left hend]
  · rw [ite_eq_right (by omega), set_get _ _ _ _ (by
      rw [writeBytes_size, hz]; omega),
      writeBytes_get _ _ _ _ (by rw [hz]; omega)]
    by_cases hlt : i < msg.size
    · simp [hlt, show i ≠ msg.size by omega]
    · by_cases heq : i = msg.size
      · simp [heq]
      · simp only [ite_eq_right heq, ite_eq_right hlt, ite_eq_right hend]
        rw [ite_eq_right (by omega), getElem!_pos _ _ (by rw [hz]; exact hi)]
        change (Array.replicate (paddedLength msg.size) (0 : UInt8))[i]'(by simpa only [Array.size_replicate] using hi) = 0
        simp

theorem paddingZeros_spec (n : Nat) : Hash.Sha256.paddingZeros n = paddingZeros n := by
  unfold Hash.Sha256.paddingZeros paddingZeros
  omega

theorem padded_size (msg : ByteArray) : (padded msg).size = paddedLength msg.size := by
  rw [padded, Hash.Sha256.pad_size, paddingZeros_spec]
  rfl

/-- The specification multiplies the wrapped byte count by 8; silver wraps the bit count. Both are
the bit count modulo 2⁶⁴. -/
theorem lengthBytes_get (size j : Nat) (hj : j < 8) :
    (Hash.Sha256.lengthBytes size)[j]'(by simpa using hj) = wordByte (UInt64.ofNat (size*8)) j := by
  simp only [Hash.Sha256.lengthBytes, ByteArray.getElem_eq_getElem_data, Array.getElem_ofFn,
    wordByte, UInt64.ofNat_mul]
  generalize UInt64.ofNat size = x
  rcases j with _|_|_|_|_|_|_|_|j <;> first | rfl | omega

theorem padded_get (msg : ByteArray) (i : Nat) (hi : i < paddedLength msg.size) :
    (padded msg)[i]! =
      if i < msg.size then msg[i]!
      else if i = msg.size then 128
      else if paddedLength msg.size-8 ≤ i then wordByte (UInt64.ofNat (msg.size*8)) (i-(paddedLength msg.size-8))
      else 0 := by
  have hs := padded_size msg
  rw [getElem!_pos (padded msg) i (by omega)]
  unfold padded
  split_ifs with hmsg hdelim hlen
  · rw [getElem!_pos msg i hmsg]
    exact Hash.Sha256.pad_prefix msg i hmsg
  · subst hdelim
    exact Hash.Sha256.pad_delimiter msg
  · obtain ⟨j, rfl⟩ : ∃ j, i = paddedLength msg.size - 8 + j :=
      ⟨i - (paddedLength msg.size - 8), by omega⟩
    have hz := paddingZeros_spec msg.size
    have hzeros : (ByteArray.mk (Array.replicate (Hash.Sha256.paddingZeros msg.size) 0)).size =
        Hash.Sha256.paddingZeros msg.size := Array.size_replicate
    have hj : j < 8 := by unfold paddedLength at *; omega
    unfold Hash.Sha256.pad
    rw [ByteArray.getElem_append_right (by
      simp only [ByteArray.size_append, ByteArray.size_push, hzeros]
      unfold paddedLength at *
      omega)]
    have hidx : paddedLength msg.size - 8 + j - (msg.push 0x80 ++
        ByteArray.mk (Array.replicate (Hash.Sha256.paddingZeros msg.size) 0)).size = j := by
      simp only [ByteArray.size_append, ByteArray.size_push, hzeros]
      unfold paddedLength
      omega
    simp only [hidx, Nat.add_sub_cancel_left]
    exact lengthBytes_get msg.size j hj
  · obtain ⟨k, rfl⟩ : ∃ k, i = msg.size + 1 + k := ⟨i - msg.size - 1, by omega⟩
    exact Hash.Sha256.pad_zero msg k (by rw [paddingZeros_spec]; unfold paddedLength at *; omega)

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
