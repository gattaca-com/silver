import EthLib.Cryptography.Hash.Sha256
import EthLib.Cryptography.Proofs.Hash.Sha256
import Mathlib.Data.List.Basic
import Mathlib.Tactic.NormNum

/-!
The pinned specification's SHA-256 works block by block on `Vector UInt32 8`. Silver's model keeps
the working variables in a `RoundState` and the schedule in an `Array UInt32`, which the generated
code's loops refine. `compressBlock_eq` and `hash_eq` equate the two for every input: the bit
length wraps modulo 2⁶⁴ in both, so neither needs the specification's `size < 2 ^ 61` bound.
-/

namespace LeanBlsSimd.Sha256.Spec

open EthLib.Cryptography

abbrev rotr := Hash.Sha256.rotr
abbrev choose := Hash.Sha256.ch
abbrev majority := Hash.Sha256.maj
abbrev bigSigma0 := Hash.Sha256.bigSigma0
abbrev bigSigma1 := Hash.Sha256.bigSigma1
abbrev smallSigma0 := Hash.Sha256.smallSigma0
abbrev smallSigma1 := Hash.Sha256.smallSigma1
abbrev constants : Array UInt32 := Hash.Sha256.K.toArray
abbrev big32 := Hash.Sha256.big32
def padded : ByteArray → ByteArray := Hash.Sha256.pad

def initialState : Array UInt32 :=
  #[0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

abbrev RoundState := MProd UInt32 (MProd UInt32 (MProd UInt32 (MProd UInt32
  (MProd UInt32 (MProd UInt32 (MProd UInt32 UInt32))))))

def round (k w : UInt32) (s : RoundState) : RoundState :=
  let a := s.1; let b := s.2.1; let c := s.2.2.1; let d := s.2.2.2.1
  let e := s.2.2.2.2.1; let f := s.2.2.2.2.2.1
  let g := s.2.2.2.2.2.2.1; let h := s.2.2.2.2.2.2.2
  let t1 := h + bigSigma1 e + choose e f g + k + w
  let t2 := bigSigma0 a + majority a b c
  ⟨t1+t2,a,b,c,d+t1,e,f,g⟩

def scheduleStep (w : Array UInt32) (t : Nat) : Array UInt32 :=
  w.set! t (w[t-16]! + smallSigma0 w[t-15]! + w[t-7]! + smallSigma1 w[t-2]!)

def schedule (buf : ByteArray) (off : Nat) : Array UInt32 :=
  (List.range' 16 48).foldl scheduleStep
    ((List.range' 0 16).foldl (fun w t => w.set! t (big32 buf (off+4*t)))
      (Array.replicate 64 0))

def rounds (w : Array UInt32) (start count : Nat) (s : RoundState) : RoundState :=
  (List.range' start count).foldl (fun s t => round constants[t]! w[t]! s) s

def stateWords (state : Array UInt32) : RoundState :=
  ⟨state[0]!,state[1]!,state[2]!,state[3]!,state[4]!,state[5]!,state[6]!,state[7]!⟩

def feedForward (state : Array UInt32) (s : RoundState) : Array UInt32 :=
  let ⟨a,b,c,d,e,f,g,h⟩ := s
  #[state[0]!+a,state[1]!+b,state[2]!+c,state[3]!+d,
    state[4]!+e,state[5]!+f,state[6]!+g,state[7]!+h]

def stateVector (state : Array UInt32) : Vector UInt32 8 :=
  #v[state[0]!,state[1]!,state[2]!,state[3]!,state[4]!,state[5]!,state[6]!,state[7]!]

def vectorWords (v : Vector UInt32 8) : RoundState :=
  ⟨v[0],v[1],v[2],v[3],v[4],v[5],v[6],v[7]⟩

def compressBlock (state : Array UInt32) (buf : ByteArray) (off : Nat) : Array UInt32 :=
  (Hash.Sha256.compress (stateVector state) buf off).toArray

def fill (f : Array UInt32 → Nat → UInt32) (w : Array UInt32) (start count : Nat) : Array UInt32 :=
  (List.range' start count).foldl (fun w i => w.set! i (f w i)) w

@[simp] theorem fill_size (f : Array UInt32 → Nat → UInt32) (w : Array UInt32) (start count : Nat) :
    (fill f w start count).size = w.size := by
  induction count generalizing w start with
  | zero => rfl
  | succ n ih => simpa only [fill,List.range',List.foldl_cons,Array.set!_eq_setIfInBounds,
      Array.size_setIfInBounds] using ih (w.set! start (f w start)) (start+1)

theorem read_set (w : Array UInt32) (i j : Nat) (x : UInt32) (hj : j < w.size) :
    (w.set! i x)[j]! = if i=j then x else w[j]! := by
  rw [getElem!_pos (w.set! i x) j (by simpa using hj),getElem!_pos w j hj]
  simp only [Array.set!_eq_setIfInBounds,Array.getElem_setIfInBounds hj]

theorem fill_before (f : Array UInt32 → Nat → UInt32) (w : Array UInt32) (start count i : Nat)
    (hi : i < start) (hw : i < w.size) : (fill f w start count)[i]! = w[i]! := by
  induction count generalizing w start with
  | zero => rfl
  | succ n ih =>
    change (fill f (w.set! start (f w start)) (start+1) n)[i]! = _
    rw [ih _ _ (by omega) (by simpa using hw),read_set _ _ _ _ hw,ite_eq_right (by omega)]

theorem fill_split (f : Array UInt32 → Nat → UInt32) (w : Array UInt32) (start m n : Nat) :
    fill f w start (m+n) = fill f (fill f w start m) (start+m) n := by
  simp only [fill,← List.range'_append,Nat.one_mul,List.foldl_append]

theorem fill_current (f : Array UInt32 → Nat → UInt32) (w : Array UInt32) (start count : Nat)
    (hc : 0 < count) (hw : start < w.size) : (fill f w start count)[start]! = f w start := by
  obtain ⟨n,rfl⟩ := Nat.exists_eq_succ_of_ne_zero (by omega : count ≠ 0)
  change (fill f (w.set! start (f w start)) (start+1) n)[start]! = _
  rw [fill_before _ _ _ _ _ (by omega) (by simpa using hw),read_set _ _ _ _ hw,ite_eq_left rfl]

def scheduleValue (w : Array UInt32) (t : Nat) : UInt32 :=
  w[t-16]! + smallSigma0 w[t-15]! + w[t-7]! + smallSigma1 w[t-2]!

def loaded (buf : ByteArray) (off : Nat) : Array UInt32 :=
  fill (fun _ t => big32 buf (off+4*t)) (Array.replicate 64 0) 0 16

theorem schedule_eq_fill (buf : ByteArray) (off : Nat) :
    schedule buf off = fill scheduleValue (loaded buf off) 16 48 := rfl

@[simp] theorem loaded_size (buf : ByteArray) (off : Nat) : (loaded buf off).size = 64 := by
  simp [loaded]

@[simp] theorem schedule_size (buf : ByteArray) (off : Nat) : (schedule buf off).size = 64 := by
  rw [schedule_eq_fill]; simp

theorem loaded_get (buf : ByteArray) (off i : Nat) (hi : i < 16) :
    (loaded buf off)[i]! = big32 buf (off+4*i) := by
  unfold loaded
  rw [show 16 = i+(16-i) by omega,fill_split]
  simpa only [Nat.zero_add] using fill_current
    (fun _ t => big32 buf (off+4*t))
    (fill (fun _ t => big32 buf (off+4*t)) (Array.replicate 64 0) 0 i)
    i (16-i) (by omega) (by simp; omega)

theorem schedule_get_initial (buf : ByteArray) (off i : Nat) (hi : i < 16) :
    (schedule buf off)[i]! = big32 buf (off+4*i) := by
  rw [schedule_eq_fill,fill_before _ _ _ _ _ hi (by simp; omega),loaded_get _ _ _ hi]

theorem schedule_get_recurrence (buf : ByteArray) (off t : Nat) (hlo : 16 ≤ t) (hi : t < 64) :
    (schedule buf off)[t]! = scheduleValue (schedule buf off) t := by
  let pre := fill scheduleValue (loaded buf off) 16 (t-16)
  have hp : pre.size = 64 := by simp [pre]
  have hs : schedule buf off = fill scheduleValue pre t (64-t) := by
    rw [schedule_eq_fill,show 48 = (t-16)+(64-t) by omega,fill_split]
    simp only [show 16+(t-16)=t by omega]
    rfl
  rw [hs,fill_current _ _ _ _ (by omega) (by omega)]
  unfold scheduleValue
  simp (disch := omega) only [fill_before]

theorem schedule_get_spec (buf : ByteArray) (off t : Nat) (ht : t < 64) :
    (Hash.Sha256.schedule buf off)[t] = (schedule buf off)[t]! := by
  induction t using Nat.strongRecOn with
  | ind t ih =>
    by_cases hlo : t < 16
    · rw [Hash.Sha256.schedule_input buf off t hlo, schedule_get_initial buf off t hlo]
    · rw [Hash.Sha256.schedule_recurrence buf off t (by omega) ht,
        schedule_get_recurrence buf off t (by omega) ht, scheduleValue,
        ih (t-16) (by omega) (by omega), ih (t-15) (by omega) (by omega),
        ih (t-7) (by omega) (by omega), ih (t-2) (by omega) (by omega)]

theorem compressBlock_eq (state : Array UInt32) (buf : ByteArray) (off : Nat) :
    compressBlock state buf off =
      feedForward state (rounds (schedule buf off) 0 64 (stateWords state)) := by
  have hround (v : Vector UInt32 8) (k w : UInt32) :
      vectorWords (Hash.Sha256.round v k w) = round k w (vectorWords v) := by
    simp [Hash.Sha256.round, round, vectorWords]
  have hfold (l : List (Fin 64)) (v : Vector UInt32 8) :
      vectorWords (l.foldl (fun current t =>
          Hash.Sha256.round current Hash.Sha256.K[t] (Hash.Sha256.schedule buf off)[t]) v) =
        (l.map Fin.val).foldl (fun s t => round constants[t]! (schedule buf off)[t]! s)
          (vectorWords v) := by
    induction l generalizing v with
    | nil => rfl
    | cons t l ih =>
      have hk : Hash.Sha256.K[t] = constants[t.val]! := by
        rw [getElem!_pos constants t.val (by simp)]
        simp
      rw [List.foldl_cons, ih, hround, hk]
      simp only [Fin.getElem_fin]
      rw [schedule_get_spec buf off t t.isLt]
      rfl
  have hworking := hfold (List.finRange 64) (stateVector state)
  rw [show (List.finRange 64).map Fin.val = List.range' 0 64 from
    List.ext_getElem (by simp) (by simp)] at hworking
  unfold compressBlock Hash.Sha256.compress
  dsimp only
  rw [show stateWords state = vectorWords (stateVector state) from rfl, rounds, ← hworking]
  generalize List.foldl (fun current t =>
    Hash.Sha256.round current Hash.Sha256.K[t] (Hash.Sha256.schedule buf off)[t])
    (stateVector state) (List.finRange 64) = working
  apply Array.ext
  · simp [feedForward]
  · intro i h1 h2
    simp only [Vector.size_toArray] at h1
    rcases i with _|_|_|_|_|_|_|_|i <;> simp [feedForward, vectorWords, stateVector]
    omega

def compressBlocks (state : Array UInt32) (buf : ByteArray) (off blocks : Nat) : Array UInt32 :=
  (List.range' off blocks 64).foldl (fun s i => compressBlock s buf i) state

def digest (state : Array UInt32) : ByteArray := Hash.Sha256.digest (stateVector state)

theorem stateVector_toArray (v : Vector UInt32 8) : stateVector v.toArray = v := by
  ext i hi
  rcases i with _|_|_|_|_|_|_|_|i <;> simp [stateVector]
  omega

theorem compressBlocks_spec (buf : ByteArray) (v : Vector UInt32 8) (n : Nat) :
    compressBlocks v.toArray buf 0 n =
      ((List.range n).foldl (fun state i => Hash.Sha256.compress state buf (64 * i)) v).toArray := by
  induction n with
  | zero => rfl
  | succ n ih =>
    rw [compressBlocks, List.range'_concat, List.foldl_append, ← compressBlocks, ih,
      List.range_succ, List.foldl_append]
    simp [compressBlock, stateVector_toArray]

theorem hash_eq (msg : ByteArray) :
    Hash.sha256 msg = digest (compressBlocks initialState (padded msg) 0
      (((padded msg).size+63)/64)) := by
  have hblocks : ((padded msg).size+63)/64 = (padded msg).size/64 := by
    have := Hash.Sha256.pad_size_mod msg
    unfold padded
    omega
  rw [hblocks, show initialState = Hash.Sha256.IV.toArray from rfl, compressBlocks_spec]
  simp only [Hash.sha256, Hash.Sha256.hash, digest, stateVector_toArray, padded]

theorem compressBlocks_append (s : Array UInt32) (b : ByteArray) (off m n : Nat) :
    compressBlocks s b off (m+n) =
      compressBlocks (compressBlocks s b off m) b (off+64*m) n := by
  simp only [compressBlocks, ← List.range'_append, List.foldl_append]

theorem rounds_append (w : Array UInt32) (s : RoundState) (off m n : Nat) :
    rounds w off (m+n) s = rounds w (off+m) n (rounds w off m s) := by
  simpa only [rounds, Nat.one_mul, List.foldl_append] using
    congrArg (List.foldl (fun s t => round constants[t]! w[t]! s) s)
      (@List.range'_append off m n 1).symm

def paddingZeros (n : Nat) : Nat := (120 - ((n+1)%64))%64

theorem paddingZeros_eq (n : Nat) :
    paddingZeros n = if n%64 < 56 then 55-n%64 else 119-n%64 := by
  unfold paddingZeros
  have hn := Nat.mod_lt n (by decide : 0 < 64)
  have hnext : (n+1)%64 = (n%64+1)%64 := by omega
  rw [hnext]
  split <;> omega

theorem padded_length_eq (n : Nat) :
    n+1+paddingZeros n+8 = n-n%64 + 64*(if n%64 < 56 then 1 else 2) := by
  rw [paddingZeros_eq]
  have hn := Nat.mod_lt n (by decide : 0 < 64)
  have hle := Nat.mod_le n 64
  split <;> omega

theorem bitLength_eq (n : Nat) :
    (UInt64.ofNat n <<< (3 : UInt64)) = UInt64.ofNat (n*8) := by
  apply UInt64.toBitVec_inj.mp
  simp only [UInt64.toBitVec_shiftLeft, UInt64.toBitVec_ofNat]
  change BitVec.ofNat 64 n <<< 3 = BitVec.ofNat 64 (n*8)
  rw [BitVec.shiftLeft_eq_mul_twoPow]
  exact (BitVec.ofNat_mul n 8).symm

end LeanBlsSimd.Sha256.Spec
