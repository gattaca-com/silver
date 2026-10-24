import EthLib.Cryptography.Bls.Sha256
import EthLib.Cryptography.Proofs.IdLoops

open private EthLib.Cryptography.Bls.Sha256.rotr
  EthLib.Cryptography.Bls.Sha256.ch EthLib.Cryptography.Bls.Sha256.maj
  EthLib.Cryptography.Bls.Sha256.bigSigma0 EthLib.Cryptography.Bls.Sha256.bigSigma1
  EthLib.Cryptography.Bls.Sha256.smallSigma0 EthLib.Cryptography.Bls.Sha256.smallSigma1
  EthLib.Cryptography.Bls.Sha256.K EthLib.Cryptography.Bls.Sha256.big32
  EthLib.Cryptography.Bls.Sha256.compressBlock EthLib.Cryptography.Bls.Sha256.padded
  from EthLib.Cryptography.Bls.Sha256

namespace LeanBlsSimd.Sha256.Spec

open EthLib.Cryptography IdLoops

abbrev rotr := EthLib.Cryptography.Bls.Sha256.rotr
abbrev choose := EthLib.Cryptography.Bls.Sha256.ch
abbrev majority := EthLib.Cryptography.Bls.Sha256.maj
abbrev bigSigma0 := EthLib.Cryptography.Bls.Sha256.bigSigma0
abbrev bigSigma1 := EthLib.Cryptography.Bls.Sha256.bigSigma1
abbrev smallSigma0 := EthLib.Cryptography.Bls.Sha256.smallSigma0
abbrev smallSigma1 := EthLib.Cryptography.Bls.Sha256.smallSigma1
abbrev constants := EthLib.Cryptography.Bls.Sha256.K
abbrev big32 := EthLib.Cryptography.Bls.Sha256.big32
def compressBlock : Array UInt32 → ByteArray → Nat → Array UInt32 := EthLib.Cryptography.Bls.Sha256.compressBlock
def padded : ByteArray → ByteArray := EthLib.Cryptography.Bls.Sha256.padded

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

theorem compressBlock_eq (state : Array UInt32) (buf : ByteArray) (off : Nat) :
    compressBlock state buf off =
      feedForward state (rounds (schedule buf off) 0 64 (stateWords state)) := by
  unfold compressBlock EthLib.Cryptography.Bls.Sha256.compressBlock
  unfold feedForward rounds schedule stateWords round scheduleStep
  simp only [Id.run, id_bind, id_pure, Std.Legacy.Range.forIn_eq_forIn_range', forIn_list_yield]
  simp only [big32, smallSigma0, smallSigma1, bigSigma0, bigSigma1, choose, majority, constants]
  norm_num only [Std.Legacy.Range.size]

def compressBlocks (state : Array UInt32) (buf : ByteArray) (off blocks : Nat) : Array UInt32 :=
  (List.range' off blocks 64).foldl (fun s i => compressBlock s buf i) state

def digest (state : Array UInt32) : ByteArray :=
  (List.range' 0 8).foldl (fun out i =>
    let h := state[i]!
    (((out.set! (4*i) (UInt8.ofNat ((h >>> 24).toNat))).set!
      (4*i+1) (UInt8.ofNat ((h >>> 16).toNat &&& 0xff))).set!
      (4*i+2) (UInt8.ofNat ((h >>> 8).toNat &&& 0xff))).set!
      (4*i+3) (UInt8.ofNat (h.toNat &&& 0xff)))
    (ByteArray.mk (Array.replicate 32 0))

theorem hash_eq (msg : ByteArray) :
    Bls.sha256 msg = digest (compressBlocks initialState (padded msg) 0
      (((padded msg).size+63)/64)) := by
  unfold Bls.sha256 Bls.Sha256.hash
  simp only [Id.run, id_bind, id_pure, Std.Legacy.Range.forIn_eq_forIn_range', forIn_list_yield]
  rfl

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
