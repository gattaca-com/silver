import LeanBlsSimd.Kzg.Extender.Kernel.Fr8ByteLoad
import LeanBlsSimd.Kzg.Extender.Kernel.Fr8Words
import LeanBlsSimd.Kzg.Extender.Kernel.Fr8Endian
import LeanBlsSimd.Refines.DecompressG2

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel.BytePacking

set_option maxRecDepth 4000
set_option maxHeartbeats 2000000
set_option exponentiation.threshold 1000

def decodedWords (input : Slice U8) (offset : Nat) : Vector UInt64 4 :=
  Vector.ofFn fun k => DecompressG2.u64_from_be_bytes (inputChunk input (offset + 8*(3-k.val)))

theorem inputChunk_toList (input : Slice U8) (start : Nat)
    (h : start+8 ≤ input.val.length) :
    (inputChunk input start).toList = (input.val.map ofU8 |>.drop start |>.take 8) := by
  rw [← slice_to_chunk input start h]
  simp [List.slice, List.map_take, List.map_drop]

theorem decodedWords_value (input : Slice U8) (offset : Usize)
    (hsize : offset.val + 32 ≤ input.val.length) :
    valWords (decodedWords input offset) =
      bytesVal ((input.val.map ofU8).drop offset.val |>.take 32) := by
  let bs := (input.val.map ofU8).drop offset.val |>.take 32
  have hlen : bs.length = 32 := by simp [bs]; omega
  have hw (k : Nat) (hk : k < 4) :
      (decodedWords input offset)[k].toNat = bytesVal ((bs.drop (24-8*k)).take 8) := by
    simp only [decodedWords, Vector.getElem_ofFn, toNat_u64_from_be_bytes]
    rw [inputChunk_toList input _ (by omega)]
    apply congrArg bytesVal
    have he : 8*(3-k) = 24-8*k := by omega
    simp [bs, List.drop_take, List.drop_drop, List.take_take, he]
    omega
  rw [valWords, hw 0 (by decide), hw 1 (by decide), hw 2 (by decide), hw 3 (by decide)]
  have e0 := bytesVal_drop bs 0
  have e8 := bytesVal_drop bs 8
  have e16 := bytesVal_drop bs 16
  have e24 := bytesVal_drop bs 24
  rw [hlen] at e0 e8 e16 e24
  have e32 : bytesVal (bs.drop 32) = 0 := by
    rw [List.drop_eq_nil_of_le (by omega)]
    rfl
  rw [List.drop_zero] at e0
  norm_num at e0 e8 e16 e24 ⊢
  rw [e0, e8, e16, e24, e32]
  ring

theorem bytesBEToNat_eq_bytesVal (b : ByteArray) :
    Fr.bytesBEToNat b = bytesVal b.data.toList := by
  have aux (bs : List UInt8) (acc : Nat) :
      Fr.fromBytesBEAux acc bs = bs.foldl (fun a b => a*256+b.toNat) acc := by
    induction bs generalizing acc with
    | nil => rfl
    | cons b bs ih =>
      simp only [Fr.fromBytesBEAux, List.foldl_cons, shiftLeft_or_byte]
      exact ih _
  exact aux _ _

theorem decodedWords_bytes (input : Slice U8) (offset : Usize)
    (hsize : offset.val + 32 ≤ input.val.length) :
    valWords (decodedWords input offset) =
      Fr.bytesBEToNat ((bytes input.val).extract offset.val (offset.val+32)) := by
  rw [decodedWords_value input offset hsize, bytesBEToNat_eq_bytesVal]
  simp [bytes, ByteArray.data_extract]

def decodedBlocks (input : Slice U8) : Vector M512 4 :=
  Vector.ofFn fun block => Vector.ofFn fun lane =>
    DecompressG2.u64_from_be_bytes (inputChunk input (64*block.val + 8*lane.val))

theorem from_bytes_blocks_refines (input : Slice U8) (hsize : 256 ≤ input.val.length) :
    fr8.u256x8.U256x8.from_bytes_loop { start := 0#usize, «end» := 4#usize } input
      (toArray id (Vector.replicate 4 FrModel.Simd.zero)) =
      ok (toArray id (decodedBlocks input)) := by
  have hm : input.val.length < 2^UScalarTy.Usize.numBits := by
    have hp := input.property
    simp only [Usize.max, Usize.numBits] at hp
    have := Nat.two_pow_pos UScalarTy.Usize.numBits
    omega
  unfold fr8.u256x8.U256x8.from_bytes_loop
  refine loop_range (n := 4) _ 4#usize rfl (toArray id)
    (fun v block => v.set block (decodedBlocks input)[block]) (toArray id)
    (Vector.replicate 4 FrModel.Simd.zero) _ ?_ ?_ ?_
  · intro r m he hs hn
    simp_body fr8.u256x8.U256x8.from_bytes_loop.body hn
  · intro r r' m block he hs he' hs' hn
    have hb : r.start.val < 4 := by rw [hs]; exact block.isLt
    have hplatform := two_pow_32_le_usize
    simp only [UScalarTy.Usize_numBits_eq] at hm hplatform
    simp_body fr8.u256x8.U256x8.from_bytes_loop.body hn
    simp (disch := (simp; omega)) only [usize_mul_ok, UScalar.ofNatCore_val_eq,
      bind_tc_ok, load_block_refines, swap_bytes_refines]
    have hv : (Vector.ofFn fun lane => swapWord (littleBlock input (64*r.start.val))[lane]) =
        (decodedBlocks input)[block] := by
      ext lane hlane
      simp [littleBlock, decodedBlocks, swapWord_from_le_bytes, hs]
    rw [hv, update_eq _ r.start _ (show r.start.val < (4#usize).val from hb)]
    refine congrArg (fun s => ok (cont (r', s))) ?_
    apply Subtype.ext
    simp [hs, List.map_set, Vector.toList_set]
  · simp [decodedBlocks, foldl_set_ofFn]

theorem inputChunk_slice (input : Slice U8) (start size pos : Nat)
    (hpos : pos + 8 ≤ size) :
    inputChunk ⟨input.val.slice start (start+size),
      le_trans (List.slice_length_le _ _ _) input.property⟩ pos =
      inputChunk input (start+pos) := by
  ext i hi
  simp [inputChunk, List.slice, show pos+i < size by omega, Nat.add_assoc]

def decodedVectors (input : Slice U8) (offset : Nat) : Vector M512 4 :=
  Vector.ofFn fun k => Vector.ofFn fun lane => (decodedWords input (offset+32*lane.val))[k]

theorem vector_from_bytes_refines (input : Slice U8) (offset : Usize)
    (hsize : offset.val + 256 ≤ input.val.length) :
    fr8.u256x8.U256x8.from_bytes input offset =
      ok (toArray id (decodedVectors input offset.val)) := by
  have hm : input.val.length < 2^UScalarTy.Usize.numBits := by
    have hp := input.property
    simp only [Usize.max, Usize.numBits] at hp
    have := Nat.two_pow_pos UScalarTy.Usize.numBits
    omega
  let window : Slice U8 := ⟨input.val.slice offset.val (offset.val+256),
    le_trans (List.slice_length_le _ _ _) input.property⟩
  have hw : window.val.length = 256 := by simp [window, List.slice_length]; omega
  simp only [UScalarTy.Usize_numBits_eq] at hm
  unfold fr8.u256x8.U256x8.from_bytes
  simp only [fr8.LANES]
  rw [usize_mul_ok 32#usize 8#usize (by decide)]
  simp only [bind_tc_ok]
  rw [add_ok _ _ (by
    change offset.val + 256 < 2^UScalarTy.Usize.numBits
    simp only [UScalarTy.Usize_numBits_eq]
    omega)]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  rw [slice_index_ok input _ _ (by simp) (by simp; omega)]
  simp only [bind_tc_ok, FrModel.Simd.zero_refines, UScalar.ofNatCore_val_eq,
    fr8.u256x8.WORDS]
  rw [show Array.repeat 4#usize FrModel.Simd.zero =
    toArray id (Vector.replicate 4 FrModel.Simd.zero) by simp [toArray_replicate]]
  change (do
    let b ← fr8.u256x8.U256x8.from_bytes_loop
      { start := 0#usize, «end» := 4#usize } window
      (toArray id (Vector.replicate 4 FrModel.Simd.zero))
    fr8.u256x8.U256x8.from_blocks b) = _
  rw [from_bytes_blocks_refines window (by omega)]
  simp only [bind_tc_ok, from_blocks_refines]
  apply congrArg (fun v : Vector M512 4 =>
    (ok (toArray (n := 4#usize) id v) : Result fr8.u256x8.U256x8))
  ext k hk lane hlane
  simp only [fromBlocks, decodedBlocks, decodedVectors, decodedWords, Vector.getElem_ofFn,
    Fin.getElem_fin]
  rw [inputChunk_slice input offset.val 256 _ (by omega)]
  apply congrArg UInt64.toNat
  apply congrArg DecompressG2.u64_from_be_bytes
  apply congrArg (inputChunk input)
  omega

def decodedLanes (input : Slice U8) (offset : Usize) : Vector (Vector UInt64 5) 8 :=
  Vector.ofFn fun lane => unpack (decodedWords input (offset.val + 32*lane.val))

theorem decodedVectors_lane (input : Slice U8) (offset : Nat) (lane : Fin 8) :
    wordLane (decodedVectors input offset) lane = decodedWords input (offset+32*lane.val) := by
  ext k hk
  simp [wordLane, decodedVectors, laneOf]

theorem raw_mask_spec (out : fr8.Fr8) (hn : Normalized out) :
    let borrow := (FrModel.Simd.sub_limbs (ofArray id out)
      (FrModel.Simd.splat_limbs (.ofList FrModel.P))).2
    ∀ lane : Fin 8, (FrModel.Simd.borrowed borrow).toNat.testBit lane.val =
      decide (laneNat out lane < Fr.modulus) := by
  intro borrow lane
  have hl := FrModel.Simd.sub_limbs_lane (ofArray id out)
    (FrModel.Simd.splat_limbs (.ofList FrModel.P)) lane
  rw [FrModel.Simd.laneOf_splat_limbs] at hl
  have hnormal : ∀ j : Fin FrModel.LIMBS,
      (laneOf (ofArray id out) lane)[j].toNat < 2^52 :=
    (normalized_iff_model out).mp hn lane
  have hb := (FrModel.Lane.sub_limbs_spec hnormal FrModel.normal_ofList_P).2.1
  have hborrow := (congrArg Prod.snd hl).trans hb
  change borrow[lane] = _ at hborrow
  rw [FrModel.Simd.testBit_borrowed, hborrow, FrModel.Lane.decide_borrowOf, FrModel.val_ofList_P,
    laneNat_eq_val]
  rfl

theorem mask_all (mask : U8) :
    mask = 255#u8 ↔ ∀ lane : Fin 8, mask.val.testBit lane.val = true := by
  constructor
  · rintro rfl lane
    fin_cases lane <;> decide
  · intro h
    apply UScalar.eq_of_val_eq
    apply Nat.eq_of_testBit_eq
    intro i
    by_cases hi : i < 8
    · have hh : (255#u8).val.testBit i = true := by interval_cases i <;> decide
      rw [hh]
      exact h ⟨i,hi⟩
    · have hm := mask.hBounds
      have hp : 2^8 ≤ 2^i := Nat.pow_le_pow_right (by decide) (by omega)
      rw [Nat.testBit_eq_false_of_lt (lt_of_lt_of_le hm hp),
        Nat.testBit_eq_false_of_lt (lt_of_lt_of_le (show (255#u8).val < 2^8 by decide) hp)]

theorem decoded_bytes_refinement (input : Slice U8) (offset : Usize)
    (hsize : offset.val + 256 ≤ input.val.length) :
    ∃ out mask, fr8.Fr8.from_bytes input offset = ok (out, mask) ∧ Normalized out ∧
      (∀ lane : Fin 8,
        laneNat out lane = Fr.bytesBEToNat
          ((bytes input.val).extract (offset.val + 32 * lane.val) (offset.val + 32 * (lane.val + 1))) ∧
        (mask.val.testBit lane.val = true ↔ laneNat out lane < Fr.modulus)) ∧
      (mask = 255#u8 ↔ ∀ lane, laneNat out lane < Fr.modulus) := by
  let out := toArray (n := 5#usize) id (transpose (decodedLanes input offset))
  let borrow := (FrModel.Simd.sub_limbs (ofArray id out)
    (FrModel.Simd.splat_limbs (.ofList FrModel.P))).2
  let mask := toU8 (FrModel.Simd.borrowed borrow)
  have hn : Normalized out := by
    intro j lane
    rw [show out = toArray id (transpose (decodedLanes input offset)) from rfl, get_limb_toArray]
    simp only [transpose, decodedLanes, Fin.getElem_fin, Vector.getElem_ofFn]
    exact (unpack_spec _).1 j
  have hm (lane : Fin 8) : mask.val.testBit lane.val = true ↔ laneNat out lane < Fr.modulus := by
    change (FrModel.Simd.borrowed borrow).toNat.testBit lane.val = true ↔ _
    rw [raw_mask_spec out hn]
    exact decide_eq_true_iff
  refine ⟨out, mask, ?_, hn, ?_, ?_⟩
  · simp [fr8.Fr8.from_bytes, vector_from_bytes_refines input offset hsize, vectorUnpack_refines,
      decodedVectors_lane, decodedLanes,
      FrModel.P_refines, FrModel.Simd.splat_limbs_refines, FrModel.Simd.sub_limbs_refines,
      FrModel.Simd.borrowed_refines, out, borrow, mask, Prod.map]
  · intro lane
    refine ⟨?_, hm lane⟩
    rw [show out = toArray id (transpose (decodedLanes input offset)) from rfl, laneNat_transpose]
    simp only [decodedLanes, Fin.getElem_fin, Vector.getElem_ofFn]
    rw [(unpack_spec _).2]
    have hlt : offset.val + 32*lane.val < 2^UScalarTy.Usize.numBits := by
      have hp := input.property
      simp only [Usize.max, Usize.numBits] at hp
      have := lane.isLt
      omega
    let at1 : Usize := UScalar.ofNatCore (offset.val + 32*lane.val) hlt
    have hv := decodedWords_bytes input at1 (by simp only [at1, UScalar.ofNatCore_val_eq]; have := lane.isLt; omega)
    simpa [at1, Nat.mul_add, Nat.add_assoc] using hv
  · rw [mask_all]
    exact forall_congr' hm

end LeanBlsSimd.Kzg.Extender.Kernel.BytePacking
