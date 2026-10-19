import LeanBlsSimd.Kzg.Extender.Kernel.Fr8Bytes
import LeanBlsSimd.Refines.DecompressG2

open Aeneas Aeneas.Std Result ControlFlow
open EthCryptographySpecs Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel.BytePacking

set_option maxRecDepth 4000
set_option maxHeartbeats 2000000
set_option exponentiation.threshold 1000

def inputChunk (input : Slice U8) (start : Nat) : Vector UInt8 8 :=
  Vector.ofFn fun i => ofU8 input.val[start + i.val]!

def decodedWords (input : Slice U8) (offset : Nat) : Vector UInt64 4 :=
  Vector.ofFn fun k => DecompressG2.u64_from_be_bytes (inputChunk input (offset + 8*(3-k.val)))

theorem slice_to_chunk (input : Slice U8) (start : Nat) (h : start + 8 ≤ input.val.length) :
    (input.val.slice start (start+8)).map ofU8 = (inputChunk input start).toList := by
  apply List.ext_getElem
  · simp [List.slice_length]
    omega
  · intro i hi hi'
    have hi8 : i < 8 := by simpa using hi'
    simp [inputChunk, List.slice, show start+i < input.val.length by omega]

theorem words_from_bytes_refines (input : Slice U8) (offset : Usize)
    (hsize : offset.val + 32 ≤ input.val.length) :
    fr8.words_from_bytes input offset = ok (toArray toU64 (decodedWords input offset)) := by
  unfold fr8.words_from_bytes fr8.words_from_bytes_loop
  have hm : input.val.length < 2^UScalarTy.Usize.numBits := by
    have hp := input.property
    simp only [Usize.max, Usize.numBits] at hp
    have := Nat.two_pow_pos UScalarTy.Usize.numBits
    omega
  simp only [UScalarTy.Usize_numBits_eq] at hm
  let chunk (k : Fin 4) := inputChunk input (offset.val + 8*k.val)
  let step (s : Vector UInt64 4 × Vector UInt8 8) (k : Fin 4) :=
    (s.1.set (3-k.val) (DecompressG2.u64_from_be_bytes (chunk k)) (by omega), chunk k)
  rw [show Array.repeat 4#usize 0#u64 = toArray toU64 (Vector.replicate 4 0) by
    simp [toArray_replicate]; rfl]
  rw [show Array.repeat 8#usize 0#u8 = toArray toU8 (Vector.replicate 8 0) by
    simp [toArray_replicate]; rfl]
  refine loop_range (n := 4) _ 4#usize rfl
    (fun s : Vector UInt64 4 × Vector UInt8 8 => (toArray toU64 s.1, toArray toU8 s.2))
    step (fun s => toArray toU64 s.1) (Vector.replicate 4 0, Vector.replicate 8 0) _ ?_ ?_ ?_
  · intro r m he hs hn
    simp_body fr8.words_from_bytes_loop.body hn
  · intro r r' m k he hs he' hs' hn
    have hplatform := two_pow_32_le_usize
    simp only [UScalarTy.Usize_numBits_eq] at hplatform
    have hk : r.start.val < 4 := by rw [hs]; exact k.isLt
    have hstart : offset.val + 8*r.start.val + 8 ≤ input.val.length := by omega
    simp_body fr8.words_from_bytes_loop.body hn
    simp only [lift, bind_tc_ok, Array.to_slice_mut, Function.uncurry_apply_pair]
    simp (disch := (simp [List.slice_length, Array.to_slice]; omega)) only [usize_mul_ok, add_ok,
      sub_ok, update_eq, bind_tc_ok,
      UScalar.ofNatCore_val_eq]
    have hslen : (input.val.slice (offset.val + 8*r.start.val)
        (offset.val + 8*r.start.val + 8)).length = 8 := by
      rw [List.slice_length]
      omega
    rw [slice_index_ok input _ _ (by simp) (by simp; omega)]
    simp only [bind_tc_ok]
    rw [copy_from_slice_ok _ _ _ (by simp [Array.to_slice, hslen])]
    simp only [bind_tc_ok]
    rw [Array.from_slice, dif_pos (by simpa using hslen)]
    simp only [UScalar.ofNatCore_val_eq]
    have heq : (⟨input.val.slice (offset.val + 8*r.start.val)
        (offset.val + 8*r.start.val + 8), hslen⟩ : Array U8 8#usize) =
        toArray toU8 (chunk k) := by
      apply Subtype.ext
      apply (List.map_injective_iff.mpr (fun a b h => by simpa using congrArg toU8 h) :
        Function.Injective (List.map ofU8))
      simpa [chunk, hs, Function.comp_def] using
        slice_to_chunk input (offset.val + 8*r.start.val) hstart
    rw [heq]
    have hword : core.num.U64.from_be_bytes (toArray toU8 (chunk k)) =
        toU64 (DecompressG2.u64_from_be_bytes (chunk k)) := by
      rw [eq_toU64_iff, DecompressG2.from_be_bytes_refines]
      simp
    rw [hword]
    simp only [step, hs]
    simp (disch := (simp; omega)) only [set_toArray, UScalar.ofNatCore_val_eq]
  · change toArray toU64 ((List.finRange 4).foldl step _).1 = _
    apply congrArg (toArray (n := 4#usize) toU64)
    have hr : List.finRange 4 = [0,1,2,3] := by decide
    rw [hr]
    ext j hj
    interval_cases j <;> simp [step, chunk, decodedWords]

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

def decodedLanes (input : Slice U8) (offset : Usize) : Vector (Vector UInt64 5) 8 :=
  Vector.ofFn fun lane => unpack (decodedWords input (offset.val + 32*lane.val))

theorem from_bytes_loop_refines (input : Slice U8) (offset : Usize)
    (hsize : offset.val + 256 ≤ input.val.length) :
    fr8.Fr8.from_bytes_loop { start := 0#usize, «end» := fr8.LANES } input offset
      (Array.repeat 8#usize (Array.repeat 5#usize 0#u64)) =
      ok (toArray (toArray toU64) (decodedLanes input offset)) := by
  unfold fr8.Fr8.from_bytes_loop
  rw [fr8.LANES]
  rw [show Array.repeat 8#usize (Array.repeat 5#usize 0#u64) =
      toArray (toArray toU64) (Vector.replicate 8 (Vector.replicate 5 0)) by
    simp [toArray_replicate]; rfl]
  have hm : input.val.length < 2^UScalarTy.Usize.numBits := by
    have hp := input.property
    simp only [Usize.max, Usize.numBits] at hp
    have := Nat.two_pow_pos UScalarTy.Usize.numBits
    omega
  simp only [UScalarTy.Usize_numBits_eq] at hm
  refine loop_range (n := 8) _ 8#usize rfl (toArray (toArray toU64))
    (fun v lane => v.set lane (decodedLanes input offset)[lane]) (toArray (toArray toU64))
    (Vector.replicate 8 (Vector.replicate 5 0)) _ ?_ ?_ ?_
  · intro r m he hs hn
    simp_body fr8.Fr8.from_bytes_loop.body hn
  · intro r r' m lane he hs he' hs' hn
    have hl : r.start.val < 8 := by rw [hs]; exact lane.isLt
    have hplatform := two_pow_32_le_usize
    simp only [UScalarTy.Usize_numBits_eq] at hplatform
    simp_body fr8.Fr8.from_bytes_loop.body hn
    simp (disch := (simp; omega)) only [usize_mul_ok, add_ok, UScalar.ofNatCore_val_eq,
      bind_tc_ok, words_from_bytes_refines, unpack_refines, ofArray_toArray_ofU64,
      update_eq _ r.start _ (show r.start.val < (8#usize).val from hl)]
    refine congrArg (fun s => ok (cont (r', s))) ?_
    apply Subtype.ext
    simp [hs, List.map_set, Vector.toList_set, decodedLanes]
  · simp [decodedLanes, foldl_set_ofFn]

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
  · simp [fr8.Fr8.from_bytes, from_bytes_loop_refines input offset hsize, transpose_refines,
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
