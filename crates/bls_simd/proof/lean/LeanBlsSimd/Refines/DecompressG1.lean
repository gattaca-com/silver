import LeanBlsSimd.Refines.G1x8
import LeanBlsSimd.Model.DecompressG1

open Aeneas Aeneas.Std Result ControlFlow
open silver_bls_simd

namespace LeanBlsSimd
namespace DecompressG1

open DecompressG2 (FLAG_COMPRESSED FLAG_INFINITY FLAG_LARGER_ROOT fp_words less_than_p
  FLAG_COMPRESSED_refines FLAG_INFINITY_refines FLAG_LARGER_ROOT_refines fp_words_refines
  less_than_p_refines)

def ofBlstP1Affine (a : blst.blst_p1_affine) : BlstP1Affine :=
  ⟨DecompressG2.ofBlstFp a.x, DecompressG2.ofBlstFp a.y⟩

def toBlstP1Affine (p : BlstP1Affine) : blst.blst_p1_affine :=
  ⟨DecompressG2.toBlstFp p.x, DecompressG2.toBlstFp p.y⟩

def toDecoded (d : Decoded) : decompress.Decoded :=
  ⟨toArray (toArray toU64) d.x, toU8 d.larger_root, toU8 d.invalid, toU8 d.undecided⟩

def ofBatch (b : decompress.Batch) : Batch :=
  ⟨ofArray ofBlstP1Affine b.points, ofU8 b.valid, ofU8 b.undecided⟩

def toBatch (b : Batch) : decompress.Batch :=
  ⟨toArray toBlstP1Affine b.points, toU8 b.valid, toU8 b.undecided⟩

@[simp] theorem ofBlstP1Affine_toBlstP1Affine (p : BlstP1Affine) :
    ofBlstP1Affine (toBlstP1Affine p) = p := by
  simp [ofBlstP1Affine, toBlstP1Affine]

@[simp] theorem toBlstP1Affine_ofBlstP1Affine (p : blst.blst_p1_affine) :
    toBlstP1Affine (ofBlstP1Affine p) = p := by
  simp [ofBlstP1Affine, toBlstP1Affine]

@[simp] theorem ofBatch_toBatch (b : Batch) : ofBatch (toBatch b) = b := by
  simp [ofBatch, toBatch]

@[simp] theorem toBatch_ofBatch (b : decompress.Batch) : toBatch (ofBatch b) = b := by
  simp [ofBatch, toBatch]

def decodeState (d : Decoded) : Array (Array U64 8#usize) 8#usize × U8 × U8 × U8 :=
  (toArray (toArray toU64) d.x, toU8 d.larger_root, toU8 d.invalid, toU8 d.undecided)

theorem ofSlice_toArray (b : Encoding) (h : (toArray toU8 b (n := 48#usize)).val.length = 48) :
    ofSlice ofU8 (Array.to_slice (toArray toU8 b (n := 48#usize))) h = b := by
  ext i hi
  simp [Array.to_slice]

theorem decode_loop_refines (inputs : Array (Array U8 48#usize) 8#usize) :
    decompress.decode_loop { start := 0#usize, «end» := fp8.LANES } inputs
        (decodeState decodeInit).1 (decodeState decodeInit).2.1
        (decodeState decodeInit).2.2.1 (decodeState decodeInit).2.2.2 =
      ok (decodeState (decode (ofArray (ofArray ofU8) inputs))) := by
  obtain ⟨IN, rfl⟩ : ∃ IN : Vector Encoding 8, inputs = toArray (toArray toU8) IN :=
    ⟨ofArray (ofArray ofU8) inputs, (toArray_ofArray (by simp) inputs _ _).symm⟩
  unfold decompress.decode_loop
  rw [LANES_refines, decode, ofArray_toArray (by simp)]
  refine loop_range (n := 8) _ 8#usize rfl decodeState (decodeStep IN) decodeState decodeInit _
    ?_ ?_ rfl
  · intro r m he hs hn
    simp_body decompress.decode_loop.body hn
  · intro r r' d lane he hs he' hs' hn
    have hl : r.start.val < 8 := by rw [hs]; exact lane.isLt
    obtain rfl : lane = ⟨r.start.val, hl⟩ := Fin.ext hs.symm
    simp_body decompress.decode_loop.body hn
    simp only [decodeState, bind_tc_ok, toU8_shiftLeft_one _ hl, lift]
    simp (disch := first | omega | decide) only [index_usize_toArray, bind_tc_ok]
    simp only [show ((0#usize).val) = 0 from rfl]
    rw [show (224#u8) = toU8 0xe0 from rfl, show (0#u8) = toU8 0 from rfl,
      FLAG_COMPRESSED_refines, FLAG_INFINITY_refines, FLAG_LARGER_ROOT_refines]
    simp only [toU8_and, toU8_or, toU8_inj, bne_iff_ne, ne_eq]
    unfold decodeStep
    simp only [Fin.getElem_fin]
    by_cases c1 : IN[r.start.val][0] &&& 0xe0 &&& FLAG_COMPRESSED = 0
    · simp only [c1, if_true]
    by_cases c2 : IN[r.start.val][0] &&& 0xe0 &&& FLAG_INFINITY = 0
    swap
    · simp only [c1, c2, if_true, if_false, not_false_eq_true, ne_eq]
    simp only [c1, c2, if_false, not_true_eq_false, ne_eq]
    simp (disch := simp [Array.to_slice, DecompressG2.FP_BYTES,
      DecompressG2.G2_COMPRESSED_LEN]) only [fp_words_refines, bind_tc_ok]
    simp only [DecompressG2.FP_BYTES, DecompressG2.G2_COMPRESSED_LEN, Nat.reduceDiv,
      ofSlice_toArray]
    rw [show (2305843009213693951#u64) = toU64 0x1fffffffffffffff from rfl]
    simp (disch := first | omega | decide | (simp; omega)) only [index_usize_toArray,
      bind_tc_ok, toU64_and, update_eq, set_toArray, less_than_p_refines, unpack52_refines]
    simp only [ofArray_toArray (f := ofU64) (g := toU64) (fun _ => rfl)]
    simp only [show (5#usize).val = 5 from rfl]
    generalize less_than_p ((fp_words IN[r.start.val]).set 5
      ((fp_words IN[r.start.val])[5] &&& 0x1fffffffffffffff)) = b
    by_cases c3 : IN[r.start.val][0] &&& 0xe0 &&& FLAG_LARGER_ROOT = 0 <;>
      cases b <;> simp [c3]

theorem decode_refines (inputs : Array (Array U8 48#usize) 8#usize) :
    decompress.decode inputs = ok (toDecoded (decode (ofArray (ofArray ofU8) inputs))) := by
  unfold decompress.decode
  change (do
    let (a, i, i1, i2) ← decompress.decode_loop { start := 0#usize, «end» := fp8.LANES }
      inputs (decodeState decodeInit).1 (decodeState decodeInit).2.1
      (decodeState decodeInit).2.2.1 (decodeState decodeInit).2.2.2
    ok ({ x := a, larger_root := i, invalid := i1, undecided := i2 } : decompress.Decoded)) = _
  rw [decode_loop_refines]
  rfl

theorem point_refines (x y : Array U64 6#usize) :
    decompress.point x y = ok (toBlstP1Affine (point (ofArray ofU64 x) (ofArray ofU64 y))) := by
  simp [decompress.point, point, toBlstP1Affine, DecompressG2.toBlstFp]

theorem default_refines :
    blst.blst_p1_affine.Insts.CoreDefaultDefault.default = ok (toBlstP1Affine default) := rfl

theorem decompress_loop_refines (xs ys : Array (Array U64 6#usize) 8#usize)
    (a : Array blst.blst_p1_affine 8#usize) :
    decompress.decompress_loop { start := 0#usize, «end» := fp8.LANES } xs ys a =
      ok (toArray toBlstP1Affine (.ofFn fun lane : Fin 8 =>
        point (ofArray (ofArray ofU64) xs (m := 8))[lane]
          (ofArray (ofArray ofU64) ys (m := 8))[lane])) := by
  obtain ⟨A, rfl⟩ : ∃ A : Vector BlstP1Affine 8, a = toArray toBlstP1Affine A :=
    ⟨ofArray ofBlstP1Affine a, (toArray_ofArray (by simp) a _ _).symm⟩
  unfold decompress.decompress_loop
  rw [LANES_refines]
  refine loop_range (n := 8) _ 8#usize rfl (toArray toBlstP1Affine)
    (fun v (lane : Fin 8) => v.set lane
      (point (ofArray (ofArray ofU64) xs (m := 8))[lane]
        (ofArray (ofArray ofU64) ys (m := 8))[lane]))
    (toArray toBlstP1Affine) A _ ?_ ?_ ?_
  · intro r m he hs hn
    simp_body decompress.decompress_loop.body hn
  · intro r r' m lane he hs he' hs' hn
    have hl : r.start.val < (8#usize).val := by rw [hs]; exact lane.isLt
    simp_body decompress.decompress_loop.body hn
    simp only [index_usize_eq _ _ hl, bind_tc_ok, point_refines, update_eq _ _ _ hl]
    refine congrArg (fun s => ok (cont (r', s))) ?_
    apply Subtype.ext
    simp [hs, List.map_set, Vector.toList_set]
  · simp [foldl_set_ofFn]

theorem decompress_refines (inputs : Array (Array U8 48#usize) 8#usize) :
    silver_bls_simd.decompress.decompress inputs =
      ok (toBatch (decompress (ofArray (ofArray ofU8) inputs))) := by
  unfold silver_bls_simd.decompress.decompress decompress
  simp only [decode_refines, bind_tc_ok]
  generalize decode (ofArray (ofArray ofU8) inputs) = D
  simp only [toDecoded, Fp8.from_plain_refines, bind_tc_ok,
    ofArray_toArray_ofArray_ofU64]
  generalize Fp8.from_plain D.x = X
  simp only [Fp8.square_refines, Fp8.mul_refines, Fp8.splat_limbs_refines,
    FOUR_MONT_refines, Fp8.add_refines, bind_tc_ok, ofFp8_toFp8, ofArray_toArray_ofU64]
  generalize (X.square.mul X).add (Fp8.splat_limbs (.ofList FOUR_MONT)) = RHS
  simp only [Fp8.sqrt_candidate_refines, bind_tc_ok, ofFp8_toFp8]
  generalize RHS.sqrt_candidate = root
  simp only [Fp8.eq_mask_refines, Fp8.is_larger_root_mask_refines,
    Fp8.neg_refines, Fp8.select_refines, bind_tc_ok, ofFp8_toFp8, lift, toU8_xor, ofU8_toU8]
  generalize Fp8.select (root.is_larger_root_mask ^^^ D.larger_root) root root.neg = Y
  simp only [Fp8.is_zero_mask_refines, G1x8.scott_membership_refines,
    bind_tc_ok, ofFp8_toFp8]
  generalize G1x8.scott_membership X Y = M
  simp only [Fp8.to_blst_limbs_refines, bind_tc_ok, ofFp8_toFp8, toMembership,
    toU8_and, toU8_or, toU8_not, default_refines, decompress_loop_refines,
    ofArray_toArray_ofArray_ofU64, toBatch, foldl_set_ofFn]

end DecompressG1

end LeanBlsSimd
