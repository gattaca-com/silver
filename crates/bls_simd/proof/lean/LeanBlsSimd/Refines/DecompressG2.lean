import LeanBlsSimd.Refines.G2x8
import LeanBlsSimd.Proofs.DecompressG2

open Aeneas Aeneas.Std Result ControlFlow
open silver_bls_simd

/-!
# `decompress_g2.rs`

The blst and batch types convert field by field. `fp_words` reads a slice, so its theorem assumes
the slice holds `FP_BYTES` bytes.

`decompress_refines` uses `decompress_eq`, which states the model's `decompress` through `xOf`,
`rhsOf` and `tail`; generalising over their applications keeps the terms small. The model writes
`points` in a fold over the batch, the generated loop over the points array alone. Both write
every lane, so each ends in the `Vector.ofFn` of the lane's point.
-/

namespace LeanBlsSimd

namespace DecompressG2

def ofBlstFp (a : blst.blst_fp) : BlstFp := ⟨ofArray ofU64 a.l⟩

def toBlstFp (x : BlstFp) : blst.blst_fp := ⟨toArray toU64 x.l⟩

def ofBlstFp2 (a : blst.blst_fp2) : BlstFp2 := ⟨ofArray ofBlstFp a.fp⟩

def toBlstFp2 (x : BlstFp2) : blst.blst_fp2 := ⟨toArray toBlstFp x.fp⟩

def ofBlstP2Affine (a : blst.blst_p2_affine) : BlstP2Affine := ⟨ofBlstFp2 a.x, ofBlstFp2 a.y⟩

def toBlstP2Affine (x : BlstP2Affine) : blst.blst_p2_affine := ⟨toBlstFp2 x.x, toBlstFp2 x.y⟩

def ofDecoded (a : decompress_g2.Decoded) : Decoded where
  x0 := ofArray (ofArray ofU64) a.x0
  x1 := ofArray (ofArray ofU64) a.x1
  larger_root := ofU8 a.larger_root
  invalid := ofU8 a.invalid
  undecided := ofU8 a.undecided

def toDecoded (d : Decoded) : decompress_g2.Decoded where
  x0 := toArray (toArray toU64) d.x0
  x1 := toArray (toArray toU64) d.x1
  larger_root := toU8 d.larger_root
  invalid := toU8 d.invalid
  undecided := toU8 d.undecided

def ofBatch (a : decompress_g2.Batch) : Batch where
  points := ofArray ofBlstP2Affine a.points
  on_curve := ofU8 a.on_curve
  valid := ofU8 a.valid
  undecided := ofU8 a.undecided

def toBatch (b : Batch) : decompress_g2.Batch where
  points := toArray toBlstP2Affine b.points
  on_curve := toU8 b.on_curve
  valid := toU8 b.valid
  undecided := toU8 b.undecided

@[simp] theorem ofBlstFp_toBlstFp (x : BlstFp) : ofBlstFp (toBlstFp x) = x := by
  simp [ofBlstFp, toBlstFp]

@[simp] theorem toBlstFp_ofBlstFp (a : blst.blst_fp) : toBlstFp (ofBlstFp a) = a := by
  simp [ofBlstFp, toBlstFp]

@[simp] theorem ofBlstFp2_toBlstFp2 (x : BlstFp2) : ofBlstFp2 (toBlstFp2 x) = x := by
  simp [ofBlstFp2, toBlstFp2]

@[simp] theorem toBlstFp2_ofBlstFp2 (a : blst.blst_fp2) : toBlstFp2 (ofBlstFp2 a) = a := by
  simp [ofBlstFp2, toBlstFp2]

@[simp] theorem ofBlstP2Affine_toBlstP2Affine (x : BlstP2Affine) :
    ofBlstP2Affine (toBlstP2Affine x) = x := by
  simp [ofBlstP2Affine, toBlstP2Affine]

@[simp] theorem toBlstP2Affine_ofBlstP2Affine (a : blst.blst_p2_affine) :
    toBlstP2Affine (ofBlstP2Affine a) = a := by
  simp [ofBlstP2Affine, toBlstP2Affine]

@[simp] theorem ofDecoded_toDecoded (d : Decoded) : ofDecoded (toDecoded d) = d := by
  simp [ofDecoded, toDecoded]

@[simp] theorem toDecoded_ofDecoded (a : decompress_g2.Decoded) : toDecoded (ofDecoded a) = a := by
  simp [ofDecoded, toDecoded]

@[simp] theorem ofBatch_toBatch (b : Batch) : ofBatch (toBatch b) = b := by
  simp [ofBatch, toBatch]

@[simp] theorem toBatch_ofBatch (a : decompress_g2.Batch) : toBatch (ofBatch a) = a := by
  simp [ofBatch, toBatch]

theorem FP_BYTES_refines : decompress_g2.FP_BYTES = ok 48#usize := by
  rw [decompress_g2.FP_BYTES, silver_bls_simd.G2_COMPRESSED_LEN]; rfl

theorem FLAG_COMPRESSED_refines : decompress_g2.FLAG_COMPRESSED = toU8 FLAG_COMPRESSED := by
  rw [decompress_g2.FLAG_COMPRESSED]; rfl

theorem FLAG_INFINITY_refines : decompress_g2.FLAG_INFINITY = toU8 FLAG_INFINITY := by
  rw [decompress_g2.FLAG_INFINITY]; rfl

theorem FLAG_LARGER_ROOT_refines : decompress_g2.FLAG_LARGER_ROOT = toU8 FLAG_LARGER_ROOT := by
  rw [decompress_g2.FLAG_LARGER_ROOT]; rfl

theorem point_refines (x0 x1 y0 y1 : Array U64 6#usize) :
    decompress_g2.point x0 x1 y0 y1 = ok (toBlstP2Affine {
      x := { fp := #v[{ l := ofArray ofU64 x0 }, { l := ofArray ofU64 x1 }] },
      y := { fp := #v[{ l := ofArray ofU64 y0 }, { l := ofArray ofU64 y1 }] } }) := by
  simp only [decompress_g2.point, toBlstP2Affine, toBlstFp2, ok.injEq, blst.blst_p2_affine.mk.injEq,
    blst.blst_fp2.mk.injEq]
  constructor <;> (apply Subtype.ext; simp [toBlstFp, Array.make])

theorem less_than_p_loop_refines (x : Array U64 6#usize) (w : ℕ) (hw : w ≤ 6) :
    decompress_g2.less_than_p_loop x
        (UScalar.ofNatCore w (lt_of_lt_of_le (by omega) two_pow_32_le_usize)) =
      ok (((List.range w).reverse.foldl (ltStep (ofArray ofU64 x)) none).getD false) := by
  induction w with
  | zero =>
    rw [decompress_g2.less_than_p_loop, loop.eq_1]
    simp [decompress_g2.less_than_p_loop.body]
  | succ w ih =>
    have hw6 : w < 6 := by omega
    have hx : (ofArray ofU64 x : Vector UInt64 6)[w]! =
        ofU64 (x.val[w]'(by simp [x.property]; omega)) := by
      rw [getElem!_pos _ w hw6]; simp
    have hbody : decompress_g2.less_than_p_loop.body x
        (UScalar.ofNatCore (w + 1) (lt_of_lt_of_le (by omega) two_pow_32_le_usize)) =
        if (ofArray ofU64 x : Vector UInt64 6)[w]! ≠ P_U64v[w]! then
          ok (done (decide ((ofArray ofU64 x : Vector UInt64 6)[w]! < P_U64v[w]!)))
        else ok (cont (UScalar.ofNatCore w (lt_of_lt_of_le (by omega) two_pow_32_le_usize))) := by
      simp only [decompress_g2.less_than_p_loop.body, gt_iff_lt, UScalar.lt_equiv,
        UScalar.ofNatCore_val_eq]
      rw [if_pos (by simp)]
      rw [show (UScalar.ofNatCore (w + 1) (lt_of_lt_of_le (by omega) two_pow_32_le_usize) : Usize) -
          1#usize = ok (UScalar.ofNatCore w (lt_of_lt_of_le (by omega) two_pow_32_le_usize)) by
        rw [sub_ok _ _ (by simp)]; simp]
      simp only [bind_tc_ok]
      rw [index_usize_eq _ _ (by simp; omega), P_U64_refines, index_usize_eq _ _ (by simp; omega)]
      simp only [bind_tc_ok, hx]
      simp [List.getElem_map, ← UInt64.toNat_inj, UInt64.lt_iff_toNat_lt, getElem!_pos P_U64v w hw6]
    rw [decompress_g2.less_than_p_loop, loop.eq_1, hbody]
    simp only [List.range_succ, List.reverse_append, List.reverse_singleton,
      List.singleton_append, List.foldl_cons]
    by_cases hc : (ofArray ofU64 x : Vector UInt64 6)[w]! = P_U64v[w]!
    · rw [if_neg (not_not.mpr hc)]
      have hstep : ltStep (ofArray ofU64 x) none w = none := by
        simp only [ltStep]; rw [if_neg (not_not.mpr hc)]
      rw [hstep, ← ih (by omega)]
      rfl
    · rw [if_pos hc]
      have hstep : ltStep (ofArray ofU64 x) none w =
          some (decide ((ofArray ofU64 x : Vector UInt64 6)[w]! < P_U64v[w]!)) := by
        simp only [ltStep]; rw [if_pos hc]
      rw [hstep, foldl_ltStep_some]
      rfl

theorem toNat_fromLEBytes (l : List Byte) :
    (BitVec.fromLEBytes l).toNat = bytesVal (l.reverse.map UInt8.ofBitVec) := by
  induction l with
  | nil => simp [BitVec.fromLEBytes, bytesVal]
  | cons b l ih =>
    have hl := (BitVec.fromLEBytes l).isLt
    have hb := b.isLt
    rw [BitVec.fromLEBytes, BitVec.toNat_or, BitVec.toNat_shiftLeft, BitVec.toNat_setWidth,
      BitVec.toNat_setWidth, ih]
    simp only [List.reverse_cons, List.map_append, List.map_cons, List.map_nil, bytesVal_append,
      List.length_cons]
    have hV := bytesVal_lt (List.map UInt8.ofBitVec l.reverse)
    simp only [List.length_map, List.length_reverse] at hV
    have h256 : (256 : ℕ) ^ l.length = 2 ^ (8 * l.length) := by rw [pow_mul]; norm_num
    have hpow : 2 ^ (8 * (l.length + 1)) = 2 ^ (8 * l.length) * 2 ^ 8 := by
      rw [← pow_add]; ring_nf
    have hb' : b.toNat < 2 ^ 8 := b.isLt
    generalize bytesVal (List.map UInt8.ofBitVec l.reverse) = V at hV ⊢
    rw [h256] at hV
    have h1 : b.toNat % 2 ^ (8 * (l.length + 1)) = b.toNat :=
      Nat.mod_eq_of_lt (by rw [hpow]; nlinarith [Nat.one_le_two_pow (n := 8 * l.length)])
    have h2 : V % 2 ^ (8 * (l.length + 1)) = V :=
      Nat.mod_eq_of_lt (by rw [hpow]; nlinarith [Nat.one_le_two_pow (n := 8 * l.length)])
    have h3 : V <<< 8 % 2 ^ (8 * (l.length + 1)) = V * 2 ^ 8 := by
      rw [Nat.shiftLeft_eq]; exact Nat.mod_eq_of_lt (by rw [hpow]; nlinarith)
    rw [h1, h2, h3, or_mul_two_pow hb']
    simp [bytesVal]
    ring

theorem from_be_bytes_refines (a : Array U8 8#usize) :
    ofU64 (core.num.U64.from_be_bytes a) = u64_from_be_bytes (ofArray ofU8 a) := by
  apply UInt64.toNat_inj.mp
  rw [toNat_u64_from_be_bytes, toNat_ofU64]
  simp only [core.num.U64.from_be_bytes, UScalar.val, BitVec.fromBEBytes, BitVec.toNat_cast,
    toNat_fromLEBytes, List.reverse_reverse, List.map_map, toList_ofArray]
  rfl

theorem fp_words_refines (be : Slice U8) (h : be.val.length = FP_BYTES) :
    decompress_g2.fp_words be = ok (toArray toU64 (fp_words (ofSlice ofU8 be h))) := by
  unfold decompress_g2.fp_words decompress_g2.fp_words_loop
  refine loop_range (n := 6) _ 6#usize rfl (toArray toU64)
    (fun v w => v.set w (fp_words (ofSlice ofU8 be h))[w]) (toArray toU64) (Vector.replicate 6 0)
    _ ?_ ?_ ?_
  · intro r m he hs hn
    simp_body decompress_g2.fp_words_loop.body hn
  · intro r r' m w he hs he' hs' hn
    have hw6 : r.start.val < 6 := by rw [hs]; exact w.isLt
    have hw : r.start.val < 8 := by omega
    obtain rfl : w = ⟨r.start.val, hw6⟩ := Fin.ext hs.symm
    have hlen : be.val.length = 48 := h
    simp_body decompress_g2.fp_words_loop.body hn
    simp only [lift, bind_tc_ok, Function.uncurry_apply_pair, Array.to_slice_mut, FP_BYTES_refines]
    simp (disch := (simp [List.slice_length, Array.to_slice]; omega)) only [usize_add_ok,
      usize_mul_ok, sub_ok, slice_index_ok, copy_from_slice_ok, update_eq, bind_tc_ok,
      UScalar.ofNatCore_val_eq]
    refine congrArg (fun s => ok (cont (r', s))) (toArray_set_of_eq _ _ _ _ _ _ _ _ rfl ?_)
    rw [eq_toU64_iff, from_be_bytes_refines]
    simp only [fp_words, Fin.getElem_fin, Vector.getElem_ofFn]
    refine congrArg u64_from_be_bytes ?_
    have hsl : (be.val.slice (48 - 8 * (r.start.val + 1)) (48 - 8 * r.start.val)).length = 8 := by
      rw [List.slice_length, hlen]; omega
    rw [Array.from_slice, dif_pos (by simpa using hsl)]
    ext i hi
    simp [List.slice, FP_BYTES, G2_COMPRESSED_LEN]
  · simp only [foldl_set_ofFn]
    rfl

theorem less_than_p_refines (x : Array U64 6#usize) :
    decompress_g2.less_than_p x = ok (less_than_p (ofArray ofU64 x)) :=
  less_than_p_loop_refines x 6 le_rfl

theorem split_at_fst (B : Vector UInt8 G2_COMPRESSED_LEN) (h' : (96#usize).val = G2_COMPRESSED_LEN)
    (p : _) (h : _) :
    ofSlice ofU8 ⟨(toArray toU8 B h').val.take (48#usize).val, p⟩ h = (split_at B).1 := by
  ext i hi
  simp [split_at]

theorem split_at_snd (B : Vector UInt8 G2_COMPRESSED_LEN) (h' : (96#usize).val = G2_COMPRESSED_LEN)
    (p : _) (h : _) :
    ofSlice ofU8 ⟨(toArray toU8 B h').val.drop (48#usize).val, p⟩ h = (split_at B).2 := by
  ext i hi
  simp [split_at, FP_BYTES, G2_COMPRESSED_LEN]

/-- The model's `Decoded` as the loop state of the generated `decode`. -/
def decodeState (d : Decoded) :
    Array (Array U64 8#usize) 8#usize × Array (Array U64 8#usize) 8#usize × U8 × U8 × U8 :=
  (toArray (toArray toU64) d.x0, toArray (toArray toU64) d.x1, toU8 d.larger_root, toU8 d.invalid,
    toU8 d.undecided)

theorem decode_loop_refines (inputs : Array (Array U8 96#usize) 8#usize) :
    decompress_g2.decode_loop { start := 0#usize, «end» := fp8.LANES } inputs
        (decodeState decodeInit).1 (decodeState decodeInit).2.1 (decodeState decodeInit).2.2.1
        (decodeState decodeInit).2.2.2.1 (decodeState decodeInit).2.2.2.2 =
      ok (decodeState (decode (ofArray (ofArray ofU8) inputs))) := by
  obtain ⟨IN, rfl⟩ : ∃ IN : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8,
      inputs = toArray (toArray toU8) IN :=
    ⟨ofArray (ofArray ofU8) inputs, (toArray_ofArray (by simp) inputs _ _).symm⟩
  unfold decompress_g2.decode_loop
  rw [LANES_refines, decode, ofArray_toArray (by simp)]
  refine loop_range (n := 8) _ 8#usize rfl decodeState (decodeStep IN) decodeState decodeInit _
    ?_ ?_ rfl
  · intro r m he hs hn
    simp_body decompress_g2.decode_loop.body hn
  · intro r r' d lane he hs he' hs' hn
    have hl : r.start.val < 8 := by rw [hs]; exact lane.isLt
    obtain rfl : lane = ⟨r.start.val, hl⟩ := Fin.ext hs.symm
    simp_body decompress_g2.decode_loop.body hn
    simp only [decodeState, bind_tc_ok, toU8_shiftLeft_one _ hl, lift]
    simp (disch := first | omega | decide) only [index_usize_toArray, bind_tc_ok]
    simp only [show ((0#usize).val) = 0 from rfl]
    rw [show (224#u8) = toU8 0xe0 from rfl, show (0#u8) = toU8 0 from rfl, FLAG_COMPRESSED_refines,
      FLAG_INFINITY_refines, FLAG_LARGER_ROOT_refines]
    simp only [toU8_and, toU8_or, toU8_inj, bne_iff_ne, ne_eq]
    unfold decodeStep
    simp only [Fin.getElem_fin]
    by_cases c1 : IN[r.start.val][0] &&& 0xe0 &&& FLAG_COMPRESSED = 0
    · simp only [c1, if_true]
    by_cases c2 : IN[r.start.val][0] &&& 0xe0 &&& FLAG_INFINITY = 0
    swap
    · simp only [c1, c2, if_true, if_false, not_false_eq_true, ne_eq]
    simp only [c1, c2, if_false, not_true_eq_false, ne_eq, FP_BYTES_refines, bind_tc_ok,
      Array.to_slice]
    rw [split_at_ok _ _ (by simp [G2_COMPRESSED_LEN])]
    simp only [bind_tc_ok, Function.uncurry_apply_pair]
    simp (disch := simp [FP_BYTES, G2_COMPRESSED_LEN]) only [fp_words_refines, bind_tc_ok,
      split_at_fst, split_at_snd]
    rw [show (2305843009213693951#u64) = toU64 0x1fffffffffffffff from rfl]
    simp (disch := first | omega | decide | (simp; omega)) only [index_usize_toArray, bind_tc_ok,
      toU64_and, update_eq, set_toArray, less_than_p_refines, unpack52_refines]
    simp only [ofArray_toArray (f := ofU64) (g := toU64) (fun _ => rfl)]
    simp only [show (5#usize).val = 5 from rfl]
    generalize less_than_p ((fp_words (split_at IN[r.start.val]).1).set 5
      ((fp_words (split_at IN[r.start.val]).1)[5] &&& 0x1fffffffffffffff)) = b1
    generalize less_than_p (fp_words (split_at IN[r.start.val]).2) = b0
    by_cases c3 : IN[r.start.val][0] &&& 0xe0 &&& FLAG_LARGER_ROOT = 0 <;>
      cases b1 <;> cases b0 <;> simp [c3]

theorem decode_refines (inputs : Array (Array U8 96#usize) 8#usize) :
    decompress_g2.decode inputs = ok (toDecoded (decode (ofArray (ofArray ofU8) inputs))) := by
  unfold decompress_g2.decode
  change (do
    let (a4, a5, i, i1, i2) ← decompress_g2.decode_loop { start := 0#usize, «end» := fp8.LANES }
      inputs (decodeState decodeInit).1 (decodeState decodeInit).2.1
      (decodeState decodeInit).2.2.1 (decodeState decodeInit).2.2.2.1
      (decodeState decodeInit).2.2.2.2
    ok ({ x0 := a4, x1 := a5, larger_root := i, invalid := i1, undecided := i2 } :
      decompress_g2.Decoded)) = _
  rw [decode_loop_refines]
  rfl

theorem default_refines :
    blst.blst_p2_affine.Insts.CoreDefaultDefault.default = ok (toBlstP2Affine default) := rfl

theorem decompress_loop_refines (a : Array blst.blst_p2_affine 8#usize)
    (x0 x1 y0 y1 : Array (Array U64 6#usize) 8#usize) :
    decompress_g2.decompress_loop { start := 0#usize, «end» := fp8.LANES } a x0 x1 y0 y1 =
      ok (toArray toBlstP2Affine (.ofFn fun lane : Fin 8 => {
        x := { fp := #v[{ l := (ofArray (ofArray ofU64) x0 (m := 8))[lane] },
          { l := (ofArray (ofArray ofU64) x1 (m := 8))[lane] }] },
        y := { fp := #v[{ l := (ofArray (ofArray ofU64) y0 (m := 8))[lane] },
          { l := (ofArray (ofArray ofU64) y1 (m := 8))[lane] }] } })) := by
  obtain ⟨A, rfl⟩ : ∃ A : Vector BlstP2Affine 8, a = toArray toBlstP2Affine A :=
    ⟨ofArray ofBlstP2Affine a, (toArray_ofArray (by simp) a _ _).symm⟩
  unfold decompress_g2.decompress_loop
  rw [LANES_refines]
  refine loop_range (n := 8) _ 8#usize rfl (toArray toBlstP2Affine)
    (fun v (lane : Fin 8) => v.set lane {
      x := { fp := #v[{ l := (ofArray (ofArray ofU64) x0 (m := 8))[lane] },
        { l := (ofArray (ofArray ofU64) x1 (m := 8))[lane] }] },
      y := { fp := #v[{ l := (ofArray (ofArray ofU64) y0 (m := 8))[lane] },
        { l := (ofArray (ofArray ofU64) y1 (m := 8))[lane] }] } })
    (toArray toBlstP2Affine) A _ ?_ ?_ ?_
  · intro r m he hs hn
    simp_body decompress_g2.decompress_loop.body hn
  · intro r r' m lane he hs he' hs' hn
    have hl : r.start.val < (8#usize).val := by rw [hs]; exact lane.isLt
    simp_body decompress_g2.decompress_loop.body hn
    simp only [index_usize_eq _ _ hl, bind_tc_ok, point_refines, update_eq _ _ _ hl]
    refine congrArg (fun s => ok (cont (r', s))) ?_
    apply Subtype.ext
    simp [hs, List.map_set, Vector.toList_set]
  · simp [foldl_set_ofFn]

theorem foldl_points (f : Fin 8 → BlstP2Affine) (ls : List (Fin 8)) (b : Batch) :
    ls.foldl (fun batch (lane : Fin 8) => { batch with points := batch.points.set lane (f lane) })
        b =
      { b with points := ls.foldl (fun v (lane : Fin 8) => v.set lane (f lane)) b.points } := by
  induction ls generalizing b with
  | nil => rfl
  | cons j ls ih => simp only [List.foldl_cons, ih]

theorem decompress_refines (inputs : Array (Array U8 96#usize) 8#usize) :
    decompress_g2.decompress inputs =
      ok (toBatch (decompress (ofArray (ofArray ofU8) inputs))) := by
  unfold decompress_g2.decompress
  rw [decompress_eq]
  simp only [decode_refines, default_refines, bind_tc_ok, lift]
  generalize decode (ofArray (ofArray ofU8) inputs) = D
  rw [← toArray_replicate toBlstP2Affine default (show (8#usize).val = 8 from rfl)]
  simp only [toDecoded, toU8_or, toU8_not, show (0#u8) = toU8 0 from rfl, toU8_inj,
    Fp8.from_plain_refines, Fp8.splat_limbs_refines, FOUR_MONT_refines, bind_tc_ok,
    ofArray_toArray_ofU64, ofArray_toArray_ofArray_ofU64]
  rw [show Fp8.from_plain D.x0 = (xOf D).c0 from rfl,
    show Fp8.from_plain D.x1 = (xOf D).c1 from rfl]
  generalize xOf D = X
  simp only [Fp2x8.square_refines, Fp2x8.mul_refines, Fp2x8.add_refines, bind_tc_ok, ofFp2x8_mk,
    ofFp8_toFp8, ofFp2x8_toFp2x8]
  rw [show (X.square.mul X).add ⟨Fp8.splat_limbs (.ofList FOUR_MONT),
    Fp8.splat_limbs (.ofList FOUR_MONT)⟩ = rhsOf X from rfl]
  simp only [Fp2x8.sqrt_refines, bind_tc_ok, ofFp2x8_toFp2x8, Function.uncurry_def, Prod.map_fst,
    Prod.map_snd]
  generalize (rhsOf X).sqrt = S
  obtain ⟨root, has⟩ := S
  simp only [toU8_and, toU8_inj]
  unfold tail
  by_cases h1 : ~~~(D.invalid ||| D.undecided) = 0
  · simp only [h1, if_true, toBatch]
  simp only [h1, if_false]
  by_cases h2 : has &&& ~~~(D.invalid ||| D.undecided) = 0
  · simp only [h2, if_true, toBatch]
  simp only [h2, if_false, tailFull, foldl_points, foldl_set_ofFn,
    Fp2x8.is_larger_root_mask_refines, Fp2x8.neg_refines, Fp2x8.select_refines,
    G2x8.scott_membership_refines, Fp8.to_blst_limbs_refines, c0_toFp2x8, c1_toFp2x8, ofFp8_toFp8,
    ofFp2x8_toFp2x8, bind_tc_ok, toU8_xor, ofU8_toU8, decompress_loop_refines, toMembership,
    toU8_and, toU8_or, toU8_not, toBatch, ofArray_toArray_ofArray_ofU64, ofFp2x8_mk]

end DecompressG2

end LeanBlsSimd
