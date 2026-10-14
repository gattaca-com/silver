import LeanBlsSimd.Refines.DecompressG2
import LeanBlsSimd.Refines.G2x8
import LeanBlsSimd.Proofs.Convert
import LeanBlsSimd.Refines.G1Wrapper

/-! Mutation controls for `LeanBlsSimd/Refines/`. Each `fail_if_success` checks that a proof script
rejects a mutation; each plain `example` must pass.

Each mutated definition takes the changed part as a parameter. An `rfl` check identifies its
unmutated instance with the original, and the same proof script succeeds on that instance.
Separate concrete examples refute the mutated claims where described below. -/

namespace LeanBlsSimd

open Aeneas Aeneas.Std Result ControlFlow
open silver_bls_simd

-- A mutated proof stops at its first failing step, so the linters flag the steps after it.
set_option linter.unreachableTactic false
set_option linter.unusedSimpArgs false
set_option linter.unusedTactic false

namespace DecompressG2

/-! ## `decode`: the order of the coordinates

The 96 input bytes hold x1, then x0. A model that stores the two halves the other way round must
not refine the generated `decode`. -/

def decodeStepWith (swap : Bool) (inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8)
    (d : Decoded) (lane : Fin 8) : Decoded :=
  let bytes := inputs[lane]
  let bit : Mmask8 := 1 <<< lane.val.toUInt8
  let flags := bytes[0]'(by simp [G2_COMPRESSED_LEN]) &&& 0xe0
  if flags &&& FLAG_COMPRESSED = 0 then { d with invalid := d.invalid ||| bit }
  else if flags &&& FLAG_INFINITY ≠ 0 then { d with undecided := d.undecided ||| bit }
  else
    let d := if flags &&& FLAG_LARGER_ROOT ≠ 0 then
      { d with larger_root := d.larger_root ||| bit } else d
    let (x1_bytes, x0_bytes) := split_at bytes
    let x1 := fp_words x1_bytes
    let x1 := x1.set 5 (x1[5] &&& 0x1fffffffffffffff)
    let x0 := fp_words x0_bytes
    if !less_than_p x1 || !less_than_p x0 then { d with invalid := d.invalid ||| bit }
    else if swap then
      { d with x0 := d.x0.set lane (unpack52 x1), x1 := d.x1.set lane (unpack52 x0) }
    else { d with x0 := d.x0.set lane (unpack52 x0), x1 := d.x1.set lane (unpack52 x1) }

example : decodeStepWith false = decodeStep := rfl

set_option hygiene false in
/-- The proof of `decode_loop_refines`, over `decodeStepWith`. -/
local macro "decode_loop_proof" : tactic => `(tactic| (
  intro inputs
  obtain ⟨IN, rfl⟩ : ∃ IN : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8,
      inputs = toArray (toArray toU8) IN :=
    ⟨ofArray (ofArray ofU8) inputs, (toArray_ofArray (by simp) inputs _ _).symm⟩
  unfold decompress_g2.decode_loop
  rw [LANES_refines, ofArray_toArray (by simp)]
  refine loop_range (n := 8) _ 8#usize rfl decodeState (decodeStepWith _ IN) decodeState
    decodeInit _ ?_ ?_ rfl
  · intro r m he hs hn
    simp_body decompress_g2.decode_loop.body hn
  · intro r r' d lane he hs he' hs' hn
    have hl : r.start.val < 8 := by rw [hs]; exact lane.isLt
    obtain rfl : lane = ⟨r.start.val, hl⟩ := Fin.ext hs.symm
    simp_body decompress_g2.decode_loop.body hn
    simp only [decodeState, bind_tc_ok, toU8_shiftLeft_one _ hl, lift]
    simp (disch := first | omega | decide) only [index_usize_toArray, bind_tc_ok]
    simp only [show ((0#usize).val) = 0 from rfl]
    rw [show (224#u8) = toU8 0xe0 from rfl, show (0#u8) = toU8 0 from rfl,
      FLAG_COMPRESSED_refines, FLAG_INFINITY_refines, FLAG_LARGER_ROOT_refines]
    simp only [toU8_and, toU8_or, toU8_inj, bne_iff_ne, ne_eq]
    unfold decodeStepWith
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
    simp (disch := first | omega | decide | (simp; omega)) only [index_usize_toArray,
      bind_tc_ok, toU64_and, update_eq, set_toArray, less_than_p_refines, unpack52_refines]
    simp only [ofArray_toArray (f := ofU64) (g := toU64) (fun _ => rfl)]
    simp only [show (5#usize).val = 5 from rfl]
    generalize less_than_p ((fp_words (split_at IN[r.start.val]).1).set 5
      ((fp_words (split_at IN[r.start.val]).1)[5] &&& 0x1fffffffffffffff)) = b1
    generalize less_than_p (fp_words (split_at IN[r.start.val]).2) = b0
    by_cases c3 : IN[r.start.val][0] &&& 0xe0 &&& FLAG_LARGER_ROOT = 0 <;>
      cases b1 <;> cases b0 <;> simp [c3]))

example : ∀ inputs : Array (Array U8 96#usize) 8#usize,
    decompress_g2.decode_loop { start := 0#usize, «end» := fp8.LANES } inputs
        (decodeState decodeInit).1 (decodeState decodeInit).2.1 (decodeState decodeInit).2.2.1
        (decodeState decodeInit).2.2.2.1 (decodeState decodeInit).2.2.2.2 =
      ok (decodeState ((List.finRange 8).foldl
        (decodeStepWith false (ofArray (ofArray ofU8) inputs)) decodeInit)) := by
  decode_loop_proof

example : True := by
  fail_if_success
    have : ∀ inputs : Array (Array U8 96#usize) 8#usize,
        decompress_g2.decode_loop { start := 0#usize, «end» := fp8.LANES } inputs
            (decodeState decodeInit).1 (decodeState decodeInit).2.1
            (decodeState decodeInit).2.2.1 (decodeState decodeInit).2.2.2.1
            (decodeState decodeInit).2.2.2.2 =
          ok (decodeState ((List.finRange 8).foldl
            (decodeStepWith true (ofArray (ofArray ofU8) inputs)) decodeInit)) := by
      decode_loop_proof
  trivial

/-! ## `fp_words`: the order of the words

The coordinate is big-endian, so word 0 holds its last eight bytes. A generated `fp_words` that
writes word `w` at `5 - w` must not refine the model's. The mutant takes the index of the write
as a parameter. A separate proof shows that the mutant writes each word at `5 - w`. On
`byteIndices` words 0 and 5 differ, so the mutated claim is false, not only unproved. -/

def fpWordsBodyWith (word : Usize → Result Usize) (be : Slice U8)
    (iter : core.ops.range.Range Usize) (words : Array U64 6#usize) :
    Result (ControlFlow (core.ops.range.Range Usize × Array U64 6#usize) (Array U64 6#usize)) := do
  let (o, iter1) ← core.iter.range.IteratorRange.next core.iter.range.StepUsize iter
  match o with
  | none => ok (done words)
  | some w =>
    let bytes := Array.repeat 8#usize 0#u8
    let (s, to_slice_mut_back) ← lift (Array.to_slice_mut bytes)
    let i ← w + 1#usize
    let i1 ← 8#usize * i
    let i2 ← decompress_g2.FP_BYTES
    let i3 ← i2 - i1
    let i4 ← 8#usize * w
    let i5 ← i2 - i4
    let s1 ← core.slice.index.Slice.index (core.slice.index.SliceIndexRangeUsizeSlice U8) be
      { start := i3, «end» := i5 }
    let s2 ← core.slice.Slice.copy_from_slice core.marker.CopyU8 s s1
    let bytes1 := to_slice_mut_back s2
    let i6 ← lift (core.num.U64.from_be_bytes bytes1)
    let w1 ← word w
    let a ← Array.update words w1 i6
    ok (cont (iter1, a))

def fpWordsWith (word : Usize → Result Usize) (be : Slice U8) : Result (Array U64 6#usize) := do
  let words := Array.repeat 6#usize 0#u64
  loop (fun (iter1, words1) => fpWordsBodyWith word be iter1 words1)
    ({ start := 0#usize, «end» := 6#usize }, words)

example : fpWordsWith ok = decompress_g2.fp_words := rfl

set_option hygiene false in
/-- The proof of `fp_words_refines`, over `fpWordsWith`. -/
local macro "fp_words_proof" : tactic => `(tactic| (
  intro be h
  unfold fpWordsWith
  refine loop_range (n := 6) _ 6#usize rfl (toArray toU64)
    (fun v w => v.set w (fp_words (ofSlice ofU8 be h))[w]) (toArray toU64) (Vector.replicate 6 0)
    _ ?_ ?_ ?_
  · intro r m he hs hn
    simp_body fpWordsBodyWith hn
  · intro r r' m w he hs he' hs' hn
    have hw6 : r.start.val < 6 := by rw [hs]; exact w.isLt
    have hw : r.start.val < 8 := by omega
    obtain rfl : w = ⟨r.start.val, hw6⟩ := Fin.ext hs.symm
    have hlen : be.val.length = 48 := h
    simp_body fpWordsBodyWith hn
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
    rfl))

example : ∀ (be : Slice U8) (h : be.val.length = FP_BYTES),
    fpWordsWith ok be = ok (toArray toU64 (fp_words (ofSlice ofU8 be h))) := by
  fp_words_proof

example : True := by
  fail_if_success
    have : ∀ (be : Slice U8) (h : be.val.length = FP_BYTES),
        fpWordsWith (5#usize - ·) be = ok (toArray toU64 (fp_words (ofSlice ofU8 be h))) := by
      fp_words_proof
  trivial

/-- The mutant writes word `w` at `5 - w`. -/
theorem fpWordsWith_rev_refines (be : Slice U8) (h : be.val.length = FP_BYTES) :
    fpWordsWith (5#usize - ·) be = ok (toArray toU64 ((List.finRange 6).foldl
      (fun v (w : Fin 6) => v.set (5 - w.val) (fp_words (ofSlice ofU8 be h))[w])
      (Vector.replicate 6 0))) := by
  unfold fpWordsWith
  refine loop_range (n := 6) _ 6#usize rfl (toArray toU64)
    (fun v (w : Fin 6) => v.set (5 - w.val) (fp_words (ofSlice ofU8 be h))[w]) (toArray toU64)
    (Vector.replicate 6 0) _ ?_ ?_ rfl
  · intro r m he hs hn
    simp_body fpWordsBodyWith hn
  · intro r r' m w he hs he' hs' hn
    have hw6 : r.start.val < 6 := by rw [hs]; exact w.isLt
    have hw : r.start.val < 8 := by omega
    obtain rfl : w = ⟨r.start.val, hw6⟩ := Fin.ext hs.symm
    have hlen : be.val.length = 48 := h
    simp_body fpWordsBodyWith hn
    simp only [lift, bind_tc_ok, Function.uncurry_apply_pair, Array.to_slice_mut, FP_BYTES_refines]
    simp (disch := (simp [List.slice_length, Array.to_slice]; omega)) only [usize_add_ok,
      usize_mul_ok, sub_ok, slice_index_ok, copy_from_slice_ok, update_eq, bind_tc_ok,
      UScalar.ofNatCore_val_eq]
    refine congrArg (fun s => ok (cont (r', s)))
      (toArray_set_of_eq _ _ _ _ _ (by omega) _ _ (by simp) ?_)
    rw [eq_toU64_iff, from_be_bytes_refines]
    simp only [fp_words, Fin.getElem_fin, Vector.getElem_ofFn]
    refine congrArg u64_from_be_bytes ?_
    have hsl : (be.val.slice (48 - 8 * (r.start.val + 1)) (48 - 8 * r.start.val)).length = 8 := by
      rw [List.slice_length, hlen]; omega
    rw [Array.from_slice, dif_pos (by simpa using hsl)]
    ext i hi
    simp [List.slice, FP_BYTES, G2_COMPRESSED_LEN]

/-- Bytes 0 to 47, so that every word differs. -/
def byteIndices : Vector UInt8 FP_BYTES := .ofFn fun i => i.val.toUInt8

def byteIndicesSlice : Slice U8 :=
  ⟨byteIndices.toList.map toU8, by
    rcases Usize.bounds_eq with h | h <;>
      simp [h, U32.max_eq, U64.max_eq, FP_BYTES, G2_COMPRESSED_LEN]⟩

theorem byteIndicesSlice_length : byteIndicesSlice.val.length = FP_BYTES := by
  simp [byteIndicesSlice]

example : ¬ ∀ (be : Slice U8) (h : be.val.length = FP_BYTES),
    fpWordsWith (5#usize - ·) be = ok (toArray toU64 (fp_words (ofSlice ofU8 be h))) := by
  intro h
  have e := congrArg (ofArray ofU64 (m := 6) (h := rfl)) (Result.ok.inj
    ((fpWordsWith_rev_refines _ byteIndicesSlice_length).symm.trans
      (h _ byteIndicesSlice_length)))
  simp only [ofArray_toArray_ofU64] at e
  have hb : ofSlice ofU8 byteIndicesSlice byteIndicesSlice_length = byteIndices := by
    ext i hi
    simp [byteIndicesSlice]
  rw [hb] at e
  have e0 := congrArg (fun x : Vector UInt64 6 => x[0]) e
  revert e0
  decide +kernel

end DecompressG2

/-! ## `Fp8::select`: the order of the operands

`select k a b` takes a lane from `b` where its bit of `k` is set, and from `a` otherwise. A
generated `select` with its operands swapped must not refine the model's. -/

def selectWith (swap : Bool) (k : U8) (a b : fp8.Fp8) : Result fp8.Fp8 :=
  if swap then fp8.Fp8.select k b a else fp8.Fp8.select k a b

example : selectWith false = fp8.Fp8.select := rfl

set_option hygiene false in
/-- The proof of `Fp8.select_refines`, over `selectWith`. -/
local macro "select_proof" : tactic => `(tactic| (
  intro k a b
  simp [selectWith, fp8.Fp8.select, Simd.blend_refines, Fp8.select, toFp8]))

example : ∀ (k : U8) (a b : fp8.Fp8),
    selectWith false k a b = ok (toFp8 (Fp8.select (ofU8 k) (ofFp8 a) (ofFp8 b))) := by
  select_proof

example : True := by
  fail_if_success
    have : ∀ (k : U8) (a b : fp8.Fp8),
        selectWith true k a b = ok (toFp8 (Fp8.select (ofU8 k) (ofFp8 a) (ofFp8 b))) := by
      select_proof
  trivial

/-! ## `Fp8::load` and `Fp8::store`: the lane order

`load` passes the limbs of lanes 7 down to 0 to `_mm512_set_epi64`, whose last argument is lane 0.
`store` writes element `l` of `lanes(v)` to `out[l]`. A generated `load` that passes the limbs in
the opposite order, or a `store` whose `lanes` reverses the vector, must not refine the model's.
Each mutant takes the intrinsic or `lanes` as a parameter, and each script takes the model's
counterpart as its argument. The same scripts prove that each mutant refines a model with the same
mutation. On `laneIndices` that model differs from the original in lane 0, so the mutated claims
are false, not only unproved. -/

section LoadStore

open core.core_arch.x86

abbrev SetEpi64 := I64 → I64 → I64 → I64 → I64 → I64 → I64 → I64 → Result __m512i

def loadBodyWith (set : SetEpi64) (values : Array (Array U64 8#usize) 8#usize)
    (iter : core.ops.range.Range Usize) (v : Array __m512i 8#usize) :
    Result (ControlFlow (core.ops.range.Range Usize × Array __m512i 8#usize)
      (Array __m512i 8#usize)) := do
  let (o, iter1) ← core.iter.range.IteratorRange.next core.iter.range.StepUsize iter
  match o with
  | none => ok (done v)
  | some j =>
    let a ← Array.index_usize values 7#usize
    let i ← Array.index_usize a j
    let i1 ← lift (UScalar.hcast .I64 i)
    let a1 ← Array.index_usize values 6#usize
    let i2 ← Array.index_usize a1 j
    let i3 ← lift (UScalar.hcast .I64 i2)
    let a2 ← Array.index_usize values 5#usize
    let i4 ← Array.index_usize a2 j
    let i5 ← lift (UScalar.hcast .I64 i4)
    let a3 ← Array.index_usize values 4#usize
    let i6 ← Array.index_usize a3 j
    let i7 ← lift (UScalar.hcast .I64 i6)
    let a4 ← Array.index_usize values 3#usize
    let i8 ← Array.index_usize a4 j
    let i9 ← lift (UScalar.hcast .I64 i8)
    let a5 ← Array.index_usize values 2#usize
    let i10 ← Array.index_usize a5 j
    let i11 ← lift (UScalar.hcast .I64 i10)
    let a6 ← Array.index_usize values 1#usize
    let i12 ← Array.index_usize a6 j
    let i13 ← lift (UScalar.hcast .I64 i12)
    let a7 ← Array.index_usize values 0#usize
    let i14 ← Array.index_usize a7 j
    let i15 ← lift (UScalar.hcast .I64 i14)
    let mi ← set i1 i3 i5 i7 i9 i11 i13 i15
    let a8 ← Array.update v j mi
    ok (cont (iter1, a8))

def loadLoopWith (set : SetEpi64) (iter : core.ops.range.Range Usize)
    (values : Array (Array U64 8#usize) 8#usize) (v : Array __m512i 8#usize) :
    Result (Array __m512i 8#usize) :=
  loop (fun (iter1, v1) => loadBodyWith set values iter1 v1) (iter, v)

def loadWith (set : SetEpi64) (values : Array (Array U64 8#usize) 8#usize) : Result fp8.Fp8 := do
  let mi ← fp8.zero
  let v := Array.repeat 8#usize mi
  let v1 ← loadLoopWith set { start := 0#usize, «end» := constants.LIMBS } values v
  ok v1

example : loadWith avx512f._mm512_set_epi64 = fp8.Fp8.load := rfl

/-- `_mm512_set_epi64` with its arguments in the opposite order, which is `_mm512_setr_epi64`. -/
def setrGen : SetEpi64 := fun e7 e6 e5 e4 e3 e2 e1 e0 =>
  avx512f._mm512_set_epi64 e0 e1 e2 e3 e4 e5 e6 e7

def Fp8.loadWith (set : Int64 → Int64 → Int64 → Int64 → Int64 → Int64 → Int64 → Int64 → M512)
    (values : Vector Limbs 8) : Fp8 :=
  ⟨.ofFn fun j => set values[7][j].toInt64 values[6][j].toInt64
    values[5][j].toInt64 values[4][j].toInt64 values[3][j].toInt64 values[2][j].toInt64
    values[1][j].toInt64 values[0][j].toInt64⟩

example : Fp8.loadWith _mm512_set_epi64 = Fp8.load := rfl

def setrModel : Int64 → Int64 → Int64 → Int64 → Int64 → Int64 → Int64 → Int64 → M512 :=
  fun e7 e6 e5 e4 e3 e2 e1 e0 => _mm512_set_epi64 e0 e1 e2 e3 e4 e5 e6 e7

set_option hygiene false in
/-- The proof of `Fp8.load_refines`, over `loadWith`, against `Fp8.loadWith set`. -/
local macro "load_proof" set:term : tactic => `(tactic| (
  intro values
  unfold loadWith loadLoopWith
  simp only [Simd.zero_refines, bind_tc_ok, LIMBS_refines, bind_ok_eq]
  rw [repeat_eq_toArray_id Simd.zero (show (8#usize).val = LIMBS from rfl)]
  refine loop_range (n := LIMBS) _ 8#usize rfl (toArray id)
    (fun v j => v.set j (Fp8.loadWith $set (ofArray (ofArray ofU64) values)).limbs[j]) (toArray id)
    (Vector.replicate LIMBS Simd.zero) _ ?_ ?_ ?_
  · intro r m he hs hn
    simp_body loadBodyWith hn
  · intro r r' m j he hs he' hs' hn
    have hj : r.start.val < (8#usize).val := by rw [hs]; exact j.isLt
    simp_body loadBodyWith hn
    simp only [index_usize_eq values 7#usize (by decide), index_usize_eq values 6#usize (by decide),
      index_usize_eq values 5#usize (by decide), index_usize_eq values 4#usize (by decide),
      index_usize_eq values 3#usize (by decide), index_usize_eq values 2#usize (by decide),
      index_usize_eq values 1#usize (by decide), index_usize_eq values 0#usize (by decide),
      index_usize_eq _ _ hj, bind_tc_ok, lift, update_eq _ _ _ hj, setrGen,
      avx512f._mm512_set_epi64, ofBitVec_hcast_I64]
    refine congrArg (fun s => ok (cont (r', s))) ?_
    apply Subtype.ext
    simp [hs, List.map_set, Vector.toList_set, Fp8.loadWith, setrModel]
  · simp [Fp8.loadWith, foldl_set_ofFn, toFp8]))

example : ∀ values : Array (Array U64 8#usize) 8#usize,
    loadWith avx512f._mm512_set_epi64 values =
      ok (toFp8 (Fp8.loadWith _mm512_set_epi64 (ofArray (ofArray ofU64) values))) := by
  load_proof _mm512_set_epi64

example : True := by
  fail_if_success
    have : ∀ values : Array (Array U64 8#usize) 8#usize,
        loadWith setrGen values =
          ok (toFp8 (Fp8.loadWith _mm512_set_epi64 (ofArray (ofArray ofU64) values))) := by
      load_proof _mm512_set_epi64
  trivial

theorem loadWith_setr_refines : ∀ values : Array (Array U64 8#usize) 8#usize,
    loadWith setrGen values =
      ok (toFp8 (Fp8.loadWith setrModel (ofArray (ofArray ofU64) values))) := by
  load_proof setrModel

/-- Eight lanes whose limbs all hold the lane's index. -/
def laneIndices : Vector Limbs 8 := .ofFn fun l => .replicate LIMBS l.val.toUInt64

example : ¬ ∀ values : Array (Array U64 8#usize) 8#usize,
    loadWith setrGen values = ok (toFp8 (Fp8.load (ofArray (ofArray ofU64) values))) := by
  intro h
  have e := congrArg ofFp8 (Result.ok.inj
    ((loadWith_setr_refines (toArray (toArray toU64) laneIndices)).symm.trans
      (h (toArray (toArray toU64) laneIndices))))
  simp only [ofFp8_toFp8, ofArray_toArray_ofArray_ofU64] at e
  have e0 := congrArg (fun x : Fp8 => x.limbs[0][0]) e
  revert e0
  decide +kernel

def storeBodyWith (lanes : __m512i → Result (Array U64 8#usize))
    (iter : core.ops.range.Range Usize) (self : fp8.Fp8) (out : Array (Array U64 8#usize) 8#usize) :
    Result (ControlFlow (core.ops.range.Range Usize × fp8.Fp8 × Array (Array U64 8#usize) 8#usize)
      (Array (Array U64 8#usize) 8#usize)) := do
  let (o, iter1) ← core.iter.range.IteratorRange.next core.iter.range.StepUsize iter
  match o with
  | none => ok (done out)
  | some j =>
    let mi ← Array.index_usize self j
    let l ← lanes mi
    let out1 ← fp8.Fp8.store_loop0_loop0 { start := 0#usize, «end» := fp8.LANES } out j l
    ok (cont (iter1, self, out1))

def storeLoopWith (lanes : __m512i → Result (Array U64 8#usize))
    (iter : core.ops.range.Range Usize) (self : fp8.Fp8) (out : Array (Array U64 8#usize) 8#usize) :
    Result (Array (Array U64 8#usize) 8#usize) :=
  loop (fun (iter1, self1, out1) => storeBodyWith lanes iter1 self1 out1) (iter, self, out)

def storeWith (lanes : __m512i → Result (Array U64 8#usize)) (self : fp8.Fp8) :
    Result (Array (Array U64 8#usize) 8#usize) := do
  let a := Array.repeat 8#usize 0#u64
  let out := Array.repeat 8#usize a
  storeLoopWith lanes { start := 0#usize, «end» := constants.LIMBS } self out

example : storeWith fp8.lanes = fp8.Fp8.store := rfl

/-- `fp8::lanes` reading the lanes in the opposite order. -/
def lanesRevGen (v : __m512i) : Result (Array U64 8#usize) := fp8.lanes v.reverse

def Fp8.storeWith (lanes : M512 → Vector UInt64 8) (self : Fp8) : Vector Limbs 8 :=
  (List.finRange LIMBS).foldl (init := .replicate 8 (.replicate LIMBS 0)) fun out (j : Fin LIMBS) =>
    let l := lanes self.limbs[j]
    (List.finRange 8).foldl (init := out) fun out (lane : Fin 8) =>
      out.set lane (out[lane].set j l[lane])

example : Fp8.storeWith Simd.lanes = Fp8.store := rfl

def lanesRevModel (v : M512) : Vector UInt64 8 := Simd.lanes v.reverse

set_option hygiene false in
/-- The proof of `Fp8.store_refines`, over `storeWith`, against `Fp8.storeWith lanes`. -/
local macro "store_proof" lanes:term : tactic => `(tactic| (
  intro self
  unfold storeWith storeLoopWith
  simp only [LIMBS_refines]
  rw [show Array.repeat 8#usize (Array.repeat 8#usize 0#u64) =
    toArray (toArray toU64) (Vector.replicate 8 (Vector.replicate LIMBS 0)) from
    by simp [toArray_replicate]; rfl]
  refine loop_range (n := LIMBS) _ 8#usize rfl (fun out => (self, toArray (toArray toU64) out))
    (fun out (j : Fin LIMBS) =>
      (List.finRange 8).foldl (fun out (lane : Fin 8) =>
        out.set lane (out[lane].set j ($lanes (ofFp8 self).limbs[j])[lane])) out)
    (toArray (toArray toU64)) (Vector.replicate 8 (Vector.replicate LIMBS 0)) _ ?_ ?_ rfl
  · intro r m he hs hn
    simp_body storeBodyWith hn
  · intro r r' m j he hs he' hs' hn
    have hj : r.start.val < (8#usize).val := by rw [hs]; exact j.isLt
    simp_body storeBodyWith hn
    simp only [index_usize_eq _ _ hj, bind_tc_ok, lanesRevGen, Simd.lanes_refines]
    rw [Fp8.store_inner_refines _ _ (by rw [hs]; exact j.isLt)]
    simp [hs, lanesRevModel]))

example : ∀ self : fp8.Fp8,
    storeWith fp8.lanes self =
      ok (toArray (toArray toU64) (Fp8.storeWith Simd.lanes (ofFp8 self))) := by
  store_proof Simd.lanes

example : True := by
  fail_if_success
    have : ∀ self : fp8.Fp8,
        storeWith lanesRevGen self =
          ok (toArray (toArray toU64) (Fp8.storeWith Simd.lanes (ofFp8 self))) := by
      store_proof Simd.lanes
  trivial

theorem storeWith_rev_refines : ∀ self : fp8.Fp8,
    storeWith lanesRevGen self =
      ok (toArray (toArray toU64) (Fp8.storeWith lanesRevModel (ofFp8 self))) := by
  store_proof lanesRevModel

example : ¬ ∀ self : fp8.Fp8,
    storeWith lanesRevGen self = ok (toArray (toArray toU64) (ofFp8 self).store) := by
  intro h
  have e := congrArg (ofArray (ofArray ofU64) (m := 8) (h := rfl)) (Result.ok.inj
    ((storeWith_rev_refines (toFp8 (Fp8.load laneIndices))).symm.trans
      (h (toFp8 (Fp8.load laneIndices)))))
  simp only [ofFp8_toFp8, ofArray_toArray_ofArray_ofU64] at e
  have e0 := congrArg (fun x : Vector Limbs 8 => x[0][0]) e
  revert e0
  decide +kernel

end LoadStore

/-! ## `Fp8::mul`: the row indices

The eighth `muladd_row` of `mul` adds `rhs[7]` at row 7. A generated `mul` that adds it at row 6
must not refine the model's. The same script proves that this mutant refines a model with the
same mutation, and that model differs from `Lane.mul` on a concrete input. So the mutated claim
is false, not only unproved. -/

def mulWith (k : Usize) (self rhs : fp8.Fp8) : Result fp8.Fp8 := do
  let p ← fp8.splat_limbs constants.P
  let pinv ← fp8.splat constants.P_INV52
  let mi ← fp8.zero
  let t := Array.repeat 17#usize mi
  let mi1 ← Array.index_usize rhs 0#usize
  let t1 ← fp8.muladd_row t self mi1 0#usize
  let mi2 ← Array.index_usize rhs 1#usize
  let t2 ← fp8.muladd_row t1 self mi2 1#usize
  let mi3 ← Array.index_usize rhs 2#usize
  let t3 ← fp8.muladd_row t2 self mi3 2#usize
  let mi4 ← Array.index_usize rhs 3#usize
  let t4 ← fp8.muladd_row t3 self mi4 3#usize
  let mi5 ← Array.index_usize rhs 4#usize
  let t5 ← fp8.muladd_row t4 self mi5 4#usize
  let mi6 ← Array.index_usize rhs 5#usize
  let t6 ← fp8.muladd_row t5 self mi6 5#usize
  let mi7 ← Array.index_usize rhs 6#usize
  let t7 ← fp8.muladd_row t6 self mi7 6#usize
  let mi8 ← Array.index_usize rhs 7#usize
  let t8 ← fp8.muladd_row t7 self mi8 k
  let t9 ← fp8.reduce_row t8 p pinv 0#usize
  let t10 ← fp8.reduce_row t9 p pinv 1#usize
  let t11 ← fp8.reduce_row t10 p pinv 2#usize
  let t12 ← fp8.reduce_row t11 p pinv 3#usize
  let t13 ← fp8.reduce_row t12 p pinv 4#usize
  let t14 ← fp8.reduce_row t13 p pinv 5#usize
  let t15 ← fp8.reduce_row t14 p pinv 6#usize
  let t16 ← fp8.reduce_row t15 p pinv 7#usize
  let i ← constants.MASK52
  let mask ← fp8.splat i
  let r := Array.repeat 8#usize mi
  let mi9 ← Array.index_usize t16 constants.LIMBS
  let a ← Array.update r 0#usize mi9
  let i1 ← constants.LIMBS - 1#usize
  let r1 ← fp8.Fp8.mul_loop { start := 0#usize, «end» := i1 } t16 mask a
  ok r1

example : mulWith 7#usize = fp8.Fp8.mul := rfl

def Lane.mulWith (k : Fin LIMBS) (self rhs : Limbs) : Limbs :=
  let p := splat_limbs (.ofList P)
  let pinv := splat (.ofNat P_INV52)
  let t : Acc := .replicate _ zero
  let t := muladd_row t self rhs[0] 0
  let t := muladd_row t self rhs[1] 1
  let t := muladd_row t self rhs[2] 2
  let t := muladd_row t self rhs[3] 3
  let t := muladd_row t self rhs[4] 4
  let t := muladd_row t self rhs[5] 5
  let t := muladd_row t self rhs[6] 6
  let t := muladd_row t self rhs[7] k
  let t := reduce_row t p pinv 0
  let t := reduce_row t p pinv 1
  let t := reduce_row t p pinv 2
  let t := reduce_row t p pinv 3
  let t := reduce_row t p pinv 4
  let t := reduce_row t p pinv 5
  let t := reduce_row t p pinv 6
  let t := reduce_row t p pinv 7

  let mask := splat (.ofNat MASK52)
  let r : Limbs := .replicate _ zero
  let r := r.set 0 t[LIMBS]
  (List.finRange (LIMBS - 1)).foldl (carryStep t mask) r

example : Lane.mulWith 7 = Lane.mul := rfl

set_option hygiene false in
/-- The proof of `Fp8.mul_refines`, over `mulWith`, and over `Lane.mulWith` where the claim
names it. -/
-- Each use keeps `Lane.reduce_row` folded, as `Fp8.mul_refines` does.
local macro "mul_proof" : tactic => `(tactic| (
  intro self rhs
  unfold mulWith
  simp only [Simd.splat_limbs_refines, P_refines, Simd.splat_refines, P_INV52_refines,
    Simd.zero_refines, MASK52_refines, bind_tc_ok, LIMBS_refines]
  rw [repeat_eq_toArray_id Simd.zero (show (17#usize).val = 2 * LIMBS + 1 from rfl),
    repeat_eq_toArray_id Simd.zero (show (8#usize).val = LIMBS from rfl)]
  simp (disch := decide) only [index_usize_eq rhs, Lane.muladd_row_refines,
    Lane.reduce_row_refines, bind_tc_ok, ofArray_toArray_id, laneOf_fromLanes]
  simp (disch := decide) only [index_usize_toArray, bind_tc_ok, update_eq, set_toArray, sub_ok,
    show (8#usize).val = LIMBS from rfl]
  rw [Fp8.mul_loop_refines _ _ _ _ rfl]
  simp only [toFp8, Fp8.mul, Fp8.limbs_ofLanes_ofFn, Fp8.lane_eq, limbs_ofFp8, bind_tc_ok,
    ofArray_toArray_id, laneOf_fromLanes, laneOf_set]
  refine congrArg (fun F => ok (toArray id (fromLanes F) rfl)) (funext fun l => ?_)
  simp only [Lane.mul, Lane.mulAcc, Lane.mulWith, Lane.splat_limbs_eq, Lane.splat_eq, Lane.zero,
    laneOf_replicate, Fin.getElem_fin, Simd.getElem_zero, Simd.getElem_splat, getElem_laneOf,
    getElem_ofArray, id_eq, UScalar.ofNatCore_val_eq, ofU64_toU64, getElem_fromLanes,
    Simd.laneOf_splat_limbs, ofArray_toArray_ofU64, fin_mk_zero, fin_mk_one, fin_mk_ofNat]))

attribute [local irreducible] Lane.reduce_row in
example : ∀ self rhs : fp8.Fp8,
    mulWith 7#usize self rhs = ok (toFp8 ((ofFp8 self).mul (ofFp8 rhs))) := by
  mul_proof

attribute [local irreducible] Lane.reduce_row in
example : True := by
  fail_if_success
    have : ∀ self rhs : fp8.Fp8,
        mulWith 6#usize self rhs = ok (toFp8 ((ofFp8 self).mul (ofFp8 rhs))) := by
      mul_proof
  trivial

attribute [local irreducible] Lane.reduce_row in
theorem mulWith_six_refines : ∀ self rhs : fp8.Fp8,
    mulWith 6#usize self rhs = ok (toFp8 (Fp8.ofLanes (.ofFn fun l =>
      Lane.mulWith 6 ((ofFp8 self).lane l) ((ofFp8 rhs).lane l)))) := by
  mul_proof

theorem lane_mulWith_six_ne :
    Lane.mulWith 6 (.ofList R2_MOD_P) (.ofList R2_MOD_P) ≠
      Lane.mul (.ofList R2_MOD_P) (.ofList R2_MOD_P) := by
  decide +kernel

example : ¬ ∀ self rhs : fp8.Fp8,
    mulWith 6#usize self rhs = ok (toFp8 ((ofFp8 self).mul (ofFp8 rhs))) := by
  intro h
  let x := toFp8 (Fp8.splat_limbs (.ofList R2_MOD_P))
  have e := congrArg ofFp8 (Result.ok.inj ((mulWith_six_refines x x).symm.trans (h x x)))
  simp only [ofFp8_toFp8] at e
  have e0 := congrArg (Fp8.lane · 0) e
  simp only [Fp8.mul, Fp8.lane_ofLanes, Vector.getElem_ofFn, x, ofFp8_toFp8,
    Fp8.lane_splat_limbs] at e0
  exact lane_mulWith_six_ne e0

/-! ## `Fp8::pow_p_minus_3_over_4`: the start of the window loop

The window loop counts down from 94, after window 94 has picked the starting entry. A generated
`pow_p_minus_3_over_4` that counts down from 95 reads window 94 twice, and must not refine the
model's. The same script proves that this mutant refines a model folding over `List.range 95`.
That model raises a lane to the power (p − 3)/4 + 3 · 2^381, and on a lane holding 2 the two
powers differ. So the mutated claim is false, not only unproved. -/

section Pow

open EthCryptographySpecs.Bls

def powWith (start : Usize) (self : fp8.Fp8) : Result fp8.Fp8 := do
  let f ← fp8.Fp8.one
  let table := Array.repeat 16#usize f
  let a ← Array.update table 1#usize self
  let table1 ← fp8.Fp8.pow_p_minus_3_over_4_loop0 { start := 2#usize, «end» := 16#usize } self a
  let i ← Array.index_usize constants.P_MINUS_3_OVER_4_WINDOWS 94#usize
  let i1 ← lift (UScalar.cast .Usize i)
  let r ← Array.index_usize table1 i1
  fp8.Fp8.pow_p_minus_3_over_4_loop1 table1 r start

example : powWith 94#usize = fp8.Fp8.pow_p_minus_3_over_4 := rfl

def Fp8.powWith (n : ℕ) (self : Fp8) : Fp8 :=
  let table : Vector Fp8 16 := .replicate 16 one
  let table := table.set 1 self
  let table := ((List.finRange 16).drop 2).foldl (init := table) fun table (k : Fin 16) =>
    table.set k (table[k.val - 1].mul self)
  let r := table[P_MINUS_3_OVER_4_WINDOWS[94]!]!
  (List.range n).reverse.foldl (windowStep table) r

example : Fp8.powWith 94 = Fp8.pow_p_minus_3_over_4 := rfl

set_option hygiene false in
/-- The proof of `Fp8.pow_p_minus_3_over_4_refines`, over `powWith`, and over `Fp8.powWith` where
the claim names it. -/
local macro "pow_proof" : tactic => `(tactic| (
  intro self
  unfold powWith
  simp only [Fp8.one_refines, bind_tc_ok]
  rw [← toArray_replicate toFp8 Fp8.one (show (16#usize).val = 16 from rfl),
    update_eq _ _ _ (by decide),
    toArray_set_of_eq toFp8 _ _ 1#usize 1 (by decide) (ofFp8 self) self rfl (by simp)]
  simp only [bind_tc_ok, Fp8.pow_table_refines]
  have h94 : P_MINUS_3_OVER_4_WINDOWS[94]! < 16 := windows_lt 94 (by simp)
  simp only [bind_tc_ok, P_MINUS_3_OVER_4_WINDOWS_index 94#usize (by decide), lift,
    cast_Usize_ofNatCore]
  rw [index_usize_toArray _ _ _ _ (by rw [UScalar.ofNatCore_val_eq]; exact h94)]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  rw [Fp8.pow_windows_refines _ _ _ _ rfl (by decide),
    ← getElem!_pos _ P_MINUS_3_OVER_4_WINDOWS[94]! h94]
  simp only [Fp8.pow_p_minus_3_over_4, Fp8.powWith, UScalar.ofNatCore_val_eq]))

example : ∀ self : fp8.Fp8,
    powWith 94#usize self = ok (toFp8 (ofFp8 self).pow_p_minus_3_over_4) := by
  pow_proof

example : True := by
  fail_if_success
    have : ∀ self : fp8.Fp8,
        powWith 95#usize self = ok (toFp8 (ofFp8 self).pow_p_minus_3_over_4) := by
      pow_proof
  trivial

theorem powWith_95_refines : ∀ self : fp8.Fp8,
    powWith 95#usize self = ok (toFp8 (Fp8.powWith 95 (ofFp8 self))) := by
  pow_proof

/-- The exponent of `Fp8.powWith 95`: window 94 enters twice. -/
theorem windows_horner_95 :
    (List.range 95).reverse.foldl (fun e w => 16 * e + P_MINUS_3_OVER_4_WINDOWS[w]!)
      P_MINUS_3_OVER_4_WINDOWS[94]! = (Fp.modulus - 3) / 4 + 3 * 2 ^ 381 := by
  decide +kernel

theorem lane_powWith_95 {x : Fp8} {l : Fin 8} (hx : Fp8Inv (x.lane l)) :
    decode ((Fp8.powWith 95 x).lane l) =
      decode (x.lane l) ^ ((Fp.modulus - 3) / 4 + 3 * 2 ^ 381) := by
  have ht := Fp8.table_fold hx ((List.finRange 16).drop 2) 1 _ le_rfl rfl (Fp8.part_table_init hx)
  unfold Fp8.powWith
  dsimp only
  generalize ((List.finRange 16).drop 2).foldl _ _ = table at ht ⊢
  have h94 : P_MINUS_3_OVER_4_WINDOWS[94]! < 16 := by decide
  have ht94 := ht ⟨_, h94⟩
  simp only [Fin.getElem_fin] at ht94
  rw [← getElem!_pos table _ h94] at ht94
  have := Fp8.window_fold ht ((List.range 95).reverse) _ _
    (fun w hw => windows_lt w (by simpa using hw)) ht94.1 ht94.2
  rw [windows_horner_95] at this
  exact this.2

/-- `x ^ 2 ^ k % m`, by `k` squarings, so that the kernel can evaluate it for `k = 381`. -/
def sqIter (m : ℕ) : ℕ → ℕ → ℕ
  | 0, x => x
  | k + 1, x => sqIter m k (x * x % m)

theorem sqIter_eq (m k x : ℕ) : ((sqIter m k x : ℕ) : ZMod m) = (x : ZMod m) ^ 2 ^ k := by
  induction k generalizing x with
  | zero => simp [sqIter]
  | succ k ih =>
    rw [sqIter, ih, ZMod.natCast_mod, Nat.cast_mul, pow_succ, pow_mul, sq, mul_pow]

theorem two_pow_ne_one : ((2 : ℕ) : ZMod Fp.modulus) ^ (3 * 2 ^ 381) ≠ 1 := by
  rw [pow_mul, show ((2 : ℕ) : ZMod Fp.modulus) ^ 3 = ((8 : ℕ) : ZMod Fp.modulus) by norm_num,
    ← sqIter_eq]
  intro h
  have := congrArg ZMod.val h
  rw [ZMod.val_natCast, ZMod.val_one] at this
  revert this
  decide +kernel

example : ¬ ∀ self : fp8.Fp8,
    powWith 95#usize self = ok (toFp8 (ofFp8 self).pow_p_minus_3_over_4) := by
  intro h
  let v : Vector Limbs 8 := .replicate 8 (.ofList [2])
  have hv : Fp8Inv v[(0 : Fin 8)] := ⟨by decide, by decide +kernel⟩
  have hval : val v[(0 : Fin 8)] = 2 := by decide +kernel
  obtain ⟨hx, hdx⟩ := Fp8.lane_from_plain (l := 0) hv
  have e := congrArg ofFp8 (Result.ok.inj
    ((powWith_95_refines (toFp8 (Fp8.from_plain v))).symm.trans (h (toFp8 (Fp8.from_plain v)))))
  simp only [ofFp8_toFp8] at e
  have h1 := lane_powWith_95 hx
  rw [e, (Fp8.lane_pow_p_minus_3_over_4 hx).2, hdx, hval, pow_add] at h1
  have h2 : ((2 : ℕ) : ZMod Fp.modulus) ^ ((Fp.modulus - 3) / 4) ≠ 0 := by
    apply pow_ne_zero
    rw [Ne, ZMod.natCast_eq_zero_iff]
    decide +kernel
  exact two_pow_ne_one ((mul_eq_left₀ h2).mp h1.symm)

end Pow

/-! ## `G2x8::times_minus_z`: the bits that add

The countdown compares the counter with `Z_BITS[1]` to `Z_BITS[5]` and adds the point at each. A
generated loop whose last comparison reads `Z_BITS[4]` again never adds at bit 16, and must not
refine the model's loop. The script fails on the mutant. A concrete refutation of the entire
loop would require evaluating both chains past bit 16, with thousands of lane multiplications.

The concrete check instead refutes the step required by `loop_countdown`. At counter 17, from
the point (0, 1, 1) with the affine point (0, 0) and mask 0, the mutant body returns mask 0 and
`chainStep` returns 255. Doubling (0, 1, 1) gives x = 0, so the addition's H = 0 · Z² − 0 is zero
on every lane. -/

def timesMinusZBodyWith (k : Usize) (px py : fp2x8.Fp2x8) (undecided : U8) (r : g2x8.G2x8)
    (bit : U32) : Result (ControlFlow (U8 × g2x8.G2x8 × U32) (g2x8.G2x8 × U8)) := do
  if bit > 0#u32
  then
    let bit1 ← bit - 1#u32
    let (d, u) ← g2x8.G2x8.double r
    let undecided1 ← lift (undecided ||| u)
    let i ← Array.index_usize constants.Z_BITS 1#usize
    if bit1 = i
    then
      let (a, u1) ← g2x8.G2x8.add_affine d px py
      let undecided2 ← lift (undecided1 ||| u1)
      ok (cont (undecided2, a, bit1))
    else
      let i1 ← Array.index_usize constants.Z_BITS 2#usize
      if bit1 = i1
      then
        let (a, u1) ← g2x8.G2x8.add_affine d px py
        let undecided2 ← lift (undecided1 ||| u1)
        ok (cont (undecided2, a, bit1))
      else
        let i2 ← Array.index_usize constants.Z_BITS 3#usize
        if bit1 = i2
        then
          let (a, u1) ← g2x8.G2x8.add_affine d px py
          let undecided2 ← lift (undecided1 ||| u1)
          ok (cont (undecided2, a, bit1))
        else
          let i3 ← Array.index_usize constants.Z_BITS 4#usize
          if bit1 = i3
          then
            let (a, u1) ← g2x8.G2x8.add_affine d px py
            let undecided2 ← lift (undecided1 ||| u1)
            ok (cont (undecided2, a, bit1))
          else
            let i4 ← Array.index_usize constants.Z_BITS k
            if bit1 = i4
            then
              let (a, u1) ← g2x8.G2x8.add_affine d px py
              let undecided2 ← lift (undecided1 ||| u1)
              ok (cont (undecided2, a, bit1))
            else ok (cont (undecided1, d, bit1))
  else ok (done (r, undecided))

def timesMinusZLoopWith (k : Usize) (px py : fp2x8.Fp2x8) (undecided : U8) (r : g2x8.G2x8)
    (bit : U32) : Result (g2x8.G2x8 × U8) :=
  loop (fun (undecided1, r1, bit1) => timesMinusZBodyWith k px py undecided1 r1 bit1)
    (undecided, r, bit)

example : timesMinusZLoopWith 5#usize = g2x8.G2x8.times_minus_z_loop := rfl

set_option hygiene false in
/-- The proof of `G2x8.times_minus_z_loop_refines`, over `timesMinusZLoopWith`. -/
local macro "times_minus_z_loop_proof" : tactic => `(tactic| (
  intro px py m c n hcn hn
  unfold timesMinusZLoopWith
  refine loop_countdown _ (fun (m : G2x8 × Mmask8) c => (toU8 m.2, toG2x8 m.1, c))
    (G2x8.chainStep (ofFp2x8 px) (ofFp2x8 py)) (Prod.map toG2x8 toU8) n ?_ ?_ c m hcn
  · intro m c hc
    simp [timesMinusZBodyWith, hc]
    rfl
  · intro ⟨r, u⟩ c c' hc hcn
    obtain ⟨⟨d, du⟩, hd⟩ : ∃ d, r.double = d := ⟨_, rfl⟩
    obtain ⟨⟨a, au⟩, ha⟩ : ∃ a, d.add_affine (ofFp2x8 px) (ofFp2x8 py) = a := ⟨_, rfl⟩
    simp only [timesMinusZBodyWith]
    rw [if_pos (by simp; omega), sub_ok _ _ (by simp; omega)]
    have e : (UScalar.ofNatCore (c.val - (1#u32).val) (by have := c.hBounds; omega) : U32) =
        c' :=
      UScalar.eq_of_val_eq (by simp; omega)
    rw [e]
    simp (disch := decide) only [bind_tc_ok, G2x8.double_refines, Function.uncurry_def,
      Prod.map_fst, Prod.map_snd, ofG2x8_toG2x8, lift, Z_BITS_index, toU8_or,
      G2x8.add_affine_refines, UScalar.eq_equiv, UScalar.ofNatCore_val_eq]
    simp only [show Z_BITS[1]! = 62 from rfl, show Z_BITS[2]! = 60 from rfl,
      show Z_BITS[3]! = 57 from rfl, show Z_BITS[4]! = 48 from rfl, show Z_BITS[5]! = 16 from rfl]
    simp only [G2x8.chainStep, hd, ha]
    by_cases h : c'.val = 62 ∨ c'.val = 60 ∨ c'.val = 57 ∨ c'.val = 48 ∨ c'.val = 16
    · have hz : Z_BITS.contains c'.val := by simp [Z_BITS]; omega
      rw [if_pos hz]
      rcases h with h | h | h | h | h <;> simp [h]
    · have hz : c'.val ∉ Z_BITS := by simp [Z_BITS]; omega
      simp only [not_or] at h
      simp [h, hz]))

example : ∀ (px py : fp2x8.Fp2x8) (m : G2x8 × Mmask8) (c : U32) (n : ℕ),
    c.val = n → n ≤ 63 →
    timesMinusZLoopWith 5#usize px py (toU8 m.2) (toG2x8 m.1) c =
      ok (Prod.map toG2x8 toU8
        ((List.range n).reverse.foldl (G2x8.chainStep (ofFp2x8 px) (ofFp2x8 py)) m)) := by
  times_minus_z_loop_proof

example : True := by
  fail_if_success
    have : ∀ (px py : fp2x8.Fp2x8) (m : G2x8 × Mmask8) (c : U32) (n : ℕ),
        c.val = n → n ≤ 63 →
        timesMinusZLoopWith 4#usize px py (toU8 m.2) (toG2x8 m.1) c =
          ok (Prod.map toG2x8 toU8
            ((List.range n).reverse.foldl (G2x8.chainStep (ofFp2x8 px) (ofFp2x8 py)) m)) := by
      times_minus_z_loop_proof
  trivial

/-- The point (0, 1, 1) in Jacobian coordinates, on every lane. -/
def zeroOneOne : G2x8 := ⟨⟨Fp8.zero, Fp8.zero⟩, Fp2x8.one, Fp2x8.one⟩

theorem double_zeroOneOne_mask : (zeroOneOne.double).2 = 0 := by
  decide +kernel

theorem add_affine_zero_mask :
    (zeroOneOne.double.1.add_affine ⟨Fp8.zero, Fp8.zero⟩ ⟨Fp8.zero, Fp8.zero⟩).2 = 255 := by
  decide +kernel

example : ¬ ∀ (px py : fp2x8.Fp2x8) (m : G2x8 × Mmask8) (c c' : U32),
    c.val = c'.val + 1 → c.val ≤ 63 →
    timesMinusZBodyWith 4#usize px py (toU8 m.2) (toG2x8 m.1) c =
      ok (cont (toU8 (G2x8.chainStep (ofFp2x8 px) (ofFp2x8 py) m c'.val).2,
        toG2x8 (G2x8.chainStep (ofFp2x8 px) (ofFp2x8 py) m c'.val).1, c')) := by
  intro h
  have e := h (toFp2x8 ⟨Fp8.zero, Fp8.zero⟩) (toFp2x8 ⟨Fp8.zero, Fp8.zero⟩) (zeroOneOne, 0) 17#u32
    16#u32 (by decide) (by decide)
  simp only [timesMinusZBodyWith] at e
  rw [if_pos (by decide), sub_ok _ _ (by decide)] at e
  simp (disch := decide) only [bind_tc_ok, G2x8.double_refines, Function.uncurry_def,
    Prod.map_fst, Prod.map_snd, ofG2x8_toG2x8, lift, Z_BITS_index, toU8_or,
    UScalar.eq_equiv, UScalar.ofNatCore_val_eq] at e
  simp only [show Z_BITS[1]! = 62 from rfl, show Z_BITS[2]! = 60 from rfl,
    show Z_BITS[3]! = 57 from rfl, show Z_BITS[4]! = 48 from rfl] at e
  rw [if_neg (by decide), if_neg (by decide), if_neg (by decide), if_neg (by decide),
    if_neg (by decide)] at e
  have hz : Z_BITS.contains 16 = true := by decide
  simp only [G2x8.chainStep, hz, if_true, ofFp2x8_toFp2x8, double_zeroOneOne_mask,
    add_affine_zero_mask, ok.injEq, cont.injEq, Prod.mk.injEq] at e
  exact absurd e.1 (by decide)

namespace G1Fallback

open DecompressG1 UncompressG1

/-! ## `decompress_g1_chunk`: the fallback lane

An undecided lane must pass its own encoding to blst. Reading `chunk[0]` instead of
`chunk[lane]` must not refine `UncompressG1.chunk`. The proof rejects the mutation.
A concrete step refutes the mutant's agreement with the original body: with all lanes
undecided and distinct scalar verdicts on inputs 0 and 1, lane 1 receives `none`
instead of `some`. This checks the loop step without evaluating decompression. -/

def chunkBodyWith [G1Externals] (fallbackLane : Usize → Usize)
  (chunk : Array (Array Std.U8 48#usize) 8#usize) (batch : decompress.Batch)
  (iter : core.ops.range.Range Std.Usize)
  (out : Slice (Option blst.blst_p1_affine)) :
  Result (ControlFlow ((core.ops.range.Range Std.Usize) × (Slice (Option
    blst.blst_p1_affine))) (Slice (Option blst.blst_p1_affine)))
  := do
  let (o, iter1) ←
    core.iter.range.IteratorRange.next core.iter.range.StepUsize iter
  match o with
  | none => ok (done out)
  | some lane =>
    let bit ← 1#u8 <<< lane
    let i ← lift (batch.undecided &&& bit)
    let (iter2, o1) ←
      if i != 0#u8
      then
        do
        let a ← Array.index_usize chunk (fallbackLane lane)
        let o2 ← uncompress_in_g1_blst a
        ok (iter1, o2)
      else
        do
        let i1 ← lift (batch.valid &&& bit)
        let o2 ←
          if i1 != 0#u8
          then do
               let bpa ← Array.index_usize batch.points lane
               ok (some bpa)
          else ok none
        ok (iter1, o2)
    let s ← Slice.update out lane o1
    ok (cont (iter2, s))

example [G1Externals] : chunkBodyWith id = decompress_g1_chunk_loop.body := rfl

def chunkWith [G1Externals] (fallbackLane : Usize → Usize)
    (inputs : Array (Array U8 48#usize) 8#usize)
    (out : Slice (Option blst.blst_p1_affine)) : Result (Slice (Option blst.blst_p1_affine)) := do
  let batch ← decompress.decompress inputs
  loop (fun (iter, out) => chunkBodyWith fallbackLane inputs batch iter out)
    ({ start := 0#usize, «end» := LANES }, out)

example [G1Externals] : chunkWith id = decompress_g1_chunk := rfl

private theorem mask_bit (m : UInt8) (l : Fin 8) :
    (toU8 m &&& toU8 (1 <<< l.val.toUInt8) != 0#u8) = m.toNat.testBit l := by
  rw [Bool.eq_iff_iff]
  simp only [bne_iff_ne, toU8_and]
  change (toU8 (m &&& (1 <<< l.val.toUInt8)) ≠ toU8 0 ↔ _)
  simp only [ne_eq, toU8_inj]
  exact Mmask8.and_one_shiftLeft_ne_zero m l

private def vectorSlice {α : Type} {n : ℕ} (v : Vector α n) (h : n ≤ Usize.max) : Slice α :=
  ⟨v.toList, by simpa using h⟩

private theorem slice_update_ok {α : Type} (s : Slice α) (i : Usize) (x : α)
    (h : i.val < s.val.length) : Slice.update s i x = ok (s.set i x) := by
  simp [Slice.update, h, Slice.set, Slice.setAtNat]

private theorem vectorSlice_set {α : Type} {n : ℕ} (v : Vector α n) (h : n ≤ Usize.max)
    (i : Usize) (hi : i.val < n) (x : α) :
    (vectorSlice v h).set i x = vectorSlice (v.set i.val x hi) h := by
  apply Subtype.ext
  simp [vectorSlice, Slice.set, Slice.setAtNat, Vector.toList_set]

private theorem modelBlst_roundtrip [G1Externals] (a : Array U8 48#usize) :
    (modelBlst (ofArray ofU8 a)).map toBlstP1Affine = G1Externals.uncompress a := by
  simp [modelBlst, toArray_ofArray, Option.map_map, Function.comp_def]

set_option hygiene false in
/-- The proof of `UncompressG1.chunk_refines`, over `chunkWith`. -/
local macro "chunk_proof" : tactic => `(tactic| (
  intro inputs out hlen
  let b := decompress (ofArray (ofArray ofU8) inputs)
  let target := (chunk modelBlst (ofArray (ofArray ofU8) inputs)).map (Option.map toBlstP1Affine)
  have hb : 8 ≤ Usize.max := by scalar_tac
  let enc := fun v : Vector (Option blst.blst_p1_affine) 8 => vectorSlice v hb
  have ho : enc (ofSlice id out hlen) = out := by
    apply Subtype.ext
    simp [enc, vectorSlice]
  refine ⟨enc target, ?_, by simp [enc, vectorSlice, target, Vector.toList_map]⟩
  rw [chunkWith, decompress_refines]
  simp only [bind_tc_ok]
  rw [← ho]
  apply loop_range (n := 8) _ LANES (by simp [LANES]) enc
    (fun v j => v.set j (target[j])) enc (ofSlice id out hlen) (enc target)
  · intro r v he hs hn
    simp only [chunkBodyWith, id_eq, hn, bind_tc_ok, Function.uncurry_apply_pair]
  · intro r r' v j he hs he' hs' hn
    have hj : r.start.val < 8 := by omega
    simp only [chunkBodyWith, id_eq, hn, bind_tc_ok, Function.uncurry_apply_pair]
    rw [toU8_shiftLeft_one _ hj]
    simp only [lift, bind_tc_ok, toBatch]
    rw [show r.start.val = j.val from hs, mask_bit]
    have ht : target[j] =
        if b.undecided.toNat.testBit j then G1Externals.uncompress (inputs.val[j.val]'(by simp [inputs.property]))
        else if b.valid.toNat.testBit j then some (toBlstP1Affine b.points[j]) else none := by
      simp only [target, chunk, Fin.getElem_fin, Vector.getElem_map, Vector.getElem_ofFn, laneVerdict]
      split
      · simp only [getElem_ofArray, modelBlst_roundtrip]
      · split <;> rfl
    cases hu : b.undecided.toNat.testBit j
    · simp only [Bool.false_eq_true, ↓reduceIte]
      rw [mask_bit]
      cases hv : b.valid.toNat.testBit j
      · simp only [Bool.false_eq_true, ↓reduceIte, bind_tc_ok, Function.uncurry_apply_pair]
        rw [slice_update_ok _ _ _ (by simp [enc, vectorSlice, hs]), vectorSlice_set v hb r.start hj]
        simp only [bind_tc_ok, enc, ht, hu, hv, hs, Bool.false_eq_true, ↓reduceIte]
      · simp only [↓reduceIte]
        rw [index_usize_toArray _ _ _ _ hj]
        simp only [bind_tc_ok, Function.uncurry_apply_pair]
        rw [slice_update_ok _ _ _ (by simp [enc, vectorSlice, hs]), vectorSlice_set v hb r.start hj]
        simp only [bind_tc_ok, enc, ht, hu, hv, hs, Bool.false_eq_true, ↓reduceIte]
        rfl
    · simp only [↓reduceIte]
      rw [index_usize_eq _ _ (by first | exact hj | decide)]
      simp only [uncompress_in_g1_blst, bind_tc_ok, Function.uncurry_apply_pair]
      rw [slice_update_ok _ _ _ (by simp [enc, vectorSlice, hs]), vectorSlice_set v hb r.start hj]
      simp only [bind_tc_ok, enc, ht, hu, hs, ↓reduceIte]
  · rw [foldl_set_ofFn]
    congr 1
    ext i hi
    simp))

example [G1Externals] : ∀ (inputs : Array (Array U8 48#usize) 8#usize)
    (out : Slice (Option blst.blst_p1_affine)), out.val.length = 8 →
    ∃ result, chunkWith id inputs out = ok result ∧
      result.val = ((chunk modelBlst (ofArray (ofArray ofU8) inputs)).toList.map
        (Option.map toBlstP1Affine)) := by
  chunk_proof

example [G1Externals] : True := by
  fail_if_success
    have : ∀ (inputs : Array (Array U8 48#usize) 8#usize)
        (out : Slice (Option blst.blst_p1_affine)), out.val.length = 8 →
        ∃ result, chunkWith (fun _ => 0#usize) inputs out = ok result ∧
          result.val = ((chunk modelBlst (ofArray (ofArray ofU8) inputs)).toList.map
            (Option.map toBlstP1Affine)) := by
      chunk_proof
  trivial

/-- Distinct scalar verdicts expose a fallback read from the wrong lane. -/
@[reducible] def distinguishingExternals : G1Externals :=
  ⟨true, fun bytes =>
    if bytes.val[0]!.val = 0 then none else some (toBlstP1Affine default)⟩

def distinctInputs : Array (Array U8 48#usize) 8#usize :=
  toArray (toArray toU8) (Vector.ofFn fun (lane : Fin 8) =>
    Vector.replicate 48 lane.val.toUInt8)

def undecidedBatch : decompress.Batch :=
  toBatch ⟨Vector.replicate 8 default, 0, 255⟩

def emptyOutput : Slice (Option blst.blst_p1_affine) :=
  vectorSlice (Vector.replicate 8 none) (by scalar_tac)

def laneOneVerdict (result : Result (ControlFlow
    (core.ops.range.Range Usize × Slice (Option blst.blst_p1_affine))
    (Slice (Option blst.blst_p1_affine)))) : Bool :=
  match result with
  | ok (cont (_, out)) => out.val[1]!.isSome
  | _ => false

set_option hygiene false in
local macro "lane_one_proof" : tactic => `(tactic| (
  obtain ⟨next, _, _, hn⟩ := next_lt
    { start := 1#usize, «end» := 8#usize } (by decide)
  simp only [chunkBodyWith, hn, bind_tc_ok, Function.uncurry_apply_pair]
  rw [toU8_shiftLeft_one _ (by decide)]
  rfl))

theorem original_lane_one : laneOneVerdict
    (@chunkBodyWith distinguishingExternals id distinctInputs undecidedBatch
      { start := 1#usize, «end» := 8#usize } emptyOutput) = true := by
  lane_one_proof

theorem mutated_lane_one : laneOneVerdict
    (@chunkBodyWith distinguishingExternals (fun _ => 0#usize) distinctInputs undecidedBatch
      { start := 1#usize, «end» := 8#usize } emptyOutput) = false := by
  lane_one_proof

example : @chunkBodyWith distinguishingExternals (fun _ => 0#usize) distinctInputs undecidedBatch
    { start := 1#usize, «end» := 8#usize } emptyOutput ≠
    @chunkBodyWith distinguishingExternals id distinctInputs undecidedBatch
      { start := 1#usize, «end» := 8#usize } emptyOutput := by
  intro h
  have e := congrArg laneOneVerdict h
  rw [original_lane_one, mutated_lane_one] at e
  contradiction

end G1Fallback

end LeanBlsSimd
