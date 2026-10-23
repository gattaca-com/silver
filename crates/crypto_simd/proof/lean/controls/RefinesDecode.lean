import controls.G1Fallback
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
open silver_crypto_simd silver_crypto_simd.bls

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
    decompress_g2.decode_loop { start := 0#usize, «end» := limbs.LANES } inputs
        (decodeState decodeInit).1 (decodeState decodeInit).2.1 (decodeState decodeInit).2.2.1
        (decodeState decodeInit).2.2.2.1 (decodeState decodeInit).2.2.2.2 =
      ok (decodeState ((List.finRange 8).foldl
        (decodeStepWith false (ofArray (ofArray ofU8) inputs)) decodeInit)) := by
  decode_loop_proof

example : True := by
  fail_if_success
    have : ∀ inputs : Array (Array U8 96#usize) 8#usize,
        decompress_g2.decode_loop { start := 0#usize, «end» := limbs.LANES } inputs
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
    let i2 ← encoding.FP_BYTES
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

example : fpWordsWith ok = encoding.fp_words := rfl

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

end LeanBlsSimd
