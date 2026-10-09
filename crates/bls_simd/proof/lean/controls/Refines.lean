import LeanBlsSimd.Refines.DecompressG2

/-! Negative controls for `LeanBlsSimd/Refines/`. Each `fail_if_success` wraps a claim that must
fail; each plain `example` must pass.

Each control runs a library proof script against a mutant. The mutant takes the mutated part as a
parameter, and `rfl` pins its unmutated instance to the original. The same script proves the
unmutated claim, so the mutation alone makes it fail. -/

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

end LeanBlsSimd
