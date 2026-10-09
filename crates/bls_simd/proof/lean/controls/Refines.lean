import LeanBlsSimd.Refines.DecompressG2
import LeanBlsSimd.Refines.G2x8
import LeanBlsSimd.Proofs.Convert

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
  (List.finRange (LIMBS - 1)).foldl (init := r) fun r (j : Fin (LIMBS - 1)) =>
    let r := r.set (j.val + 1) (t[LIMBS + j.val + 1] + srli 52 r[j.val])
    r.set j.val (r[j.val] &&& mask)

example : Lane.mulWith 7 = Lane.mul := rfl

set_option hygiene false in
/-- The proof of `Fp8.mul_refines`, over `mulWith`, and over `Lane.mulWith` where the claim
names it. -/
-- Each use needs the headroom `Fp8.mul_refines` has: 150k-200k heartbeats.
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
  simp only [Lane.mul, Lane.mulWith, Lane.splat_limbs_eq, Lane.splat_eq, Lane.zero,
    laneOf_replicate, Fin.getElem_fin, Simd.getElem_zero, Simd.getElem_splat, getElem_laneOf,
    getElem_ofArray, id_eq, UScalar.ofNatCore_val_eq, ofU64_toU64, getElem_fromLanes,
    Simd.laneOf_splat_limbs, ofArray_toArray_ofU64, fin_mk_zero, fin_mk_one, fin_mk_ofNat]))

set_option maxHeartbeats 400000 in
example : ∀ self rhs : fp8.Fp8,
    mulWith 7#usize self rhs = ok (toFp8 ((ofFp8 self).mul (ofFp8 rhs))) := by
  mul_proof

set_option maxHeartbeats 400000 in
example : True := by
  fail_if_success
    have : ∀ self rhs : fp8.Fp8,
        mulWith 6#usize self rhs = ok (toFp8 ((ofFp8 self).mul (ofFp8 rhs))) := by
      mul_proof
  trivial

set_option maxHeartbeats 400000 in
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
  (List.range n).reverse.foldl (init := r) fun r w =>
    let r := r.square.square.square.square
    let digit := P_MINUS_3_OVER_4_WINDOWS[w]!
    if digit ≠ 0 then r.mul table[digit]! else r

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
  unfold Fp8.windowStep
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
refine the model's loop. This control shows only that the script fails on the mutant. Refuting
the mutated claim means evaluating both chains past bit 16 on a concrete point: over 2000 lane
multiplications, at about 0.1 s each in Lean's kernel. -/

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
  · intro m c c' hc hcn
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
    unfold G2x8.chainStep
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

end LeanBlsSimd
