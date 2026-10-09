import LeanBlsSimd.Proofs.Fp8

/-!
# Conversions: plain integers, blst's limbs, and the larger root

`from_plain` and `to_plain` move between plain integers and Montgomery form through `load` and
`store`; `is_larger_root_mask` compares a lane's plain value with (p − 1)/2. `unpack52` and
`pack64` convert between six 64-bit words and eight 52-bit limbs, exactly on values below 2^384;
`to_blst_limbs` gives each lane as the six words of blst's Montgomery form, with R = 2^384.

`pack64` relies on `u128` holding every intermediate: before each limb its accumulator holds
fewer than 64 bits, so the shifted limb lands on bits the accumulator does not use, and the sum
stays below 2^116.
-/

namespace LeanBlsSimd

open EthCryptographySpecs.Bls

namespace Fp8

/-- Lane `l` of `to_plain`: the canonical integer of the field element the lane holds. -/
theorem getElem_to_plain {x : Fp8} {l : Fin 8} (hx : Fp8Inv (x.lane l)) :
    Fp8Inv x.to_plain[l] ∧ val x.to_plain[l] = (decode (x.lane l)).val := by
  have hone : Fp8Inv ((splat_limbs (.ofList ONE_PLAIN)).lane l) := by
    rw [lane_splat_limbs]
    exact inv_ofList_ONE_PLAIN
  obtain ⟨hc, hcv⟩ := lane_canonical (inv_mul hx hone)
  rw [to_plain, getElem_store]
  refine ⟨hc, ?_⟩
  rw [hcv, ← ZMod.val_natCast, lane_mul, (LeanBlsSimd.mul_spec hx hone).2, lane_splat_limbs,
    val_ofList_ONE_PLAIN, Nat.cast_one, mul_one, decode]

theorem val_to_plain_lt {x : Fp8} {l : Fin 8} (hx : Fp8Inv (x.lane l)) :
    val x.to_plain[l] < Fp.modulus := by
  rw [(getElem_to_plain hx).2]
  exact ZMod.val_lt _

theorem lane_from_plain {values : Vector Limbs 8} {l : Fin 8} (hv : Fp8Inv values[l]) :
    Fp8Inv ((from_plain values).lane l) ∧ decode ((from_plain values).lane l) = val values[l] := by
  have hr2 : Fp8Inv ((splat_limbs (.ofList R2_MOD_P)).lane l) := by
    rw [lane_splat_limbs]
    exact inv_ofList_R2_MOD_P
  have hl : Fp8Inv ((load values).lane l) := by rwa [lane_load]
  refine ⟨inv_mul hl hr2, ?_⟩
  rw [from_plain, decode_lane_mul hl hr2, lane_load, lane_splat_limbs, decode_ofList_R2_MOD_P,
    decode, mul_assoc, inv_mul_cancel₀ R_ne_zero, mul_one]

/-- Bit `l` is set exactly when the field element in lane `l` exceeds (p − 1)/2 as an integer
below p. -/
theorem testBit_is_larger_root_mask {x : Fp8} {l : Fin 8} (hx : Fp8Inv (x.lane l)) :
    x.is_larger_root_mask.toNat.testBit l =
      decide ((Fp.modulus - 1) / 2 < (decode (x.lane l)).val) := by
  obtain ⟨hc, hcv⟩ := getElem_to_plain hx
  have hl := Simd.sub_limbs_lane (Simd.splat_limbs (.ofList HALF_P_MINUS_1)) (load x.to_plain).limbs l
  rw [Simd.laneOf_splat_limbs, ← lane_eq, lane_load] at hl
  obtain ⟨-, hb, -⟩ := Lane.sub_limbs_spec normal_ofList_HALF_P_MINUS_1 (fun j => hc.normal j)
  rw [← hl] at hb
  simp only at hb
  unfold is_larger_root_mask
  dsimp only
  rw [Simd.testBit_borrowed, hb, Lane.decide_borrowOf, val_ofList_HALF_P_MINUS_1, hcv]

end Fp8

theorem or_mul_two_pow {A B k : ℕ} (hA : A < 2 ^ k) : A ||| B * 2 ^ k = A + B * 2 ^ k := by
  rw [Nat.or_comm, ← Nat.shiftLeft_eq, ← Nat.shiftLeft_add_eq_or_of_lt hA, Nat.shiftLeft_eq,
    add_comm]

theorem toNat_mask52 : (UInt64.ofNat MASK52).toNat = 2 ^ 52 - 1 := by decide

theorem toNat_limb_one (a : UInt64) (s : ℕ) (hs : s < 64) :
    ((a >>> s.toUInt64) &&& .ofNat MASK52).toNat = a.toNat / 2 ^ s % 2 ^ 52 := by
  have hs64 : s.toUInt64.toNat % 64 = s := by
    rw [Nat.toUInt64_eq, UInt64.toNat_ofNat']
    omega
  rw [UInt64.toNat_and, toNat_mask52, Nat.and_two_pow_sub_one_eq_mod, UInt64.toNat_shiftRight,
    hs64, Nat.shiftRight_eq_div_pow]

theorem toNat_limb_two (a b : UInt64) (s : ℕ) (hs : 0 < s) (hs' : s < 64) :
    (((a >>> s.toUInt64) ||| b <<< (64 - s).toUInt64) &&& .ofNat MASK52).toNat =
      (a.toNat / 2 ^ s + b.toNat % 2 ^ s * 2 ^ (64 - s)) % 2 ^ 52 := by
  have ha := a.toNat_lt
  have hs64 : s.toUInt64.toNat % 64 = s := by
    rw [Nat.toUInt64_eq, UInt64.toNat_ofNat']
    omega
  have hr64 : (64 - s).toUInt64.toNat % 64 = 64 - s := by
    rw [Nat.toUInt64_eq, UInt64.toNat_ofNat']
    omega
  rw [UInt64.toNat_and, toNat_mask52, Nat.and_two_pow_sub_one_eq_mod, UInt64.toNat_or,
    UInt64.toNat_shiftRight, UInt64.toNat_shiftLeft, hs64, hr64, Nat.shiftRight_eq_div_pow,
    Nat.shiftLeft_eq, show (2 : ℕ) ^ 64 = 2 ^ s * 2 ^ (64 - s) by rw [← pow_add]; congr 1; omega,
    Nat.mul_mod_mul_right, or_mul_two_pow]
  rw [Nat.div_lt_iff_lt_mul (by positivity), ← pow_add, show 64 - s + s = 64 by omega]
  simpa using ha

/-- The value of six little-endian 64-bit words. -/
def val64 (x : Vector UInt64 6) : ℕ := ∑ j : Fin 6, x[j].toNat * 2 ^ (64 * j.val)

set_option exponentiation.threshold 1000 in
theorem val64_eq (x : Vector UInt64 6) : val64 x = x[0].toNat + x[1].toNat * 2 ^ 64 +
    x[2].toNat * 2 ^ 128 + x[3].toNat * 2 ^ 192 + x[4].toNat * 2 ^ 256 + x[5].toNat * 2 ^ 320 := by
  simp [val64, Fin.sum_univ_six]

set_option exponentiation.threshold 1000 in
/-- Every 384-bit value unpacks exactly: limb 7 takes the top 20 bits of word 5. -/
theorem unpack52_spec (x : Vector UInt64 6) :
    (∀ j : Fin LIMBS, (unpack52 x)[j].toNat < 2 ^ 52) ∧ val (unpack52 x) = val64 x := by
  have l0 : (unpack52 x)[0].toNat = x[0].toNat / 2 ^ 0 % 2 ^ 52 :=
    toNat_limb_one x[0] 0 (by norm_num)
  have l1 : (unpack52 x)[1].toNat = (x[0].toNat / 2 ^ 52 + x[1].toNat % 2 ^ 52 * 2 ^ (64 - 52)) %
      2 ^ 52 := toNat_limb_two x[0] x[1] 52 (by norm_num) (by norm_num)
  have l2 : (unpack52 x)[2].toNat = (x[1].toNat / 2 ^ 40 + x[2].toNat % 2 ^ 40 * 2 ^ (64 - 40)) %
      2 ^ 52 := toNat_limb_two x[1] x[2] 40 (by norm_num) (by norm_num)
  have l3 : (unpack52 x)[3].toNat = (x[2].toNat / 2 ^ 28 + x[3].toNat % 2 ^ 28 * 2 ^ (64 - 28)) %
      2 ^ 52 := toNat_limb_two x[2] x[3] 28 (by norm_num) (by norm_num)
  have l4 : (unpack52 x)[4].toNat = (x[3].toNat / 2 ^ 16 + x[4].toNat % 2 ^ 16 * 2 ^ (64 - 16)) %
      2 ^ 52 := toNat_limb_two x[3] x[4] 16 (by norm_num) (by norm_num)
  have l5 : (unpack52 x)[5].toNat = x[4].toNat / 2 ^ 4 % 2 ^ 52 :=
    toNat_limb_one x[4] 4 (by norm_num)
  have l6 : (unpack52 x)[6].toNat = (x[4].toNat / 2 ^ 56 + x[5].toNat % 2 ^ 56 * 2 ^ (64 - 56)) %
      2 ^ 52 := toNat_limb_two x[4] x[5] 56 (by norm_num) (by norm_num)
  have l7 : (unpack52 x)[7].toNat = x[5].toNat / 2 ^ 44 % 2 ^ 52 :=
    toNat_limb_one x[5] 44 (by norm_num)
  refine ⟨fun j => ?_, ?_⟩
  · fin_cases j <;> simp only [Fin.getElem_fin] <;>
      (first | rw [l0] | rw [l1] | rw [l2] | rw [l3] | rw [l4] | rw [l5] | rw [l6] | rw [l7]) <;>
      exact Nat.mod_lt _ (by norm_num)
  · have := x[0].toNat_lt; have := x[1].toNat_lt; have := x[2].toNat_lt
    have := x[3].toNat_lt; have := x[4].toNat_lt; have := x[5].toNat_lt
    rw [val_eq, val64_eq, l0, l1, l2, l3, l4, l5, l6, l7]
    omega

theorem set!_eq (xs : Vector UInt64 6) (i : ℕ) (x : UInt64) : xs.set! i x = xs.setIfInBounds i x :=
  rfl

/-- The state of `pack64`'s loop: words, the `u128` accumulator, its bit count, the next word. -/
abbrev PackState := Vector UInt64 6 × BitVec 128 × ℕ × ℕ

/-- The loop body of `pack64`. -/
def packStep (x : Limbs) : PackState → Fin LIMBS → PackState :=
  fun (out, acc, acc_bits, word) (j : Fin LIMBS) =>
    let acc := acc ||| x[j].toBitVec.setWidth 128 <<< acc_bits
    let acc_bits := acc_bits + LIMB_BITS
    if acc_bits ≥ 64 then
      (out.set! word (.ofBitVec (acc.setWidth 64)), acc >>> 64, acc_bits - 64, word + 1)
    else (out, acc, acc_bits, word)

theorem pack64_eq (x : Limbs) : pack64 x =
    let (out, acc, _, word) := (List.finRange LIMBS).foldl (packStep x) (.replicate 6 0, 0, 0, 0)
    if h : word < 6 then out.set word (.ofBitVec (acc.setWidth 64)) h else out := rfl

theorem limb_shift_lt (y : UInt64) {b : ℕ} (hb : b < 64) : y.toNat * 2 ^ b < 2 ^ 127 := by
  have hb2 : 2 ^ b ≤ 2 ^ 63 := Nat.pow_le_pow_right (by norm_num) (by omega)
  calc y.toNat * 2 ^ b < 2 ^ 64 * 2 ^ 63 :=
        Nat.mul_lt_mul_of_lt_of_le y.toNat_lt hb2 (by positivity)
    _ = 2 ^ 127 := by norm_num

/-- The accumulator holds below `2 ^ b` bits, so the new limb's bits are disjoint from it. -/
theorem or_limb (N b : ℕ) (y : UInt64) (hN : N < 2 ^ b) (hb : b < 64) :
    BitVec.ofNat 128 N ||| y.toBitVec.setWidth 128 <<< b = BitVec.ofNat 128 (N + y.toNat * 2 ^ b) := by
  have hyb := limb_shift_lt y hb
  have hb2 : 2 ^ b < 2 ^ 64 := Nat.pow_lt_pow_right (by norm_num) hb
  have hy := y.toNat_lt
  apply BitVec.eq_of_toNat_eq
  rw [BitVec.toNat_or, BitVec.toNat_shiftLeft, BitVec.toNat_setWidth, BitVec.toNat_ofNat,
    BitVec.toNat_ofNat, UInt64.toNat_toBitVec, Nat.shiftLeft_eq,
    Nat.mod_eq_of_lt (show N < 2 ^ 128 by omega), Nat.mod_eq_of_lt (show y.toNat < 2 ^ 128 by omega),
    Nat.mod_eq_of_lt (show y.toNat * 2 ^ b < 2 ^ 128 by omega),
    Nat.mod_eq_of_lt (show N + y.toNat * 2 ^ b < 2 ^ 128 by omega), or_mul_two_pow hN]

theorem foldl_pack_keep (x : Limbs) (out : Vector UInt64 6) (N b w : ℕ) (j : Fin LIMBS)
    (js : List (Fin LIMBS)) (hN : N < 2 ^ b) (hb : b + 52 < 64) :
    (j :: js).foldl (packStep x) (out, BitVec.ofNat 128 N, b, w) =
      js.foldl (packStep x) (out, BitVec.ofNat 128 (N + x[j].toNat * 2 ^ b), b + 52, w) := by
  rw [List.foldl_cons]
  congr 1
  simp only [packStep, LIMB_BITS, or_limb N b x[j] hN (by omega)]
  rw [if_neg (by omega)]

theorem foldl_pack_emit (x : Limbs) (out : Vector UInt64 6) (N b w : ℕ) (j : Fin LIMBS)
    (js : List (Fin LIMBS)) (hN : N < 2 ^ b) (hb : b < 64) (hb' : 64 ≤ b + 52) :
    (j :: js).foldl (packStep x) (out, BitVec.ofNat 128 N, b, w) =
      js.foldl (packStep x) (out.set! w (.ofNat ((N + x[j].toNat * 2 ^ b) % 2 ^ 64)),
        BitVec.ofNat 128 ((N + x[j].toNat * 2 ^ b) / 2 ^ 64), b + 52 - 64, w + 1) := by
  rw [List.foldl_cons]
  congr 1
  simp only [packStep, LIMB_BITS, or_limb N b x[j] hN hb]
  rw [if_pos (by omega)]
  have hyb := limb_shift_lt x[j] hb
  have hb2 : 2 ^ b < 2 ^ 64 := Nat.pow_lt_pow_right (by norm_num) hb
  have hlt : N + x[j].toNat * 2 ^ b < 2 ^ 128 := by omega
  have e1 : (⟨BitVec.setWidth 64 (BitVec.ofNat 128 (N + x[j].toNat * 2 ^ b))⟩ : UInt64) =
      UInt64.ofNat ((N + x[j].toNat * 2 ^ b) % 2 ^ 64) := by
    apply UInt64.toNat_inj.mp
    rw [UInt64.toNat_ofBitVec, BitVec.toNat_setWidth, BitVec.toNat_ofNat, UInt64.toNat_ofNat',
      Nat.mod_eq_of_lt hlt, Nat.mod_mod]
  have e2 : BitVec.ofNat 128 (N + x[j].toNat * 2 ^ b) >>> 64 =
      BitVec.ofNat 128 ((N + x[j].toNat * 2 ^ b) / 2 ^ 64) := by
    apply BitVec.eq_of_toNat_eq
    rw [BitVec.toNat_ushiftRight, BitVec.toNat_ofNat, BitVec.toNat_ofNat, Nat.mod_eq_of_lt hlt,
      Nat.shiftRight_eq_div_pow, Nat.mod_eq_of_lt (by omega)]
  rw [e1, e2]

set_option exponentiation.threshold 1000 in
/-- The bits from 384 up are dropped: the loop ends with `word = 6`, so the last 32 bits of the
accumulator are never written. -/
theorem pack64_spec {a : Limbs} (ha : ∀ j : Fin LIMBS, a[j].toNat < 2 ^ 52) :
    val64 (pack64 a) = val a % 2 ^ 384 := by
  have h0 := ha 0; have h1 := ha 1; have h2 := ha 2; have h3 := ha 3
  have h4 := ha 4; have h5 := ha 5; have h6 := ha 6; have h7 := ha 7
  rw [pack64_eq, Lane.finRange_LIMBS, show (0 : BitVec 128) = BitVec.ofNat 128 0 from rfl]
  rw [foldl_pack_keep, foldl_pack_emit, foldl_pack_emit, foldl_pack_emit, foldl_pack_emit,
    foldl_pack_keep, foldl_pack_emit, foldl_pack_emit, List.foldl_nil]
  · dsimp only
    rw [dif_neg (by norm_num), val64_eq, val_eq]
    simp only [set!_eq, Vector.getElem_setIfInBounds, Vector.getElem_replicate, Fin.getElem_fin,
      val_fin_LIMBS] at h0 h1 h2 h3 h4 h5 h6 h7 ⊢
    norm_num
    omega
  all_goals
    simp only [Fin.getElem_fin, val_fin_LIMBS] at h0 h1 h2 h3 h4 h5 h6 h7 ⊢
    omega

theorem val64_lt (x : Vector UInt64 6) : val64 x < 2 ^ 384 := by
  have := x[0].toNat_lt; have := x[1].toNat_lt; have := x[2].toNat_lt
  have := x[3].toNat_lt; have := x[4].toNat_lt; have := x[5].toNat_lt
  rw [val64_eq]
  omega

theorem eq_of_val64_eq {x y : Vector UInt64 6} (h : val64 x = val64 y) : x = y := by
  have := x[0].toNat_lt; have := x[1].toNat_lt; have := x[2].toNat_lt
  have := x[3].toNat_lt; have := x[4].toNat_lt; have := x[5].toNat_lt
  have := y[0].toNat_lt; have := y[1].toNat_lt; have := y[2].toNat_lt
  have := y[3].toNat_lt; have := y[4].toNat_lt; have := y[5].toNat_lt
  rw [val64_eq, val64_eq] at h
  ext j hj
  interval_cases j <;> omega

theorem pack64_unpack52 (x : Vector UInt64 6) : pack64 (unpack52 x) = x := by
  obtain ⟨hn, hv⟩ := unpack52_spec x
  apply eq_of_val64_eq
  rw [pack64_spec hn, hv, Nat.mod_eq_of_lt (val64_lt x)]

theorem unpack52_pack64 {a : Limbs} (ha : ∀ j : Fin LIMBS, a[j].toNat < 2 ^ 52)
    (hlt : val a < 2 ^ 384) : unpack52 (pack64 a) = a := by
  obtain ⟨hn, hv⟩ := unpack52_spec (pack64 a)
  apply eq_of_val_eq hn ha
  rw [hv, pack64_spec ha, Nat.mod_eq_of_lt hlt]

namespace Fp8

set_option exponentiation.threshold 1000 in
/-- Lane `l` of `to_blst_limbs`: the six words of blst's Montgomery form, R = 2^384, of the
field element the lane holds. -/
theorem val64_to_blst_limbs {x : Fp8} {l : Fin 8} (hx : Fp8Inv (x.lane l)) :
    val64 x.to_blst_limbs[l] = (decode (x.lane l) * 2 ^ 384).val := by
  have ht : Fp8Inv ((splat_limbs (.ofList TWO_POW_384_MOD_P)).lane l) := by
    rw [lane_splat_limbs]
    exact inv_ofList_TWO_POW_384_MOD_P
  obtain ⟨hc, hcv⟩ := lane_canonical (inv_mul hx ht)
  have hp := p_lt
  have hs : ((x.mul (splat_limbs (.ofList TWO_POW_384_MOD_P))).canonical.store)[l.val] =
      (x.mul (splat_limbs (.ofList TWO_POW_384_MOD_P))).canonical.lane l := getElem_store _ l
  simp only [to_blst_limbs, Vector.getElem_ofFn, Fin.getElem_fin]
  rw [hs, pack64_spec (fun j => hc.normal j), Nat.mod_eq_of_lt (by have := hc.bound; omega), hcv,
    ← ZMod.val_natCast, lane_mul, (LeanBlsSimd.mul_spec hx ht).2, lane_splat_limbs,
    val_ofList_TWO_POW_384_MOD_P, ZMod.natCast_mod, decode]
  push_cast
  ring_nf

end Fp8

end LeanBlsSimd
