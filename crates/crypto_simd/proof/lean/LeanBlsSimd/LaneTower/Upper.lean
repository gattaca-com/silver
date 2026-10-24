import LeanBlsSimd.LaneTower.Constants
import LeanBlsSimd.LaneTower.Permute

open EthLib.Cryptography Bls

namespace LeanBlsSimd.Fp8

set_option exponentiation.threshold 1000

/-- Inclusive value bounds preserve exact zero contributions in packed lane recombinations. -/
structure UpperRep (k m : ℕ) (x : Fp8) (l : Fin 8) (a : ZMod Fp.modulus) : Prop where
  nonneg : 0 ≤ SignedLimbs.val (x.lane l)
  bound : SignedLimbs.val (x.lane l) ≤ (k : ℤ) * Fp.modulus
  limbs : SignedLimbs.Bounded (x.lane l) m
  value : (SignedLimbs.val (x.lane l) : ZMod Fp.modulus) * (R : ZMod Fp.modulus)⁻¹ = a

structure CappedRep (k : ℕ) (x : Fp8) (l : Fin 8) (a : ZMod Fp.modulus) : Prop where
  normal : SignedLimbs.Normalized (x.lane l)
  bound : val (x.lane l) ≤ k * Fp.modulus
  value : decode (x.lane l) = a

variable {k m k' m' c : ℕ} {x y offset : Fp8} {l : Fin 8} {a b : ZMod Fp.modulus}

theorem BoundRep.capped (h : BoundRep k x l a) : CappedRep k x l a :=
  ⟨h.normal, h.bound.le, h.value⟩

theorem Holds.capped (h : x.Holds l a) : CappedRep 2 x l a := h.boundRep.capped

theorem capped_zero (l : Fin 8) : CappedRep 0 zero l 0 := by
  refine ⟨(inv_zero l).normal, ?_, decode_lane_zero l⟩
  rw [lane_zero, val_replicate_zero]
  simp

theorem CappedRep.upper (h : CappedRep k x l a) : UpperRep k 1 x l a := by
  refine ⟨?_, ?_, SignedLimbs.normalized_bounded h.normal, ?_⟩
  · rw [signed_val_eq h.normal]; positivity
  · rw [signed_val_eq h.normal]; exact_mod_cast h.bound
  · rw [signed_val_eq h.normal, Int.cast_natCast]; exact h.value

theorem CappedRep.boundRep (h : CappedRep k x l a) (hk : k < k') : BoundRep k' x l a := by
  refine ⟨h.normal, h.bound.trans_lt ?_, h.value⟩
  exact Nat.mul_lt_mul_of_pos_right hk (by decide)

theorem UpperRep.mono (h : UpperRep k m x l a) (hk : k ≤ k') (hm : m ≤ m') :
    UpperRep k' m' x l a := by
  refine ⟨h.nonneg, h.bound.trans ?_, ?_, h.value⟩
  · exact mul_le_mul_of_nonneg_right (by exact_mod_cast hk) (by positivity)
  · intro j
    exact (h.limbs j).trans_le (mul_le_mul_of_nonneg_right (by exact_mod_cast hm) (by positivity))

theorem UpperRep.add_raw (hx : UpperRep k m x l a) (hy : UpperRep k' m' y l b)
    (hm : m + m' ≤ 1024) : UpperRep (k + k') (m + m') (x.add_raw y) l (a + b) := by
  have hr : ((m : ℤ) + m') * 2 ^ 52 ≤ 2 ^ 63 := by
    have hm' : (m : ℤ) + m' ≤ 1024 := by exact_mod_cast hm
    linarith
  have hs := SignedLimbs.addRaw_spec hx.limbs hy.limbs hr
  refine ⟨?_, ?_, ?_, ?_⟩
  · rw [lane_add_raw, hs.1]; linarith [hx.nonneg, hy.nonneg]
  · rw [lane_add_raw, hs.1]; push_cast; nlinarith [hx.bound, hy.bound]
  · rw [lane_add_raw]; simpa only [Nat.cast_add] using hs.2
  · rw [lane_add_raw, hs.1, Int.cast_add, add_mul, hx.value, hy.value]

theorem UpperRep.sub_raw (hx : UpperRep k m x l a) (hy : UpperRep k' m' y l b)
    (ho : Offset c offset l) (hc : k' ≤ c) (hm : m + m' + 1 ≤ 1024) :
    UpperRep (k + c) (m + m' + 1) (x.sub_raw y offset) l (a - b) := by
  have hr : ((m : ℤ) + m' + 1) * 2 ^ 52 ≤ 2 ^ 63 := by
    have hm' : (m : ℤ) + m' + 1 ≤ 1024 := by exact_mod_cast hm
    linarith
  have hs := SignedLimbs.subRaw_spec hx.limbs hy.limbs ho.normal
    (by positivity) (by positivity) hr
  have hov : SignedLimbs.val (offset.lane l) = (c : ℤ) * Fp.modulus := by
    rw [signed_val_eq ho.normal, ho.value]; push_cast; rfl
  have hc' : (k' : ℤ) * Fp.modulus ≤ (c : ℤ) * Fp.modulus :=
    mul_le_mul_of_nonneg_right (by exact_mod_cast hc) (by positivity)
  refine ⟨?_, ?_, ?_, ?_⟩
  · rw [lane_sub_raw, hs.1, hov]; linarith [hx.nonneg, hy.bound]
  · rw [lane_sub_raw, hs.1, hov]; push_cast; nlinarith [hx.bound, hy.nonneg]
  · rw [lane_sub_raw]; simpa only [Nat.cast_add, Nat.cast_one] using hs.2
  · rw [lane_sub_raw, hs.1, hov]
    push_cast
    rw [ZMod.natCast_self, mul_zero, add_zero, sub_mul, hx.value, hy.value]

theorem UpperRep.normalise (h : UpperRep k m x l a)
    (hk : k * Fp.modulus < R) (hm : m ≤ 1024) : CappedRep k x.normalise l a := by
  have hl (j : Fin 8) : |SignedLimbs.limb (x.lane l)[j]| < (2 : ℤ) ^ 62 := by
    have hb := h.limbs j
    have hm' : (m : ℤ) ≤ 1024 := by exact_mod_cast hm
    change |SignedLimbs.limb ((x.lane l)[j.val])| < (m : ℤ) * 2 ^ 52 at hb
    norm_num at hb ⊢
    omega
  have hc : (k : ℤ) * Fp.modulus < 2 ^ 416 := by exact_mod_cast hk
  have hs := SignedLimbs.normalise_eight_spec hl h.nonneg (h.bound.trans_lt hc)
  have hn : SignedLimbs.Normalized (x.normalise.lane l) := by rw [lane_normalise]; exact hs.2
  have hv : (val (x.normalise.lane l) : ℤ) = SignedLimbs.val (x.lane l) := by
    rw [← signed_val_eq hn, lane_normalise]
    exact hs.1
  refine ⟨hn, ?_, ?_⟩
  · have hb := h.bound
    rw [← hv] at hb
    exact_mod_cast hb
  · rw [decode, ← Int.cast_natCast (val (x.normalise.lane l)), hv]
    exact h.value

theorem CappedRep.mul (hx : CappedRep k x l a) (hy : CappedRep k' y l b)
    (hk : k * k' * Fp.modulus < R) : (x.mul y).Holds l (a * b) := by
  have hab : val (x.lane l) * val (y.lane l) < R * Fp.modulus := by
    have hv := Nat.mul_le_mul hx.bound hy.bound
    have hc := Nat.mul_lt_mul_of_pos_right hk (by decide : 0 < Fp.modulus)
    nlinarith
  have hs := mul_spec_of_product_lt hx.normal hy.normal hab
  refine ⟨?_, ?_⟩
  · rw [lane_mul]; exact hs.1
  · rw [lane_mul, decode, hs.2, ← hx.value, ← hy.value, decode, decode]
    ring

theorem UpperRep.of_lane_eq {z : Fp8} {j : Fin 8} (h : UpperRep k m x l a)
    (he : z.lane j = x.lane l) : UpperRep k m z j a := by
  constructor <;> rw [he]
  exacts [h.nonneg, h.bound, h.limbs, h.value]

theorem CappedRep.of_lane_eq {z : Fp8} {j : Fin 8} (h : CappedRep k x l a)
    (he : z.lane j = x.lane l) : CappedRep k z j a := by
  constructor <;> rw [he]
  exacts [h.normal, h.bound, h.value]

end LeanBlsSimd.Fp8
