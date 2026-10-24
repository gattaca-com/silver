import LeanBlsSimd.Proofs.Fp8Holds
import LeanBlsSimd.Proofs.Fp8Multiple
import LeanBlsSimd.Proofs.SignedLimbs

namespace LeanBlsSimd.Fp8
open EthLib.Cryptography.Bls

structure Lazy (k m : ℕ) (x : Fp8) (l : Fin 8) : Prop where
  nonneg : 0 ≤ SignedLimbs.val (x.lane l)
  bound : SignedLimbs.val (x.lane l) < (k : ℤ) * Fp.modulus
  limbs : SignedLimbs.Bounded (x.lane l) m

structure LazyRep (k m : ℕ) (x : Fp8) (l : Fin 8) (a : ZMod Fp.modulus) : Prop where
  range : Lazy k m x l
  value : (SignedLimbs.val (x.lane l) : ZMod Fp.modulus) * (R : ZMod Fp.modulus)⁻¹ = a

structure BoundRep (k : ℕ) (x : Fp8) (l : Fin 8) (a : ZMod Fp.modulus) : Prop where
  normal : SignedLimbs.Normalized (x.lane l)
  bound : val (x.lane l) < k * Fp.modulus
  value : decode (x.lane l) = a

structure Offset (c : ℕ) (x : Fp8) (l : Fin 8) : Prop where
  normal : SignedLimbs.Normalized (x.lane l)
  value : val (x.lane l) = c * Fp.modulus

theorem signed_val_eq {a : Limbs} (ha : SignedLimbs.Normalized a) :
    SignedLimbs.val a = (val a : ℤ) := SignedLimbs.val_eq_nat ha

theorem lane_add_raw (x y : Fp8) (l : Fin 8) :
    (x.add_raw y).lane l = SignedLimbs.addRaw (x.lane l) (y.lane l) := by
  ext j hj
  simp [add_raw, lane, SignedLimbs.addRaw, _mm512_add_epi64]

theorem lane_sub_raw (x y offset : Fp8) (l : Fin 8) :
    (x.sub_raw y offset).lane l = SignedLimbs.subRaw (x.lane l) (y.lane l) (offset.lane l) := by
  ext j hj
  simp [sub_raw, lane, SignedLimbs.subRaw, _mm512_add_epi64, _mm512_sub_epi64]

theorem lane_normalise (x : Fp8) (l : Fin 8) :
    x.normalise.lane l = SignedLimbs.normalise (x.lane l) := by
  simp [normalise, lane_ofLanes]

theorem offset_two (l : Fin 8) : Offset 2 (multiple_of_p 2) l := by
  obtain ⟨hn, hv⟩ := multiple_of_p_spec 2 (by decide) l
  exact ⟨hn, hv⟩

theorem offset_four (l : Fin 8) : Offset 4 (multiple_of_p 4) l := by
  obtain ⟨hn, hv⟩ := multiple_of_p_spec 4 (by decide) l
  exact ⟨hn, hv⟩

theorem offset_eight (l : Fin 8) : Offset 8 (multiple_of_p 8) l := by
  obtain ⟨hn, hv⟩ := multiple_of_p_spec 8 (by decide) l
  exact ⟨hn, hv⟩

variable {k m k' m' c : ℕ} {x y offset : Fp8} {l : Fin 8} {a b : ZMod Fp.modulus}

theorem Holds.boundRep (h : x.Holds l a) : BoundRep 2 x l a :=
  ⟨h.inv.normal, h.inv.bound, h.eq⟩

theorem BoundRep.mono (h : BoundRep k x l a) (hk : k ≤ k') : BoundRep k' x l a :=
  ⟨h.normal, lt_of_lt_of_le h.bound (Nat.mul_le_mul_right _ hk), h.value⟩

theorem BoundRep.lazyRep (h : BoundRep k x l a) : LazyRep k 1 x l a := by
  refine ⟨⟨?_, ?_, SignedLimbs.normalized_bounded h.normal⟩, ?_⟩
  · rw [signed_val_eq h.normal]; positivity
  · rw [signed_val_eq h.normal]; exact_mod_cast h.bound
  · rw [signed_val_eq h.normal, Int.cast_natCast]; exact h.value

theorem Holds.lazyRep (h : x.Holds l a) : LazyRep 2 1 x l a := h.boundRep.lazyRep

theorem BoundRep.holds (h : BoundRep k x l a) (hk : k ≤ 2) : x.Holds l a := by
  refine ⟨⟨h.normal, lt_of_lt_of_le h.bound ?_⟩, h.value⟩
  exact Nat.mul_le_mul_right _ hk

theorem LazyRep.add_raw (hx : LazyRep k m x l a) (hy : LazyRep k' m' y l b)
    (hm : m + m' ≤ 1024) : LazyRep (k + k') (m + m') (x.add_raw y) l (a + b) := by
  have hr : ((m : ℤ) + m') * 2 ^ 52 ≤ 2 ^ 63 := by
    have hm' : (m : ℤ) + m' ≤ 1024 := by exact_mod_cast hm
    linarith
  have hs := SignedLimbs.addRaw_spec hx.range.limbs hy.range.limbs hr
  constructor
  · constructor
    · rw [lane_add_raw, hs.1]; linarith [hx.range.nonneg, hy.range.nonneg]
    · rw [lane_add_raw, hs.1]; push_cast; nlinarith [hx.range.bound, hy.range.bound]
    · rw [lane_add_raw]; simpa only [Nat.cast_add] using hs.2
  · rw [lane_add_raw, hs.1, Int.cast_add, add_mul, hx.value, hy.value]

theorem LazyRep.sub_raw (hx : LazyRep k m x l a) (hy : LazyRep k' m' y l b)
    (ho : Offset c offset l) (hc : k' ≤ c) (hm : m + m' + 1 ≤ 1024) :
    LazyRep (k + c) (m + m' + 1) (x.sub_raw y offset) l (a - b) := by
  have hr : ((m : ℤ) + m' + 1) * 2 ^ 52 ≤ 2 ^ 63 := by
    have hm' : (m : ℤ) + m' + 1 ≤ 1024 := by exact_mod_cast hm
    linarith
  have hs := SignedLimbs.subRaw_spec hx.range.limbs hy.range.limbs ho.normal
    (by positivity) (by positivity) hr
  have hov : SignedLimbs.val (offset.lane l) = (c : ℤ) * Fp.modulus := by
    rw [signed_val_eq ho.normal, ho.value]; push_cast; rfl
  have hc' : (k' : ℤ) * Fp.modulus ≤ (c : ℤ) * Fp.modulus :=
    mul_le_mul_of_nonneg_right (by exact_mod_cast hc) (by positivity)
  constructor
  · constructor
    · rw [lane_sub_raw, hs.1, hov]; linarith [hx.range.nonneg, hy.range.bound]
    · rw [lane_sub_raw, hs.1, hov]; push_cast; nlinarith [hx.range.bound, hy.range.nonneg]
    · rw [lane_sub_raw]; simpa only [Nat.cast_add, Nat.cast_one] using hs.2
  · rw [lane_sub_raw, hs.1, hov]
    push_cast
    rw [ZMod.natCast_self, mul_zero, add_zero, sub_mul, hx.value, hy.value]

set_option exponentiation.threshold 1000 in
theorem LazyRep.normalise_of_capacity (h : LazyRep k m x l a)
    (hk : k * Fp.modulus ≤ R) (hm : m ≤ 1024) :
    BoundRep k x.normalise l a := by
  have hl (j : Fin 8) : |SignedLimbs.limb (x.lane l)[j]| < (2 : ℤ) ^ 62 := by
    have hb := h.range.limbs j
    have hm' : (m : ℤ) ≤ 1024 := by exact_mod_cast hm
    change |SignedLimbs.limb ((x.lane l)[j.val])| < (m : ℤ) * 2 ^ 52 at hb
    norm_num at hb ⊢
    omega
  have hhi : SignedLimbs.val (x.lane l) < (2 : ℤ) ^ 416 := by
    have hk' : (k : ℤ) * Fp.modulus ≤ 2 ^ 416 := by exact_mod_cast hk
    exact h.range.bound.trans_le hk'
  have hs := SignedLimbs.normalise_eight_spec hl h.range.nonneg hhi
  have hn : SignedLimbs.Normalized (x.normalise.lane l) := by rw [lane_normalise]; exact hs.2
  have hv : (val (x.normalise.lane l) : ℤ) = SignedLimbs.val (x.lane l) := by
    rw [← signed_val_eq hn, lane_normalise]
    exact hs.1
  refine ⟨hn, ?_, ?_⟩
  · have hb := h.range.bound
    rw [← hv] at hb
    exact_mod_cast hb
  · rw [decode, ← Int.cast_natCast (val (x.normalise.lane l)), hv]
    exact h.value

theorem LazyRep.normalise (h : LazyRep k m x l a) (hk : k ≤ 1024) (hm : m ≤ 1024) :
    BoundRep k x.normalise l a := by
  apply h.normalise_of_capacity _ hm
  exact (Nat.mul_le_mul_right _ hk).trans (by decide +kernel)

theorem BoundRep.mul_of_capacity (hx : BoundRep k x l a) (hy : BoundRep k' y l b)
    (hk : k * k' * Fp.modulus ≤ R) : (x.mul y).Holds l (a * b) := by
  have hab : val (x.lane l) * val (y.lane l) < R * Fp.modulus := by
    have hbound := Nat.mul_lt_mul_of_lt_of_lt hx.bound hy.bound
    have hcap := Nat.mul_le_mul_right Fp.modulus hk
    nlinarith
  have hs := mul_spec_of_product_lt hx.normal hy.normal hab
  refine ⟨?_, ?_⟩
  · rw [lane_mul]; exact hs.1
  · rw [lane_mul, decode, hs.2, ← hx.value, ← hy.value, decode, decode]
    ring

theorem BoundRep.mul (hx : BoundRep k x l a) (hy : BoundRep k' y l b)
    (hk : k * k' ≤ 1024) : (x.mul y).Holds l (a * b) := by
  apply hx.mul_of_capacity hy
  exact (Nat.mul_le_mul_right Fp.modulus hk).trans (by decide +kernel)

theorem BoundRep.square (hx : BoundRep k x l a) (hk : k * k ≤ 1024) :
    x.square.Holds l (a ^ 2) := by
  simpa only [square, sq] using hx.mul hx hk

theorem BoundRep.cond_sub (hx : BoundRep k x l a) (ho : Offset c offset l)
    (hk : k ≤ 2 * c) : BoundRep c (x.cond_sub offset) l a := by
  obtain ⟨hn, hv⟩ := lane_cond_sub hx.normal ho.normal
  rw [ho.value] at hv
  refine ⟨hn, ?_, ?_⟩
  · rw [hv]
    have hbound := hx.bound
    have hkc := Nat.mul_le_mul_right Fp.modulus hk
    rw [Nat.mul_assoc] at hkc
    split_ifs <;> omega
  · rw [decode, hv]
    split_ifs with hlt
    · exact hx.value
    · rw [Nat.cast_sub (by omega), Nat.cast_mul, ZMod.natCast_self, mul_zero, sub_zero]
      exact hx.value

theorem LazyRep.reduced_from_4p (h : LazyRep k m x l a)
    (hk : k ≤ 4) (hm : m ≤ 1024) :
    (x.normalise.cond_sub (multiple_of_p 2)).Holds l a := by
  exact ((h.normalise (by omega) hm).cond_sub (offset_two l) (by omega)).holds (by decide)

theorem LazyRep.reduced_from_8p (h : LazyRep k m x l a)
    (hk : k ≤ 8) (hm : m ≤ 1024) :
    ((x.normalise.cond_sub (multiple_of_p 4)).cond_sub (multiple_of_p 2)).Holds l a := by
  exact (((h.normalise (by omega) hm).cond_sub (offset_four l) (by omega)).cond_sub
    (offset_two l) (by decide)).holds (by decide)

end LeanBlsSimd.Fp8
