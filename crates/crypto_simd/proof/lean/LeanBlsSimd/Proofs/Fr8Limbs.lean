import LeanBlsSimd.Model.Fr8
import LeanBlsSimd.Proofs.Limbs
import EthLib.Cryptography.Proofs.Bls.FrZMod

/-! The five-limb IFMA product, reduction rows, and closing carries. -/

namespace LeanBlsSimd.FrModel

open EthLib.Cryptography.Bls

/-- The value of little-endian `LIMB_BITS`-bit limbs. -/
def val (a : Limbs) : ℕ := ∑ j : Fin LIMBS, a[j].toNat * 2 ^ (LIMB_BITS * j.val)

/-- The invariant of every lane of an `Fr8`. -/
structure Fr8Inv (a : Limbs) : Prop where
  normal : ∀ j : Fin LIMBS, a[j].toNat < 2 ^ LIMB_BITS
  bound : val a < 2 * Fr.modulus

theorem sum_fin_limbs (f : Fin LIMBS → ℕ) :
    ∑ j, f j = f 0 + f 1 + f 2 + f 3 + f 4 := by
  change ∑ j : Fin 5, f j = _
  simp [Fin.sum_univ_succ, Nat.add_assoc]
  rfl

theorem val_fin_LIMBS :
    ((0 : Fin LIMBS) : ℕ) = 0 ∧ ((1 : Fin LIMBS) : ℕ) = 1 ∧ ((2 : Fin LIMBS) : ℕ) = 2 ∧
      ((3 : Fin LIMBS) : ℕ) = 3 ∧ ((4 : Fin LIMBS) : ℕ) = 4 := by decide

namespace Lane

open LeanBlsSimd.Lane

/-! ## The accumulator's value -/

/-- The accumulator's value, counting only the entries from `lo` up: a reduction row leaves the
entry it clears behind, holding its carried-out bits. -/
def valFrom (t : Acc) (lo : ℕ) : ℕ :=
  ∑ k : Fin (2 * LIMBS + 1), if lo ≤ k.val then t[k].toNat * 2 ^ (52 * k.val) else 0

theorem valFrom_set (t : Acc) (lo k : ℕ) (hk : k < 2 * LIMBS + 1) (hlo : lo ≤ k) (v : UInt64)
    (d : ℕ) (hv : v.toNat = t[k].toNat + d) :
    valFrom (t.set k v hk) lo = valFrom t lo + d * 2 ^ (52 * k) := by
  unfold valFrom
  rw [← sum_ite_val_eq _ k hk (d * 2 ^ (52 * k)), ← Finset.sum_add_distrib]
  refine Finset.sum_congr rfl fun k' _ => ?_
  rw [Fin.getElem_fin, Vector.getElem_set]
  by_cases h : k = k'.val
  · subst h
    simp [hlo, hv, add_mul]
  · simp [h, Ne.symm h]

theorem valFrom_eq (t : Acc) (lo : ℕ) (hlo : lo < 2 * LIMBS + 1) :
    valFrom t lo = t[lo].toNat * 2 ^ (52 * lo) + valFrom t (lo + 1) := by
  unfold valFrom
  rw [← sum_ite_val_eq _ lo hlo (t[lo].toNat * 2 ^ (52 * lo)), ← Finset.sum_add_distrib]
  refine Finset.sum_congr rfl fun k _ => ?_
  by_cases h : k.val = lo
  · simp [h]
  · by_cases h' : lo ≤ k.val
    · simp [h, h', show lo + 1 ≤ k.val by omega]
    · simp [h, h', show ¬ lo + 1 ≤ k.val by omega]

theorem valFrom_top (t : Acc) : valFrom t (2 * LIMBS + 1) = 0 := by
  unfold valFrom
  exact Finset.sum_eq_zero fun k _ => if_neg (by omega)

set_option exponentiation.threshold 1000 in
theorem valFrom_LIMBS (t : Acc) :
    valFrom t LIMBS = R * ∑ k : Fin LIMBS, t[LIMBS + k.val].toNat * 2 ^ (52 * k.val) +
      t[2 * LIMBS].toNat * 2 ^ (52 * (2 * LIMBS)) := by
  rw [valFrom_eq t LIMBS (by decide), valFrom_eq t (LIMBS + 1) (by decide),
    valFrom_eq t (LIMBS + 1 + 1) (by decide), valFrom_eq t (LIMBS + 1 + 1 + 1) (by decide),
    valFrom_eq t (LIMBS + 1 + 1 + 1 + 1) (by decide),
    valFrom_eq t (LIMBS + 1 + 1 + 1 + 1 + 1) (by decide),
    show LIMBS + 1 + 1 + 1 + 1 + 1 + 1 = 2 * LIMBS + 1 from rfl, valFrom_top,
    sum_fin_limbs]
  simp only [val_fin_LIMBS, R, LIMBS, LIMB_BITS, Nat.reduceAdd, Nat.reduceMul]
  ring

/-! ## The rows -/

/-- The loop body of `muladd_row` and `reduce_row`; iteration `j` multiplies `x j` by `y j`. -/
def maddStep (x y : Fin LIMBS → UInt64) (i : Fin LIMBS) (t : Acc) (j : Fin LIMBS) : Acc :=
  let t := t.set (i.val + j.val) (madd52lo t[i.val + j.val] (x j) (y j))
  t.set (i.val + j.val + 1) (madd52hi t[i.val + j.val + 1] (x j) (y j))

theorem muladd_row_eq (t : Acc) (a : Limbs) (b : UInt64) (i : Fin LIMBS) :
    muladd_row t a b i = (List.finRange LIMBS).foldl (maddStep (a[·]) (fun _ => b) i) t := rfl

theorem maddStep_spec (x y : Fin LIMBS → UInt64) (i j : Fin LIMBS) (t : Acc) (lo B : ℕ)
    (hlo : lo ≤ i) (ht : ∀ k : Fin (2 * LIMBS + 1), t[k].toNat ≤ B) (hB : B + 2 ^ 52 ≤ 2 ^ 64) :
    (∀ k : Fin (2 * LIMBS + 1), (maddStep x y i t j)[k].toNat ≤ B + 2 ^ 52) ∧
      valFrom (maddStep x y i t j) lo =
        valFrom t lo + lo52 (x j) * lo52 (y j) * 2 ^ (52 * (i.val + j.val)) := by
  have h0 : i.val + j.val < 2 * LIMBS + 1 := by omega
  have h1 : i.val + j.val + 1 < 2 * LIMBS + 1 := by omega
  have hlo' := Nat.mod_lt (lo52 (x j) * lo52 (y j)) (show 2 ^ 52 > 0 by norm_num)
  have hhi : lo52 (x j) * lo52 (y j) / 2 ^ 52 < 2 ^ 52 := by
    rw [Nat.div_lt_iff_lt_mul (by norm_num)]
    exact Nat.mul_lt_mul'' (lo52_lt _) (lo52_lt _)
  have hk0 := ht ⟨_, h0⟩
  have hk1 := ht ⟨_, h1⟩
  simp only [Fin.getElem_fin] at hk0 hk1
  set t1 := t.set (i.val + j.val) (madd52lo t[i.val + j.val] (x j) (y j)) with ht1
  have e0 := toNat_madd52lo t[i.val + j.val] (x j) (y j) (by omega)
  have e1 : t1[i.val + j.val + 1] = t[i.val + j.val + 1] := Vector.getElem_set_ne _ _ (by omega)
  have e1' := toNat_madd52hi t1[i.val + j.val + 1] (x j) (y j) (by rw [e1]; omega)
  have e1t := toNat_madd52hi t[i.val + j.val + 1] (x j) (y j) (by omega)
  have v1 := valFrom_set t lo _ h0 (by omega) _ _ e0
  have v2 := valFrom_set t1 lo _ h1 (by omega) _ _ e1'
  refine ⟨fun k => ?_, ?_⟩
  · simp only [maddStep, Fin.getElem_fin, Vector.getElem_set]
    have hk := ht k
    simp only [Fin.getElem_fin] at hk
    split_ifs <;> omega
  · simp only [maddStep]
    rw [← ht1, v2, ht1, v1]
    rw [show 52 * (i.val + j.val + 1) = 52 * (i.val + j.val) + 52 by ring, pow_add, add_assoc,
      mod_mul_add_div_mul]

theorem foldl_maddStep (x y : Fin LIMBS → UInt64) (i : Fin LIMBS) (lo : ℕ) (hlo : lo ≤ i) :
    ∀ (js : List (Fin LIMBS)) (t : Acc) (B : ℕ), (∀ k : Fin (2 * LIMBS + 1), t[k].toNat ≤ B) →
      B + js.length * 2 ^ 52 ≤ 2 ^ 64 →
      (∀ k : Fin (2 * LIMBS + 1), (js.foldl (maddStep x y i) t)[k].toNat ≤
          B + js.length * 2 ^ 52) ∧
        valFrom (js.foldl (maddStep x y i) t) lo = valFrom t lo +
          (js.map fun j => lo52 (x j) * lo52 (y j) * 2 ^ (52 * (i.val + j.val))).sum
  | [], t, B, ht, _ => by simpa using ht
  | j :: js, t, B, ht, hB => by
    simp only [List.length_cons] at hB
    obtain ⟨hb, hv⟩ := maddStep_spec x y i j t lo B hlo ht (by nlinarith)
    obtain ⟨hb', hv'⟩ := foldl_maddStep x y i lo hlo js _ _ hb (by nlinarith)
    refine ⟨fun k => ?_, ?_⟩
    · have := hb' k
      simp only [List.foldl_cons, List.length_cons] at this ⊢
      nlinarith
    · simp only [List.foldl_cons, List.map_cons, List.sum_cons]
      rw [hv', hv]
      ring

theorem maddStep_getElem_of_lt (x y : Fin LIMBS → UInt64) (i j : Fin LIMBS) (t : Acc) (k : ℕ)
    (hk : k < i.val + j.val) : (maddStep x y i t j)[k]'(by omega) = t[k] := by
  simp only [maddStep]
  rw [Vector.getElem_set_ne _ _ (by omega), Vector.getElem_set_ne _ _ (by omega)]

theorem foldl_maddStep_getElem_of_lt (x y : Fin LIMBS → UInt64) (i : Fin LIMBS) (k : ℕ)
    (hk : k < 2 * LIMBS + 1) :
    ∀ (js : List (Fin LIMBS)) (t : Acc), (∀ j ∈ js, k < i.val + j.val) →
      (js.foldl (maddStep x y i) t)[k] = t[k]
  | [], _, _ => rfl
  | j :: js, t, h => by
    rw [List.foldl_cons,
      foldl_maddStep_getElem_of_lt x y i k hk js _ fun j hj => h j (by simp [hj]),
      maddStep_getElem_of_lt x y i j t k (h j (by simp))]

theorem finRange_LIMBS : List.finRange LIMBS = [0, 1, 2, 3, 4] := by decide

theorem muladd_row_spec (t : Acc) (a : Limbs) (b : UInt64) (i : Fin LIMBS) (lo B : ℕ)
    (hlo : lo ≤ i) (ha : ∀ j : Fin LIMBS, a[j].toNat < 2 ^ 52) (hb : b.toNat < 2 ^ 52)
    (ht : ∀ k : Fin (2 * LIMBS + 1), t[k].toNat ≤ B) (hB : B + 2 ^ 56 ≤ 2 ^ 64) :
    (∀ k : Fin (2 * LIMBS + 1), (muladd_row t a b i)[k].toNat ≤ B + 2 ^ 56) ∧
      valFrom (muladd_row t a b i) lo = valFrom t lo + val a * b.toNat * 2 ^ (52 * i.val) := by
  have hlen : (List.finRange LIMBS).length * 2 ^ 52 = 5 * 2 ^ 52 := by simp [LIMBS]
  obtain ⟨hb', hv⟩ := foldl_maddStep (a[·]) (fun _ => b) i lo hlo (List.finRange LIMBS) t B ht
    (by rw [hlen]; omega)
  rw [muladd_row_eq]
  refine ⟨fun k => by have := hb' k; rw [hlen] at this; omega, ?_⟩
  rw [hv, ← Fin.sum_univ_def]
  refine congrArg (valFrom t lo + ·) ?_
  unfold val
  rw [Finset.sum_mul, Finset.sum_mul]
  refine Finset.sum_congr rfl fun j _ => ?_
  rw [lo52_of_lt (ha j), lo52_of_lt hb, LIMB_BITS, mul_add, pow_add]
  ring

/-- `hinv` is what makes the row clear entry `i`: p · pinv ≡ −1 modulo 2^52. -/
theorem reduce_row_spec (t : Acc) (p : Limbs) (pinv : UInt64) (i : Fin LIMBS) (B : ℕ)
    (hp : ∀ j : Fin LIMBS, p[j].toNat < 2 ^ 52) (hpinv : pinv.toNat < 2 ^ 52)
    (hinv : (pinv.toNat * p[0].toNat + 1) % 2 ^ 52 = 0)
    (ht : ∀ k : Fin (2 * LIMBS + 1), t[k].toNat ≤ B) (hB : B + 2 ^ 56 ≤ 2 ^ 64) :
    ∃ q < 2 ^ 52, (∀ k : Fin (2 * LIMBS + 1), (reduce_row t p pinv i)[k].toNat ≤ B + 2 ^ 56) ∧
      valFrom (reduce_row t p pinv i) (i.val + 1) = valFrom t i + q * val p * 2 ^ (52 * i.val) := by
  unfold reduce_row
  extract_lets q t'
  have ht' : t' = (List.finRange LIMBS).foldl (maddStep (p[·]) (fun _ => q) i) t := rfl
  have hlen : (List.finRange LIMBS).length * 2 ^ 52 = 5 * 2 ^ 52 := by simp [LIMBS]
  have hq : q.toNat = lo52 t[i.val] * pinv.toNat % 2 ^ 52 := by
    rw [show q = madd52lo zero t[i.val] pinv from rfl, toNat_madd52lo _ _ _ (by simp [zero]),
      lo52_of_lt hpinv]
    simp [zero]
  have hqlt : q.toNat < 2 ^ 52 := hq ▸ Nat.mod_lt _ (by norm_num)
  obtain ⟨hb', hv⟩ := foldl_maddStep (p[·]) (fun _ => q) i i le_rfl (List.finRange LIMBS) t B ht
    (by rw [hlen]; omega)
  rw [← ht'] at hb' hv
  rw [hlen] at hb'
  have hsum : (List.map (fun j => lo52 p[j] * lo52 q * 2 ^ (52 * (i.val + j.val)))
      (List.finRange LIMBS)).sum = q.toNat * val p * 2 ^ (52 * i.val) := by
    rw [← Fin.sum_univ_def]
    unfold val
    rw [Finset.mul_sum, Finset.sum_mul]
    refine Finset.sum_congr rfl fun j _ => ?_
    rw [lo52_of_lt hqlt, lo52_of_lt (hp j), LIMB_BITS, mul_add, pow_add]
    ring
  rw [hsum] at hv
  have hi : i.val < 2 * LIMBS + 1 := by omega
  have hi1 : i.val + 1 < 2 * LIMBS + 1 := by omega
  have hti : t'[i.val].toNat = t[i.val].toNat + p[0].toNat * q.toNat % 2 ^ 52 := by
    have hfirst : ∀ j ∈ ([1, 2, 3, 4] : List (Fin LIMBS)), 1 ≤ j.val := by decide
    rw [ht', finRange_LIMBS, List.foldl_cons,
      foldl_maddStep_getElem_of_lt _ _ i i.val hi _ _ fun j hj => by have := hfirst j hj; omega]
    have hti0 := ht ⟨i.val, hi⟩
    simp only [Fin.getElem_fin] at hti0
    simp only [maddStep, val_fin_LIMBS, add_zero]
    rw [Vector.getElem_set_ne _ _ (by omega), Vector.getElem_set_self,
      toNat_madd52lo _ _ _ (by omega), lo52_of_lt (hp 0), lo52_of_lt hqlt]
    rfl
  have hmod : t'[i.val].toNat % 2 ^ 52 = 0 := by
    rw [hti, hq]
    apply Nat.mod_eq_zero_of_dvd
    rw [← ZMod.natCast_eq_zero_iff]
    have h1 : ((pinv.toNat * p[0].toNat + 1 : ℕ) : ZMod (2 ^ 52)) = 0 :=
      (ZMod.natCast_eq_zero_iff _ _).mpr (Nat.dvd_of_mod_eq_zero hinv)
    unfold lo52
    push_cast [ZMod.natCast_mod] at h1 ⊢
    linear_combination (t[i.val].toNat : ZMod (2 ^ 52)) * h1
  have hti1 := hb' ⟨i.val + 1, hi1⟩
  simp only [Fin.getElem_fin] at hti1
  -- Explicit bounds: `get_elem_tactic` times out searching this large context for them.
  have hcarry : (t'[i.val]'hi).toNat / 2 ^ 52 < 2 ^ 12 := by
    have := (t'[i.val]'hi).toNat_lt_size
    simp only [UInt64.size] at this
    omega
  have hv1 : (t'[i.val + 1]'hi1 + srli 52 (t'[i.val]'hi)).toNat =
      (t'[i.val + 1]'hi1).toNat + (t'[i.val]'hi).toNat / 2 ^ 52 := by
    rw [UInt64.toNat_add, toNat_srli52, Nat.mod_eq_of_lt (by omega)]
  refine ⟨q.toNat, hqlt, fun k => ?_, ?_⟩
  · rw [Fin.getElem_fin, Vector.getElem_set]
    split_ifs with h
    · rw [hv1]
      omega
    · have := hb' k
      simp only [Fin.getElem_fin] at this
      omega
  · rw [valFrom_set t' _ _ hi1 le_rfl _ _ hv1, ← hv, valFrom_eq t' i.val hi]
    have hd := Nat.mod_add_div (t'[i.val]'hi).toNat (2 ^ 52)
    rw [hmod, zero_add] at hd
    set d := (t'[i.val]'hi).toNat / 2 ^ 52
    rw [← hd, show 52 * (i.val + 1) = 52 * i.val + 52 by ring, pow_add]
    ring

/-! ## The constants `Fr8::mul` splats -/

theorem splat_P_lt : ∀ j : Fin LIMBS, (splat_limbs (.ofList P))[j].toNat < 2 ^ 52 := by decide

theorem val_splat_P : val (splat_limbs (.ofList P)) = Fr.modulus := by decide +kernel

theorem splat_P_INV52_lt : (splat (.ofNat P_INV52)).toNat < 2 ^ 52 := by decide

theorem splat_P_INV52_spec :
    ((splat (.ofNat P_INV52)).toNat * (splat_limbs (.ofList P))[0].toNat + 1) % 2 ^ 52 = 0 := by
  decide

theorem splat_MASK52 : (splat (.ofNat MASK52)).toNat = 2 ^ 52 - 1 := by decide

/-! ## The ten rows -/

set_option exponentiation.threshold 1000 in
/-- Needs only normalised limbs: R · `val` of the top half is a · b plus a multiple of p. -/
theorem mulAcc_spec {a b : Limbs} (ha : ∀ j : Fin LIMBS, a[j].toNat < 2 ^ LIMB_BITS)
    (hb : ∀ j : Fin LIMBS, b[j].toNat < 2 ^ LIMB_BITS) :
    (∀ k : Fin (2 * LIMBS + 1), (mulAcc a b)[k].toNat ≤ 2 ^ 60) ∧
      ∃ Q < R, valFrom (mulAcc a b) LIMBS = val a * val b + Q * Fr.modulus := by
  have han : ∀ j : Fin LIMBS, a[j].toNat < 2 ^ 52 := ha
  have hbn : ∀ j : Fin LIMBS, b[j].toNat < 2 ^ 52 := hb
  unfold mulAcc
  extract_lets p pinv t0 t1 t2 t3 t4 t5 t6 t7 t8 t9
  have hp : ∀ j : Fin LIMBS, p[j].toNat < 2 ^ 52 := splat_P_lt
  have hpinv : pinv.toNat < 2 ^ 52 := splat_P_INV52_lt
  have hinv : (pinv.toNat * p[0].toNat + 1) % 2 ^ 52 = 0 := splat_P_INV52_spec
  have b0 : ∀ k : Fin (2 * LIMBS + 1), t0[k].toNat ≤ 0 := by simp [t0, zero]
  have v0 : valFrom t0 0 = 0 := by simp [valFrom, t0, zero]
  obtain ⟨b1, v1⟩ := muladd_row_spec t0 a b[0] 0 0 _ (by simp) han (hbn 0) b0 (by norm_num)
  obtain ⟨b2, v2⟩ := muladd_row_spec t1 a b[1] 1 0 _ (by simp) han (hbn 1) b1 (by norm_num)
  obtain ⟨b3, v3⟩ := muladd_row_spec t2 a b[2] 2 0 _ (by simp) han (hbn 2) b2 (by norm_num)
  obtain ⟨b4, v4⟩ := muladd_row_spec t3 a b[3] 3 0 _ (by simp) han (hbn 3) b3 (by norm_num)
  obtain ⟨b5, v5⟩ := muladd_row_spec t4 a b[4] 4 0 _ (by simp) han (hbn 4) b4 (by norm_num)
  obtain ⟨q0, hq0, b6, v6⟩ := reduce_row_spec t5 p pinv 0 _ hp hpinv hinv b5 (by norm_num)
  obtain ⟨q1, hq1, b7, v7⟩ := reduce_row_spec t6 p pinv 1 _ hp hpinv hinv b6 (by norm_num)
  obtain ⟨q2, hq2, b8, v8⟩ := reduce_row_spec t7 p pinv 2 _ hp hpinv hinv b7 (by norm_num)
  obtain ⟨q3, hq3, b9, v9⟩ := reduce_row_spec t8 p pinv 3 _ hp hpinv hinv b8 (by norm_num)
  obtain ⟨q4, hq4, b10, v10⟩ := reduce_row_spec t9 p pinv 4 _ hp hpinv hinv b9 (by norm_num)
  refine ⟨fun k => (b10 k).trans (by norm_num), q0 + q1 * 2 ^ 52 + q2 * 2 ^ 104 +
    q3 * 2 ^ 156 + q4 * 2 ^ 208, ?_, ?_⟩
  · simp only [R, LIMBS, LIMB_BITS, Nat.reduceMul]
    omega
  have w1 : valFrom t1 _ = _ := v1
  have w2 : valFrom t2 _ = _ := v2
  have w3 : valFrom t3 _ = _ := v3
  have w4 : valFrom t4 _ = _ := v4
  have w5 : valFrom t5 _ = _ := v5
  have w6 : valFrom t6 _ = _ := v6
  have w7 : valFrom t7 _ = _ := v7
  have w8 : valFrom t8 _ = _ := v8
  have w9 : valFrom t9 _ = _ := v9
  simp only [val_fin_LIMBS, Nat.reduceMul, mul_one, pow_zero] at w1 w2 w3 w4 w5
  simp only [val_fin_LIMBS, Nat.reduceAdd, Nat.reduceMul, mul_one, pow_zero] at w6 w7 w8 w9 v10
  have hvp : val p = Fr.modulus := val_splat_P
  have hvb : val b = b[0].toNat + b[1].toNat * 2 ^ 52 + b[2].toNat * 2 ^ 104 +
      b[3].toNat * 2 ^ 156 + b[4].toNat * 2 ^ 208 := by
    unfold val
    rw [sum_fin_limbs]
    simp only [Fin.getElem_fin, val_fin_LIMBS, LIMB_BITS, Nat.reduceMul, pow_zero, mul_one]
  show valFrom (reduce_row t9 p pinv 4) 5 = _
  rw [v10, w9, w8, w7, w6, w5, w4, w3, w2, w1, v0, hvp, hvb]
  ring

/-! ## `Fr8::mul` -/

theorem normalize_spec (t : Acc) (mask : UInt64) (hmask : mask.toNat = 2 ^ 52 - 1)
    (ht : ∀ k : Fin (2 * LIMBS + 1), t[k].toNat ≤ 2 ^ 60) :
    let r := (List.finRange (LIMBS - 1)).foldl (carryStep t mask)
      ((Vector.replicate LIMBS zero).set 0 t[LIMBS])
    (∀ j : Fin LIMBS, j.val < LIMBS - 1 → r[j].toNat < 2 ^ 52) ∧
      val r = ∑ k : Fin LIMBS, t[LIMBS + k.val].toNat * 2 ^ (52 * k.val) := by
  unfold carryStep
  intro r
  have hfin : List.finRange (LIMBS - 1) = [⟨0, by decide⟩, ⟨1, by decide⟩, ⟨2, by decide⟩,
      ⟨3, by decide⟩] := by decide
  have hb : ∀ k (hk : k < 2 * LIMBS + 1), t[k].toNat ≤ 2 ^ 60 := fun k hk => ht ⟨k, hk⟩
  have h0 := hb LIMBS (by decide)
  have h1 := hb (LIMBS + 1) (by decide)
  have h2 := hb (LIMBS + 2) (by decide)
  have h3 := hb (LIMBS + 3) (by decide)
  have h4 := hb (LIMBS + 4) (by decide)
  set u0 := t[LIMBS] with hu0
  set u1 := t[LIMBS + 1] + srli 52 u0
  set u2 := t[LIMBS + 2] + srli 52 u1
  set u3 := t[LIMBS + 3] + srli 52 u2
  set u4 := t[LIMBS + 4] + srli 52 u3
  have e0 : r[0] = u0 &&& mask := by simp [r, hfin, u0]
  have e1 : r[1] = u1 &&& mask := by simp [r, hfin, Nat.add_assoc, u0, u1]
  have e2 : r[2] = u2 &&& mask := by simp [r, hfin, Nat.add_assoc, u0, u1, u2]
  have e3 : r[3] = u3 &&& mask := by simp [r, hfin, Nat.add_assoc, u0, u1, u2, u3]
  have e4 : r[4] = u4 := by simp [r, hfin, Nat.add_assoc, u0, u1, u2, u3, u4]
  have n1 : u1.toNat = t[LIMBS + 1].toNat + u0.toNat / 2 ^ 52 := toNat_add_srli52 _ u0 h1
  have n2 : u2.toNat = t[LIMBS + 2].toNat + u1.toNat / 2 ^ 52 := toNat_add_srli52 _ u1 h2
  have n3 : u3.toNat = t[LIMBS + 3].toNat + u2.toNat / 2 ^ 52 := toNat_add_srli52 _ u2 h3
  have n4 : u4.toNat = t[LIMBS + 4].toNat + u3.toNat / 2 ^ 52 := toNat_add_srli52 _ u3 h4
  have m := fun x => toNat_and_mask x mask hmask
  refine ⟨fun ⟨j, hj⟩ hj7 => ?_, ?_⟩
  · simp only [LIMBS] at hj7
    interval_cases j
    all_goals
      simp only [Fin.getElem_fin, e0, e1, e2, e3, m]
      exact Nat.mod_lt _ (by norm_num)
  · unfold val
    rw [sum_fin_limbs, sum_fin_limbs]
    simp only [Fin.getElem_fin, val_fin_LIMBS, add_zero, e0, e1, e2, e3, e4, m,
      LIMB_BITS, ← hu0]
    norm_num
    omega

end Lane

open Lane in
set_option exponentiation.threshold 1000 in
theorem mul_spec {a b : Limbs} (ha : Fr8Inv a) (hb : Fr8Inv b) :
    Fr8Inv (Lane.mul a b) ∧
      (val (Lane.mul a b) : ZMod Fr.modulus) = val a * val b * (R : ZMod Fr.modulus)⁻¹ := by
  obtain ⟨hacc, Q, hQ, hv⟩ := mulAcc_spec ha.normal hb.normal
  unfold Lane.mul
  extract_lets t10 mask r0 r1
  have ht10 : t10 = mulAcc a b := rfl
  rw [← ht10] at hacc hv
  obtain ⟨hn, hval⟩ := normalize_spec t10 mask splat_MASK52 hacc
  generalize hres : List.foldl _ r1 (List.finRange (LIMBS - 1)) = res
  have hn' : ∀ j : Fin LIMBS, j.val < LIMBS - 1 → res[j].toNat < 2 ^ 52 := hres ▸ hn
  have hval' : val res = _ := hres ▸ hval
  have hres4 : res[4].toNat * 2 ^ 208 ≤ val res := by
    unfold val
    rw [sum_fin_limbs]
    simp only [Fin.getElem_fin, val_fin_LIMBS, LIMB_BITS, Nat.reduceMul]
    omega
  rw [valFrom_LIMBS, ← hval'] at hv
  generalize t10[2 * LIMBS].toNat = y at hv
  have hAB : val a * val b < 2 * Fr.modulus * (2 * Fr.modulus) := Nat.mul_lt_mul'' ha.bound hb.bound
  have hvN := hv
  simp only [Fr.modulus, R, LIMBS, LIMB_BITS, Nat.reduceMul] at hvN hAB hQ
  have hlt : val res < 2 * Fr.modulus := by simp only [Fr.modulus]; omega
  have hy : y = 0 := by omega
  refine ⟨⟨fun j => ?_, hlt⟩, ?_⟩
  · by_cases hj : j.val < LIMBS - 1
    · exact hn' j hj
    · obtain ⟨j, hj'⟩ := j
      obtain rfl : j = 4 := by simp only [LIMBS] at hj hj'; omega
      simp only [Fin.getElem_fin, LIMB_BITS]
      simp only [Fr.modulus] at hlt
      omega
  · have hR : (R : ZMod Fr.modulus) ≠ 0 := by
      rw [Ne, ZMod.natCast_eq_zero_iff]
      decide
    rw [eq_mul_inv_iff_mul_eq₀ hR]
    have := congrArg (Nat.cast : ℕ → ZMod Fr.modulus) hv
    rw [hy] at this
    push_cast [ZMod.natCast_self] at this
    simpa [mul_comm] using this

namespace Fr8

/-- The lifting lemma: lane `l` of a lane-wise operation is that operation on lane `l`. -/
theorem lane_ofLanes (lanes : Vector Limbs 8) (l : Fin 8) : (ofLanes lanes).lane l = lanes[l] := by
  ext j hj
  simp [lane, ofLanes]

theorem mul_spec {x y : Fr8} (hx : ∀ l, Fr8Inv (x.lane l)) (hy : ∀ l, Fr8Inv (y.lane l))
    (l : Fin 8) :
    Fr8Inv ((x.mul y).lane l) ∧ (val ((x.mul y).lane l) : ZMod Fr.modulus) =
      val (x.lane l) * val (y.lane l) * (R : ZMod Fr.modulus)⁻¹ := by
  rw [Fr8.mul, lane_ofLanes]
  simp only [Fin.getElem_fin, Vector.getElem_ofFn]
  exact LeanBlsSimd.FrModel.mul_spec (hx l) (hy l)

end Fr8

end LeanBlsSimd.FrModel
