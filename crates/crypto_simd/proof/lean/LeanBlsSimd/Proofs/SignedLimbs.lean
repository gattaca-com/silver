import LeanBlsSimd.Model.SignedLimbs
import LeanBlsSimd.Proofs.Limbs

namespace LeanBlsSimd.SignedLimbs

theorem limb_eq (x : UInt64) :
    limb x = if x.toNat < 2 ^ 63 then (x.toNat : ℤ) else (x.toNat : ℤ) - 2 ^ 64 := by
  change x.toBitVec.toInt = _
  rw [BitVec.toInt_eq_toNat_cond]
  simp only [UInt64.toNat_toBitVec]
  split_ifs <;> omega

theorem limb_eq_nat {x : UInt64} (hx : x.toNat < 2 ^ 63) :
    limb x = (x.toNat : ℤ) := by rw [limb_eq, if_pos hx]

theorem limb_add {a b : UInt64}
    (hl : -(2 : ℤ) ^ 63 ≤ limb a + limb b) (hh : limb a + limb b < 2 ^ 63) :
    limb (a + b) = limb a + limb b := by
  simp only [limb, UInt64.toInt64_add, Int64.toInt_add]
  apply Int.bmod_eq_of_le <;> norm_num at * <;> assumption

theorem limb_sub {a b : UInt64}
    (hl : -(2 : ℤ) ^ 63 ≤ limb a - limb b) (hh : limb a - limb b < 2 ^ 63) :
    limb (a - b) = limb a - limb b := by
  simp only [limb, UInt64.toInt64_sub, Int64.toInt_sub]
  apply Int.bmod_eq_of_le <;> norm_num at * <;> assumption

theorem limb_srai52 (x : UInt64) : limb (srai 52 x) = limb x / 2 ^ 52 := by
  change (x.toBitVec.sshiftRight (min 52 63)).toInt = x.toBitVec.toInt / 2 ^ 52
  rw [BitVec.toInt_sshiftRight, Int.shiftRight_eq_div_pow]
  rfl

theorem mask_normalized (x : UInt64) :
    (x &&& UInt64.ofNat (2 ^ 52 - 1)).toNat < 2 ^ 52 := by
  rw [LeanBlsSimd.Lane.toNat_and_mask _ _ (by decide)]
  exact Nat.mod_lt _ (by norm_num)

theorem limb_mask (x : UInt64) :
    limb (x &&& UInt64.ofNat (2 ^ 52 - 1)) = limb x % 2 ^ 52 := by
  rw [limb_eq_nat (by have := mask_normalized x; omega),
    LeanBlsSimd.Lane.toNat_and_mask _ _ (by decide), limb_eq]
  split_ifs <;> omega

theorem val_eq_nat {n : ℕ} {a : Vector UInt64 n} (ha : Normalized a) :
    val a = ((∑ j : Fin n, a[j].toNat * 2 ^ (52 * j.val) : ℕ) : ℤ) := by
  unfold val
  push_cast
  apply Finset.sum_congr rfl
  intro j _
  rw [limb_eq_nat (by have := ha j; omega)]

theorem normalized_bounded {n : ℕ} {a : Vector UInt64 n} (ha : Normalized a) :
    Bounded a 1 := by
  intro j
  rw [limb_eq_nat (by have := ha j; omega), abs_of_nonneg (by omega)]
  have := ha j
  norm_num at *
  omega

theorem addRaw_val {n : ℕ} {a b : Vector UInt64 n}
    (h : ∀ j : Fin n, -(2 : ℤ) ^ 63 ≤ limb a[j] + limb b[j] ∧
      limb a[j] + limb b[j] < 2 ^ 63) :
    val (addRaw a b) = val a + val b := by
  simp only [Fin.getElem_fin] at h
  simp only [val, addRaw, Vector.getElem_ofFn, Fin.getElem_fin]
  rw [← Finset.sum_add_distrib]
  apply Finset.sum_congr rfl
  intro j _
  rw [limb_add (h j).1 (h j).2, add_mul]

theorem addRaw_spec {n : ℕ} {a b : Vector UInt64 n} {m k : ℤ}
    (ha : Bounded a m) (hb : Bounded b k) (h : (m + k) * 2 ^ 52 ≤ 2 ^ 63) :
    val (addRaw a b) = val a + val b ∧ Bounded (addRaw a b) (m + k) := by
  have hs (j : Fin n) : |limb a[j] + limb b[j]| < (m + k) * 2 ^ 52 := by
    have := abs_add_le (limb a[j]) (limb b[j])
    have := ha j
    have := hb j
    linarith
  have hr (j : Fin n) : -(2 : ℤ) ^ 63 ≤ limb a[j] + limb b[j] ∧
      limb a[j] + limb b[j] < 2 ^ 63 := by
    have := abs_lt.mp (hs j)
    constructor <;> linarith
  refine ⟨addRaw_val hr, fun j => ?_⟩
  simp only [Fin.getElem_fin] at hr hs
  simpa only [addRaw, Vector.getElem_ofFn, Fin.getElem_fin,
    limb_add (hr j).1 (hr j).2] using hs j

theorem subRaw_spec {n : ℕ} {a b offset : Vector UInt64 n} {m k : ℤ}
    (ha : Bounded a m) (hb : Bounded b k) (ho : Normalized offset)
    (_hm : 0 ≤ m) (hk : 0 ≤ k) (h : (m + k + 1) * 2 ^ 52 ≤ 2 ^ 63) :
    val (subRaw a b offset) = val a + val offset - val b ∧
      Bounded (subRaw a b offset) (m + k + 1) := by
  have ho' := normalized_bounded ho
  have ha' (j : Fin n) : -(2 : ℤ) ^ 63 ≤ limb a[j] + limb offset[j] ∧
      limb a[j] + limb offset[j] < 2 ^ 63 := by
    have := abs_lt.mp (ha j)
    have := abs_lt.mp (ho' j)
    constructor <;> linarith
  have hs (j : Fin n) :
      |limb a[j] + limb offset[j] - limb b[j]| < (m + k + 1) * 2 ^ 52 := by
    have := abs_add_le (limb a[j]) (limb offset[j])
    have := abs_sub (limb a[j] + limb offset[j]) (limb b[j])
    have := ha j
    have := hb j
    have := ho' j
    linarith
  have he (j : Fin n) : limb (a[j] + offset[j] - b[j]) =
      limb a[j] + limb offset[j] - limb b[j] := by
    rw [limb_sub, limb_add (ha' j).1 (ha' j).2]
    all_goals
      rw [limb_add (ha' j).1 (ha' j).2]
      have := abs_lt.mp (hs j)
      linarith
  constructor
  · simp only [val, subRaw, Vector.getElem_ofFn, Fin.getElem_fin]
    simp only [Fin.getElem_fin] at he
    rw [← Finset.sum_add_distrib, ← Finset.sum_sub_distrib]
    apply Finset.sum_congr rfl
    intro j _
    rw [he j]
    ring
  · intro j
    simp only [Fin.getElem_fin] at he hs
    simpa only [subRaw, Vector.getElem_ofFn, Fin.getElem_fin, he j] using hs j

theorem limb_eq_nat_of_nonneg {x : UInt64} (hx : 0 ≤ limb x) :
    limb x = (x.toNat : ℤ) := by
  have := x.toNat_lt_size
  rw [limb_eq] at hx ⊢
  split_ifs
  · rfl
  · simp only [UInt64.size] at this
    omega

/-- The carry has twelve signed bits; the next limb retains ample signed headroom. -/
theorem carry_limb_spec {x y : UInt64}
    (hx : |limb x| < (2 : ℤ) ^ 62 + 2048) (hy : |limb y| < (2 : ℤ) ^ 62) :
    limb (y + srai 52 x) = limb y + limb x / 2 ^ 52 ∧
      |limb (y + srai 52 x)| < (2 : ℤ) ^ 62 + 2048 := by
  have hx' := abs_lt.mp hx
  have hy' := abs_lt.mp hy
  have hc : -(2048 : ℤ) < limb x / 2 ^ 52 ∧ limb x / 2 ^ 52 < 2048 := by omega
  have he : limb (y + srai 52 x) = limb y + limb x / 2 ^ 52 := by
    rw [limb_add, limb_srai52]
    all_goals rw [limb_srai52]; omega
  exact ⟨he, by rw [he]; apply abs_lt.mpr; constructor <;> omega⟩

private theorem val_set {n : ℕ} (a : Vector UInt64 n) (i : Fin n) (x : UInt64) :
    val (a.set i.val x) = val a + (limb x - limb a[i]) * 2 ^ (52 * i.val) := by
  unfold val
  have hs := Finset.sum_ite_eq' Finset.univ i
    (fun _ => (limb x - limb a[i]) * (2 : ℤ) ^ (52 * i.val))
  simp only [Finset.mem_univ, if_true] at hs
  rw [← hs]
  rw [← Finset.sum_add_distrib]
  apply Finset.sum_congr rfl
  intro j _
  simp only [Fin.getElem_fin, Vector.getElem_set]
  by_cases h : i = j
  · subst j; simp; ring
  · have hv : i.val ≠ j.val := fun e => h (Fin.ext e)
    simp [hv, Ne.symm h]

private theorem carryStep_val {n : ℕ} (a : Vector UInt64 n) (j : Fin (n - 1))
    (hx : |limb a[j.val]| < (2 : ℤ) ^ 62 + 2048)
    (hy : |limb a[j.val + 1]| < (2 : ℤ) ^ 62) :
    val (carryStep a j) = val a := by
  have hc := (carry_limb_spec hx hy).1
  unfold carryStep
  rw [val_set _ ⟨j.val, by omega⟩, val_set _ ⟨j.val + 1, by omega⟩]
  simp only [Fin.getElem_fin, Vector.getElem_set, show j.val + 1 ≠ j.val by omega,
    if_false, limb_mask]
  rw [hc, Nat.mul_add, pow_add]
  have he := Int.emod_add_mul_ediv (limb a[j.val]) ((2 : ℤ) ^ 52)
  simp only [Nat.mul_one]
  linear_combination he * (2 : ℤ) ^ (52 * j.val)

private theorem prefix_bound (k : ℕ) (f : ℕ → ℤ)
    (hf : ∀ j < k, 0 ≤ f j ∧ f j < 2 ^ 52) :
    0 ≤ ∑ j ∈ Finset.range k, f j * (2 : ℤ) ^ (52 * j) ∧
    ∑ j ∈ Finset.range k, f j * (2 : ℤ) ^ (52 * j) < 2 ^ (52 * k) := by
  induction k with
  | zero => simp
  | succ k ih =>
    have hi := ih (fun j hj => hf j (by omega))
    have hk := hf k (by omega)
    have hp : (0 : ℤ) < 2 ^ (52 * k) := by positivity
    rw [Finset.sum_range_succ, Nat.mul_add, pow_add]
    simp only [Nat.mul_one]
    constructor
    · exact add_nonneg hi.1 (mul_nonneg hk.1 hp.le)
    · nlinarith

private theorem normalise_prefix {n : ℕ} (a : Vector UInt64 n)
    (ha : ∀ j : Fin n, |limb a[j]| < (2 : ℤ) ^ 62) (k : ℕ) (hk : k ≤ n - 1) :
    let b := ((List.finRange (n - 1)).take k).foldl carryStep a
    val b = val a ∧
    (∀ j : Fin n, j.val < k → b[j].toNat < 2 ^ 52) ∧
    (∀ j : Fin n, j.val = k → |limb b[j]| < (2 : ℤ) ^ 62 + 2048) ∧
    (∀ j : Fin n, k < j.val → b[j] = a[j]) := by
  induction k with
  | zero =>
    simp only [List.take_zero, List.foldl_nil]
    refine ⟨True.intro, ?_, ?_, ?_⟩
    · intro j hj; omega
    · intro j _; have := ha j; omega
    · intro j _; trivial
  | succ k ih =>
    have hi := ih (by omega)
    let b := ((List.finRange (n - 1)).take k).foldl carryStep a
    change val b = val a ∧ _ at hi
    have hkn : k < n - 1 := by omega
    have he : ((List.finRange (n - 1)).take (k + 1)).foldl carryStep a =
        carryStep b ⟨k, hkn⟩ := by
      rw [List.take_add_one, List.getElem?_eq_getElem (by simpa using hkn)]
      simp [List.foldl_append, b]
    rw [he]
    have hx : |limb b[k]| < (2 : ℤ) ^ 62 + 2048 := hi.2.2.1 ⟨k, by omega⟩ rfl
    have hy : |limb b[k + 1]| < (2 : ℤ) ^ 62 := by
      have he := hi.2.2.2 ⟨k + 1, by omega⟩ (by simp)
      change b[k + 1] = a[k + 1] at he
      rw [he]
      exact ha ⟨k + 1, by omega⟩
    refine ⟨(carryStep_val b ⟨k, hkn⟩ hx hy).trans hi.1, ?_, ?_, ?_⟩
    · intro j hj
      by_cases hjk : k = j.val
      · simp only [carryStep, Fin.getElem_fin, Vector.getElem_set, hjk, if_true,
          show j.val + 1 ≠ j.val by omega, if_false]
        exact mask_normalized _
      · have hjk' : k + 1 ≠ j.val := by omega
        simpa only [carryStep, Fin.getElem_fin, Vector.getElem_set, hjk, hjk',
          if_false, show k + 1 ≠ k by omega] using hi.2.1 j (by omega)
    · intro j hj
      have hne : k ≠ j.val := by omega
      simp only [carryStep, Fin.getElem_fin, Vector.getElem_set, hne, if_false,
        ← hj, if_true]
      simpa only [hj] using (carry_limb_spec hx hy).2
    · intro j hj
      have hne : k ≠ j.val := by omega
      have hne' : k + 1 ≠ j.val := by omega
      simpa only [carryStep, Fin.getElem_fin, Vector.getElem_set, hne, hne',
        if_false, show k + 1 ≠ k by omega] using hi.2.2.2 j (by omega)

private theorem normalized_of_prefix {n : ℕ} (a : Vector UInt64 (n + 1))
    (hn : ∀ j : Fin (n + 1), j.val < n → a[j].toNat < 2 ^ 52)
    (hlo : 0 ≤ val a) (hhi : val a < 2 ^ (52 * (n + 1))) : Normalized a := by
  let f (j : ℕ) : ℤ := if h : j < n + 1 then limb a[j] else 0
  have hf (j : ℕ) (hj : j < n + 1) : f j = limb a[j] := dif_pos hj
  have hb := prefix_bound n f (by
    intro j hj
    have hjn : a[j].toNat < 2 ^ 52 := hn ⟨j, by omega⟩ hj
    rw [hf j (by omega), limb_eq_nat (by omega)]
    constructor <;> omega)
  have hv : val a = (∑ j ∈ Finset.range n, f j * (2 : ℤ) ^ (52 * j)) +
      limb a[n] * 2 ^ (52 * n) := by
    unfold val
    rw [Fin.sum_univ_castSucc]
    simp only [Fin.val_last, Fin.val_castSucc, Fin.getElem_fin]
    congr 1
    rw [← Fin.sum_univ_eq_sum_range]
    apply Finset.sum_congr rfl
    intro j _
    rw [hf j.val (by omega)]
  have hp : (0 : ℤ) < 2 ^ (52 * n) := by positivity
  rw [hv] at hlo hhi
  rw [Nat.mul_add, pow_add] at hhi
  simp only [Nat.mul_one] at hhi
  have ht : 0 ≤ limb a[n] ∧ limb a[n] < 2 ^ 52 := by
    constructor
    · by_contra h; have : limb a[n] ≤ -1 := by omega
      nlinarith
    · by_contra h; have : (2 : ℤ) ^ 52 ≤ limb a[n] := by omega
      nlinarith
  intro j
  by_cases hj : j.val < n
  · exact hn j hj
  · have hjn : j.val = n := by omega
    simp only [Fin.getElem_fin, hjn]
    have := limb_eq_nat_of_nonneg ht.1
    omega

theorem normalise_width_spec {n : ℕ} {a : Vector UInt64 n}
    (ha : ∀ j : Fin n, |limb a[j]| < (2 : ℤ) ^ 62)
    (hlo : 0 ≤ val a) (hhi : val a < 2 ^ (52 * n)) :
    val (normalise a) = val a ∧ Normalized (normalise a) := by
  have hi := normalise_prefix a ha (n - 1) (by omega)
  have ht : (List.finRange (n - 1)).take (n - 1) = List.finRange (n - 1) :=
    List.take_of_length_le (by simp)
  rw [ht] at hi
  change val (normalise a) = val a ∧ _ at hi
  refine ⟨hi.1, ?_⟩
  cases n with
  | zero => intro j; exact Fin.elim0 j
  | succ n =>
    apply normalized_of_prefix (normalise a)
    · simpa only [Nat.add_sub_cancel] using hi.2.1
    · rwa [hi.1]
    · rwa [hi.1]

set_option exponentiation.threshold 1000 in
theorem val_five (a : Vector UInt64 5) :
    val a = limb a[0] + limb a[1] * 2 ^ 52 + limb a[2] * 2 ^ 104 +
      limb a[3] * 2 ^ 156 + limb a[4] * 2 ^ 208 := by
  simp [val, Fin.sum_univ_succ]
  ring

theorem normalise_five_eq (a : Vector UInt64 5) :
    let x1 := a[1] + srai 52 a[0]
    let x2 := a[2] + srai 52 x1
    let x3 := a[3] + srai 52 x2
    let x4 := a[4] + srai 52 x3
    normalise a = #v[
      a[0] &&& UInt64.ofNat (2 ^ 52 - 1),
      x1 &&& UInt64.ofNat (2 ^ 52 - 1),
      x2 &&& UInt64.ofNat (2 ^ 52 - 1),
      x3 &&& UInt64.ofNat (2 ^ 52 - 1), x4] := by
  have hf : List.finRange (5 - 1) = [0, 1, 2, 3] := by decide
  simp only [normalise, hf, List.foldl_cons, List.foldl_nil]
  ext j hj
  interval_cases j <;> simp [carryStep]

set_option exponentiation.threshold 1000 in
/-- Signed carries preserve the five-limb integer. The range of that integer forces
the unmasked final limb into radix 52, including when an input limb is negative. -/
theorem normalise_spec {a : Vector UInt64 5}
    (ha : ∀ j : Fin 5, |limb a[j]| < (2 : ℤ) ^ 62)
    (hlo : 0 ≤ val a) (hhi : val a < 2 ^ 260) :
    val (normalise a) = val a ∧ Normalized (normalise a) := by
  exact normalise_width_spec ha hlo hhi

set_option exponentiation.threshold 1000 in
theorem val_eight (a : Vector UInt64 8) :
    val a = limb a[0] + limb a[1] * 2 ^ 52 + limb a[2] * 2 ^ 104 +
      limb a[3] * 2 ^ 156 + limb a[4] * 2 ^ 208 + limb a[5] * 2 ^ 260 +
      limb a[6] * 2 ^ 312 + limb a[7] * 2 ^ 364 := by
  simp [val, Fin.sum_univ_eight]

theorem normalise_eight_eq (a : Vector UInt64 8) :
    let x1 := a[1] + srai 52 a[0]
    let x2 := a[2] + srai 52 x1
    let x3 := a[3] + srai 52 x2
    let x4 := a[4] + srai 52 x3
    let x5 := a[5] + srai 52 x4
    let x6 := a[6] + srai 52 x5
    let x7 := a[7] + srai 52 x6
    normalise a = #v[
      a[0] &&& UInt64.ofNat (2 ^ 52 - 1),
      x1 &&& UInt64.ofNat (2 ^ 52 - 1),
      x2 &&& UInt64.ofNat (2 ^ 52 - 1),
      x3 &&& UInt64.ofNat (2 ^ 52 - 1),
      x4 &&& UInt64.ofNat (2 ^ 52 - 1),
      x5 &&& UInt64.ofNat (2 ^ 52 - 1),
      x6 &&& UInt64.ofNat (2 ^ 52 - 1), x7] := by
  have hf : List.finRange (8 - 1) = [0, 1, 2, 3, 4, 5, 6] := by decide
  simp only [normalise, hf, List.foldl_cons, List.foldl_nil]
  ext j hj
  interval_cases j <;> simp [carryStep]

set_option exponentiation.threshold 1000 in
/-- Signed carries preserve the eight-limb integer; its range bounds the final limb. -/
theorem normalise_eight_spec {a : Vector UInt64 8}
    (ha : ∀ j : Fin 8, |limb a[j]| < (2 : ℤ) ^ 62)
    (hlo : 0 ≤ val a) (hhi : val a < 2 ^ 416) :
    val (normalise a) = val a ∧ Normalized (normalise a) := by
  exact normalise_width_spec ha hlo hhi

end LeanBlsSimd.SignedLimbs
