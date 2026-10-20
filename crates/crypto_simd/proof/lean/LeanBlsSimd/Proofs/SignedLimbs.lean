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
  let x1 := a[1] + srai 52 a[0]
  let x2 := a[2] + srai 52 x1
  let x3 := a[3] + srai 52 x2
  let x4 := a[4] + srai 52 x3
  have h0 : |limb a[0]| < (2 : ℤ) ^ 62 + 2048 := by
    have h : |limb a[0]| < (2 : ℤ) ^ 62 := by simpa using ha 0
    omega
  have h1 := carry_limb_spec (x := a[0]) (y := a[1]) h0 (by simpa using ha 1)
  have h2 := carry_limb_spec (x := x1) (y := a[2]) h1.2 (by simpa using ha 2)
  have h3 := carry_limb_spec (x := x2) (y := a[3]) h2.2 (by simpa using ha 3)
  have h4 := carry_limb_spec (x := x3) (y := a[4]) h3.2 (by simpa using ha 4)
  change limb x1 = _ ∧ _ at h1
  change limb x2 = _ ∧ _ at h2
  change limb x3 = _ ∧ _ at h3
  change limb x4 = _ ∧ _ at h4
  have hv : val (normalise a) = val a := by
    rw [normalise_five_eq, val_five, val_five]
    simp only [Vector.getElem_mk, List.getElem_toArray, List.getElem_cons_zero,
      List.getElem_cons_succ, limb_mask]
    change limb a[0] % 2 ^ 52 + limb x1 % 2 ^ 52 * 2 ^ 52 +
      limb x2 % 2 ^ 52 * 2 ^ 104 + limb x3 % 2 ^ 52 * 2 ^ 156 +
      limb x4 * 2 ^ 208 = _
    omega
  refine ⟨hv, ?_⟩
  have hn := normalise_five_eq a
  change normalise a = #v[_, x1 &&& _, x2 &&& _, x3 &&& _, x4] at hn
  have ht : 0 ≤ limb x4 ∧ limb x4 < 2 ^ 52 := by
    rw [← hv, hn, val_five] at hlo hhi
    simp only [Vector.getElem_mk, List.getElem_toArray, List.getElem_cons_zero,
      List.getElem_cons_succ, limb_mask] at hlo hhi
    omega
  intro j
  rw [hn]
  fin_cases j <;> simp only [Fin.getElem_fin, Vector.getElem_mk,
    List.getElem_toArray, List.getElem_cons_zero, List.getElem_cons_succ]
  · exact mask_normalized _
  · exact mask_normalized _
  · exact mask_normalized _
  · exact mask_normalized _
  · have := limb_eq_nat_of_nonneg ht.1
    omega

end LeanBlsSimd.SignedLimbs
