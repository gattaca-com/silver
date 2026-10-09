import LeanBlsSimd.Proofs.Vector

/-!
# The borrow and carry chains of `sub_limbs` and `add_limbs`

On normalised limbs, `Lane.sub_limbs a b` returns limbs of `val a - val b`, wrapped modulo R, and
a borrow of all ones exactly when `val a < val b` (`sub_limbs_spec`). `Lane.add_limbs a b` returns
limbs of `(val a + val b) % R`: it drops the carry out of the top limb (`add_limbs_spec`).

Within a limb, `sub_limbs` relies on 64-bit wrapping: a negative difference wraps to a value at
least 2^64 − 2^52 − 1, so its bit 63 is set, and `srai 63` turns it into a borrow of all ones.
`add_limbs` never wraps a 64-bit lane: each limb sum stays below 2^53 + 1.
-/

namespace LeanBlsSimd

open EthCryptographySpecs.Bls

set_option exponentiation.threshold 1000 in
theorem R_eq : R = 2 ^ 416 := rfl

theorem val_eq (a : Limbs) : val a = a[0].toNat + a[1].toNat * 2 ^ 52 + a[2].toNat * 2 ^ 104 +
    a[3].toNat * 2 ^ 156 + a[4].toNat * 2 ^ 208 + a[5].toNat * 2 ^ 260 + a[6].toNat * 2 ^ 312 +
    a[7].toNat * 2 ^ 364 := by
  unfold val
  rw [sum_fin_limbs]
  simp only [Fin.getElem_fin, val_fin_LIMBS, LIMB_BITS, Nat.reduceMul, pow_zero, mul_one]

theorem eq_of_val_eq {a b : Limbs} (ha : ∀ j : Fin LIMBS, a[j].toNat < 2 ^ 52)
    (hb : ∀ j : Fin LIMBS, b[j].toNat < 2 ^ 52) (h : val a = val b) : a = b := by
  rw [val_eq, val_eq] at h
  have := ha 0; have := ha 1; have := ha 2; have := ha 3
  have := ha 4; have := ha 5; have := ha 6; have := ha 7
  have := hb 0; have := hb 1; have := hb 2; have := hb 3
  have := hb 4; have := hb 5; have := hb 6; have := hb 7
  simp only [Fin.getElem_fin, val_fin_LIMBS] at *
  ext j hj
  simp only [LIMBS] at hj
  interval_cases j <;> omega

set_option exponentiation.threshold 1000 in
theorem val_replicate_zero : val (.replicate LIMBS 0 : Limbs) = 0 := by decide

theorem val_eq_zero_iff {a : Limbs} : val a = 0 ↔ a = .replicate _ 0 := by
  constructor
  · intro h
    rw [val_eq] at h
    ext j hj
    simp only [LIMBS] at hj
    simp only [Vector.getElem_replicate]
    interval_cases j <;> simp <;> omega
  · rintro rfl
    exact val_replicate_zero

namespace Lane

/-- A borrow of `sub_limbs`: all ones for 1. -/
def borrowOf (c : Bool) : UInt64 := if c then 0xffffffffffffffff else 0

theorem decide_borrowOf (c : Bool) : decide (borrowOf c = 0xffffffffffffffff) = c := by
  cases c <;> decide

theorem srai63_eq (x : UInt64) : srai 63 x = borrowOf (decide (2 ^ 63 ≤ x.toNat)) := by
  apply UInt64.toNat_inj.mp
  have hx := x.toNat_lt_size
  simp only [UInt64.size] at hx
  simp only [srai, borrowOf, Nat.min_self, UInt64.toNat_ofBitVec, BitVec.toNat_sshiftRight,
    BitVec.msb_eq_decide, Nat.shiftRight_eq_div_pow]
  simp only [UInt64.toNat_toBitVec, decide_eq_true_eq, Nat.reduceSub]
  split_ifs <;> simp <;> omega

/-- The loop body of `sub_limbs`. -/
def subStep (a b : Limbs) (st : Limbs × UInt64) (j : Fin LIMBS) : Limbs × UInt64 :=
  let s := a[j] - b[j] + st.2
  (st.1.set j (s &&& splat (.ofNat MASK52)), srai 63 s)

theorem sub_limbs_eq (a b : Limbs) :
    sub_limbs a b = (List.finRange LIMBS).foldl (subStep a b) (.replicate _ 0, borrowOf false) :=
  rfl

/-- One limb of `sub_limbs`. The difference wraps modulo 2^64 when it is negative, that is when
`a < b + c`; bit 63 then marks it, and `srai 63` spreads that bit into the next borrow. -/
theorem subStep_spec (a b : Limbs) (st : Limbs × UInt64) (c : Bool) (hc : st.2 = borrowOf c)
    (j : Fin LIMBS) (ha : a[j].toNat < 2 ^ 52) (hb : b[j].toNat < 2 ^ 52) :
    ∃ x c', subStep a b st j = (st.1.set j x, borrowOf c') ∧ x.toNat < 2 ^ 52 ∧
      x.toNat + b[j].toNat + c.toNat = a[j].toNat + 2 ^ 52 * c'.toNat := by
  obtain ⟨d, borrow⟩ := st
  subst hc
  simp only [Fin.getElem_fin] at ha hb ⊢
  have hs : (a[j.val] - b[j.val] + borrowOf c).toNat =
      (a[j.val].toNat + 2 ^ 64 * 2 - b[j.val].toNat - c.toNat) % 2 ^ 64 := by
    cases c <;> simp [borrowOf, UInt64.toNat_add, UInt64.toNat_sub] <;> omega
  have hc : decide (2 ^ 63 ≤ (a[j.val] - b[j.val] + borrowOf c).toNat) =
      decide (a[j.val].toNat < b[j.val].toNat + c.toNat) := by
    rw [hs]
    cases c <;> simp <;> omega
  refine ⟨(a[j.val] - b[j.val] + borrowOf c) &&& splat (.ofNat MASK52),
    decide (a[j.val].toNat < b[j.val].toNat + c.toNat),
    by simp only [subStep, Fin.getElem_fin, srai63_eq, hc], ?_, ?_⟩
  · rw [toNat_and_mask _ _ splat_MASK52]
    exact Nat.mod_lt _ (by norm_num)
  · rw [toNat_and_mask _ _ splat_MASK52, hs]
    have := c.toNat_le
    by_cases h : a[j.val].toNat < b[j.val].toNat + c.toNat
    · rw [decide_eq_true h, Bool.toNat_true]
      omega
    · rw [decide_eq_false h, Bool.toNat_false]
      omega

set_option exponentiation.threshold 1000 in
theorem sub_limbs_chain {a b : Limbs} (ha : ∀ j : Fin LIMBS, a[j].toNat < 2 ^ 52)
    (hb : ∀ j : Fin LIMBS, b[j].toNat < 2 ^ 52) :
    ∃ d c, sub_limbs a b = (d, borrowOf c) ∧ (∀ j : Fin LIMBS, d[j].toNat < 2 ^ 52) ∧
      val d + val b = val a + c.toNat * R := by
  simp only [sub_limbs_eq, finRange_LIMBS, List.foldl_cons, List.foldl_nil]
  obtain ⟨x0, c1, e0, h0, v0⟩ := subStep_spec a b (.replicate _ 0, borrowOf false) false rfl 0 (ha 0) (hb 0)
  set s1 := subStep a b (.replicate _ 0, borrowOf false) 0
  obtain ⟨x1, c2, e1, h1, v1⟩ := subStep_spec a b s1 c1 (by rw [e0]) 1 (ha 1) (hb 1)
  set s2 := subStep a b s1 1
  obtain ⟨x2, c3, e2, h2, v2⟩ := subStep_spec a b s2 c2 (by rw [e1]) 2 (ha 2) (hb 2)
  set s3 := subStep a b s2 2
  obtain ⟨x3, c4, e3, h3, v3⟩ := subStep_spec a b s3 c3 (by rw [e2]) 3 (ha 3) (hb 3)
  set s4 := subStep a b s3 3
  obtain ⟨x4, c5, e4, h4, v4⟩ := subStep_spec a b s4 c4 (by rw [e3]) 4 (ha 4) (hb 4)
  set s5 := subStep a b s4 4
  obtain ⟨x5, c6, e5, h5, v5⟩ := subStep_spec a b s5 c5 (by rw [e4]) 5 (ha 5) (hb 5)
  set s6 := subStep a b s5 5
  obtain ⟨x6, c7, e6, h6, v6⟩ := subStep_spec a b s6 c6 (by rw [e5]) 6 (ha 6) (hb 6)
  set s7 := subStep a b s6 6
  obtain ⟨x7, c8, e7, h7, v7⟩ := subStep_spec a b s7 c7 (by rw [e6]) 7 (ha 7) (hb 7)
  rw [e7, e6, e5, e4, e3, e2, e1, e0]
  refine ⟨_, c8, rfl, fun j => ?_, ?_⟩
  · fin_cases j <;> simp [Vector.getElem_set] <;> assumption
  simp only [Fin.getElem_fin, val_fin_LIMBS] at v0 v1 v2 v3 v4 v5 v6 v7
  rw [val_eq, val_eq, val_eq]
  simp only [Vector.getElem_set, val_fin_LIMBS, R_eq]
  have := c1.toNat_le
  have := c2.toNat_le
  have := c3.toNat_le
  have := c4.toNat_le
  have := c5.toNat_le
  have := c6.toNat_le
  have := c7.toNat_le
  simp at v0 ⊢
  omega

set_option exponentiation.threshold 1000 in
theorem sub_limbs_spec {a b : Limbs} (ha : ∀ j : Fin LIMBS, a[j].toNat < 2 ^ 52)
    (hb : ∀ j : Fin LIMBS, b[j].toNat < 2 ^ 52) :
    (∀ j : Fin LIMBS, (sub_limbs a b).1[j].toNat < 2 ^ 52) ∧
      (sub_limbs a b).2 = borrowOf (decide (val a < val b)) ∧
      val (sub_limbs a b).1 + val b = val a + (decide (val a < val b)).toNat * R := by
  obtain ⟨d, c, e, hd, hv⟩ := sub_limbs_chain ha hb
  have hdR : val d < R := by
    rw [val_eq, R_eq]
    have := hd 0; have := hd 1; have := hd 2; have := hd 3
    have := hd 4; have := hd 5; have := hd 6; have := hd 7
    simp only [Fin.getElem_fin, val_fin_LIMBS] at *
    omega
  have hc : c = decide (val a < val b) := by
    rw [R_eq] at hv hdR
    cases c <;> simp at hv ⊢ <;> omega
  subst hc
  simp only [e]
  exact ⟨hd, trivial, hv⟩

/-- A carry of `add_limbs`. -/
def carryOf (c : Bool) : UInt64 := if c then 1 else 0

/-- The loop body of `add_limbs`. -/
def addStep (a b : Limbs) (st : Limbs × UInt64) (j : Fin LIMBS) : Limbs × UInt64 :=
  let t := a[j] + b[j] + st.2
  (st.1.set j (t &&& splat (.ofNat MASK52)), srli 52 t)

theorem add_limbs_eq (a b : Limbs) :
    add_limbs a b = (List.finRange LIMBS).foldl (addStep a b) (.replicate _ 0, carryOf false) :=
  rfl

/-- One limb of `add_limbs`: the sum stays below 2^53 + 1, so it never wraps. -/
theorem addStep_spec (a b : Limbs) (st : Limbs × UInt64) (c : Bool) (hc : st.2 = carryOf c)
    (j : Fin LIMBS) (ha : a[j].toNat < 2 ^ 52) (hb : b[j].toNat < 2 ^ 52) :
    ∃ x c', addStep a b st j = (st.1.set j x, carryOf c') ∧ x.toNat < 2 ^ 52 ∧
      x.toNat + 2 ^ 52 * c'.toNat = a[j].toNat + b[j].toNat + c.toNat := by
  obtain ⟨d, carry⟩ := st
  subst hc
  simp only [Fin.getElem_fin] at ha hb ⊢
  have ht : (a[j.val] + b[j.val] + carryOf c).toNat = a[j.val].toNat + b[j.val].toNat + c.toNat := by
    cases c <;> simp [carryOf, UInt64.toNat_add] <;> omega
  have hc' : srli 52 (a[j.val] + b[j.val] + carryOf c) =
      carryOf (decide (2 ^ 52 ≤ a[j.val].toNat + b[j.val].toNat + c.toNat)) := by
    apply UInt64.toNat_inj.mp
    rw [toNat_srli52, ht]
    have := c.toNat_le
    by_cases h : 2 ^ 52 ≤ a[j.val].toNat + b[j.val].toNat + c.toNat
    · simp only [h, decide_true, carryOf, if_true]
      simp only [UInt64.toNat_one]
      omega
    · simp only [h, decide_false, carryOf, Bool.false_eq_true, if_false, UInt64.toNat_zero]
      omega
  refine ⟨(a[j.val] + b[j.val] + carryOf c) &&& splat (.ofNat MASK52),
    decide (2 ^ 52 ≤ a[j.val].toNat + b[j.val].toNat + c.toNat),
    by simp only [addStep, Fin.getElem_fin, hc'], ?_, ?_⟩
  · rw [toNat_and_mask _ _ splat_MASK52]
    exact Nat.mod_lt _ (by norm_num)
  · rw [toNat_and_mask _ _ splat_MASK52, ht]
    have := c.toNat_le
    by_cases h : 2 ^ 52 ≤ a[j.val].toNat + b[j.val].toNat + c.toNat
    · rw [decide_eq_true h, Bool.toNat_true]
      omega
    · rw [decide_eq_false h, Bool.toNat_false]
      omega

set_option exponentiation.threshold 1000 in
theorem add_limbs_chain {a b : Limbs} (ha : ∀ j : Fin LIMBS, a[j].toNat < 2 ^ 52)
    (hb : ∀ j : Fin LIMBS, b[j].toNat < 2 ^ 52) :
    ∃ s c, add_limbs a b = (s, carryOf c) ∧ (∀ j : Fin LIMBS, s[j].toNat < 2 ^ 52) ∧
      val s + c.toNat * R = val a + val b := by
  simp only [add_limbs_eq, finRange_LIMBS, List.foldl_cons, List.foldl_nil]
  obtain ⟨x0, c1, e0, h0, v0⟩ := addStep_spec a b (.replicate _ 0, carryOf false) false rfl 0 (ha 0) (hb 0)
  set s1 := addStep a b (.replicate _ 0, carryOf false) 0
  obtain ⟨x1, c2, e1, h1, v1⟩ := addStep_spec a b s1 c1 (by rw [e0]) 1 (ha 1) (hb 1)
  set s2 := addStep a b s1 1
  obtain ⟨x2, c3, e2, h2, v2⟩ := addStep_spec a b s2 c2 (by rw [e1]) 2 (ha 2) (hb 2)
  set s3 := addStep a b s2 2
  obtain ⟨x3, c4, e3, h3, v3⟩ := addStep_spec a b s3 c3 (by rw [e2]) 3 (ha 3) (hb 3)
  set s4 := addStep a b s3 3
  obtain ⟨x4, c5, e4, h4, v4⟩ := addStep_spec a b s4 c4 (by rw [e3]) 4 (ha 4) (hb 4)
  set s5 := addStep a b s4 4
  obtain ⟨x5, c6, e5, h5, v5⟩ := addStep_spec a b s5 c5 (by rw [e4]) 5 (ha 5) (hb 5)
  set s6 := addStep a b s5 5
  obtain ⟨x6, c7, e6, h6, v6⟩ := addStep_spec a b s6 c6 (by rw [e5]) 6 (ha 6) (hb 6)
  set s7 := addStep a b s6 6
  obtain ⟨x7, c8, e7, h7, v7⟩ := addStep_spec a b s7 c7 (by rw [e6]) 7 (ha 7) (hb 7)
  rw [e7, e6, e5, e4, e3, e2, e1, e0]
  refine ⟨_, c8, rfl, fun j => ?_, ?_⟩
  · fin_cases j <;> simp [Vector.getElem_set] <;> assumption
  simp only [Fin.getElem_fin, val_fin_LIMBS] at v0 v1 v2 v3 v4 v5 v6 v7
  rw [val_eq, val_eq, val_eq]
  simp only [Vector.getElem_set, val_fin_LIMBS, R_eq]
  have := c1.toNat_le
  have := c2.toNat_le
  have := c3.toNat_le
  have := c4.toNat_le
  have := c5.toNat_le
  have := c6.toNat_le
  have := c7.toNat_le
  simp at v0 ⊢
  omega

theorem val_lt_R {a : Limbs} (ha : ∀ j : Fin LIMBS, a[j].toNat < 2 ^ 52) : val a < R := by
  rw [val_eq, R_eq]
  have := ha 0; have := ha 1; have := ha 2; have := ha 3
  have := ha 4; have := ha 5; have := ha 6; have := ha 7
  simp only [Fin.getElem_fin, val_fin_LIMBS] at *
  omega

/-- The carry out of the top limb is dropped: the value wraps modulo R. -/
theorem add_limbs_spec {a b : Limbs} (ha : ∀ j : Fin LIMBS, a[j].toNat < 2 ^ 52)
    (hb : ∀ j : Fin LIMBS, b[j].toNat < 2 ^ 52) :
    (∀ j : Fin LIMBS, (add_limbs a b).1[j].toNat < 2 ^ 52) ∧
      val (add_limbs a b).1 = (val a + val b) % R := by
  obtain ⟨s, c, e, hs, hv⟩ := add_limbs_chain ha hb
  have hsR := val_lt_R hs
  simp only [e]
  refine ⟨hs, ?_⟩
  have := c.toNat_le
  rw [← hv, Nat.add_mul_mod_self_right, Nat.mod_eq_of_lt hsR]

end Lane

end LeanBlsSimd
