import LeanBlsSimd.Model.Fr8Product
import LeanBlsSimd.Proofs.Fr8
import LeanBlsSimd.Proofs.Reduction

namespace LeanBlsSimd.FrModel
open EthCryptographySpecs.Bls

namespace Lane

private theorem madd52lo_bound (t a b : UInt64) :
    (madd52lo t a b).toNat ≤ t.toNat + 2 ^ 52 := by
  have h := Nat.mod_lt (lo52 a * lo52 b) (show 0 < 2 ^ 52 by decide)
  simp only [madd52lo, UInt64.toNat_add, UInt64.toNat_ofNat']
  have h1 := Nat.mod_le (t.toNat + (lo52 a * lo52 b % 2 ^ 52) % UInt64.size)
    UInt64.size
  have h2 := Nat.mod_le (lo52 a * lo52 b % 2 ^ 52) UInt64.size
  omega

private theorem madd52hi_bound (t a b : UInt64) :
    (madd52hi t a b).toNat ≤ t.toNat + 2 ^ 52 := by
  have h : lo52 a * lo52 b / 2 ^ 52 < 2 ^ 52 := by
    rw [Nat.div_lt_iff_lt_mul (by decide)]
    exact Nat.mul_lt_mul'' (LeanBlsSimd.Lane.lo52_lt _) (LeanBlsSimd.Lane.lo52_lt _)
  simp only [madd52hi, UInt64.toNat_add, UInt64.toNat_ofNat']
  have h1 := Nat.mod_le (t.toNat + (lo52 a * lo52 b / 2 ^ 52) % UInt64.size)
    UInt64.size
  have h2 := Nat.mod_le (lo52 a * lo52 b / 2 ^ 52) UInt64.size
  omega

-- Separate fixed rows keep the finite-case proofs within default heartbeat limits.
private theorem muladd_row_bound_0 (t : Acc) (a : Limbs) (b : UInt64) (B : ℕ)
    (ht : ∀ k : Fin (2 * LIMBS + 1), t[k].toNat ≤ B) :
    ∀ k : Fin (2 * LIMBS + 1), (muladd_row t a b 0)[k].toNat ≤ B + 2 * 2 ^ 52 := by
  intro ⟨k, hk⟩
  have hbase := ht ⟨k, hk⟩
  simp only [LIMBS] at hk
  interval_cases k <;>
    simp only [muladd_row, finRange_LIMBS, List.foldl_cons, List.foldl_nil,
      Fin.getElem_fin, val_fin_LIMBS, Nat.reduceAdd,
      Vector.getElem_set, Nat.reduceEqDiff, ↓reduceIte] at *
  all_goals grind only [madd52lo_bound, madd52hi_bound]

private theorem muladd_row_bound_1 (t : Acc) (a : Limbs) (b : UInt64) (B : ℕ)
    (ht : ∀ k : Fin (2 * LIMBS + 1), t[k].toNat ≤ B) :
    ∀ k : Fin (2 * LIMBS + 1), (muladd_row t a b 1)[k].toNat ≤ B + 2 * 2 ^ 52 := by
  intro ⟨k, hk⟩
  have hbase := ht ⟨k, hk⟩
  simp only [LIMBS] at hk
  interval_cases k <;>
    simp only [muladd_row, finRange_LIMBS, List.foldl_cons, List.foldl_nil,
      Fin.getElem_fin, val_fin_LIMBS, Nat.reduceAdd,
      Vector.getElem_set, Nat.reduceEqDiff, ↓reduceIte] at *
  all_goals grind only [madd52lo_bound, madd52hi_bound]

private theorem muladd_row_bound_2 (t : Acc) (a : Limbs) (b : UInt64) (B : ℕ)
    (ht : ∀ k : Fin (2 * LIMBS + 1), t[k].toNat ≤ B) :
    ∀ k : Fin (2 * LIMBS + 1), (muladd_row t a b 2)[k].toNat ≤ B + 2 * 2 ^ 52 := by
  intro ⟨k, hk⟩
  have hbase := ht ⟨k, hk⟩
  simp only [LIMBS] at hk
  interval_cases k <;>
    simp only [muladd_row, finRange_LIMBS, List.foldl_cons, List.foldl_nil,
      Fin.getElem_fin, val_fin_LIMBS, Nat.reduceAdd,
      Vector.getElem_set, Nat.reduceEqDiff, ↓reduceIte] at *
  all_goals grind only [madd52lo_bound, madd52hi_bound]

private theorem muladd_row_bound_3 (t : Acc) (a : Limbs) (b : UInt64) (B : ℕ)
    (ht : ∀ k : Fin (2 * LIMBS + 1), t[k].toNat ≤ B) :
    ∀ k : Fin (2 * LIMBS + 1), (muladd_row t a b 3)[k].toNat ≤ B + 2 * 2 ^ 52 := by
  intro ⟨k, hk⟩
  have hbase := ht ⟨k, hk⟩
  simp only [LIMBS] at hk
  interval_cases k <;>
    simp only [muladd_row, finRange_LIMBS, List.foldl_cons, List.foldl_nil,
      Fin.getElem_fin, val_fin_LIMBS, Nat.reduceAdd,
      Vector.getElem_set, Nat.reduceEqDiff, ↓reduceIte] at *
  all_goals grind only [madd52lo_bound, madd52hi_bound]

private theorem muladd_row_bound_4 (t : Acc) (a : Limbs) (b : UInt64) (B : ℕ)
    (ht : ∀ k : Fin (2 * LIMBS + 1), t[k].toNat ≤ B) :
    ∀ k : Fin (2 * LIMBS + 1), (muladd_row t a b 4)[k].toNat ≤ B + 2 * 2 ^ 52 := by
  intro ⟨k, hk⟩
  have hbase := ht ⟨k, hk⟩
  simp only [LIMBS] at hk
  interval_cases k <;>
    simp only [muladd_row, finRange_LIMBS, List.foldl_cons, List.foldl_nil,
      Fin.getElem_fin, val_fin_LIMBS, Nat.reduceAdd,
      Vector.getElem_set, Nat.reduceEqDiff, ↓reduceIte] at *
  all_goals grind only [madd52lo_bound, madd52hi_bound]

/-- Each accumulator cell receives at most one low and one high IFMA half per row. -/
theorem muladd_row_bound (t : Acc) (a : Limbs) (b : UInt64) (i : Fin LIMBS) (B : ℕ)
    (ht : ∀ k : Fin (2 * LIMBS + 1), t[k].toNat ≤ B) :
    ∀ k : Fin (2 * LIMBS + 1), (muladd_row t a b i)[k].toNat ≤ B + 2 * 2 ^ 52 := by
  obtain ⟨i, hi⟩ := i
  simp only [LIMBS] at hi
  interval_cases i
  · exact muladd_row_bound_0 t a b B ht
  · exact muladd_row_bound_1 t a b B ht
  · exact muladd_row_bound_2 t a b B ht
  · exact muladd_row_bound_3 t a b B ht
  · exact muladd_row_bound_4 t a b B ht

theorem reduce_row_bound (t : Acc) (p : Limbs) (pinv : UInt64) (i : Fin LIMBS) (B : ℕ)
    (ht : ∀ k : Fin (2 * LIMBS + 1), t[k].toNat ≤ B) :
    ∀ k : Fin (2 * LIMBS + 1),
      (reduce_row t p pinv i)[k].toNat ≤ B + 2 * 2 ^ 52 + 2 ^ 12 := by
  unfold reduce_row
  extract_lets q t'
  have ht' := muladd_row_bound t p q i B ht
  change ∀ k : Fin (2 * LIMBS + 1), t'[k].toNat ≤ B + 2 * 2 ^ 52 at ht'
  intro k
  simp only [Fin.getElem_fin, Vector.getElem_set]
  split_ifs
  · have hi : i.val < 2 * LIMBS + 1 := by omega
    have hi1 : i.val + 1 < 2 * LIMBS + 1 := by omega
    have hb := ht' ⟨i.val + 1, hi1⟩
    have hc : (srli 52 (t'[i.val]'hi)).toNat < 2 ^ 12 := by
      rw [LeanBlsSimd.Lane.toNat_srli52]
      have := (t'[i.val]'hi).toNat_lt_size
      simp only [UInt64.size] at this
      omega
    rw [UInt64.toNat_add]
    have hm := Nat.mod_le ((t'[i.val + 1]'hi1).toNat +
      (srli 52 (t'[i.val]'hi)).toNat) UInt64.size
    simp only [Fin.getElem_fin] at hb
    omega
  · have := ht' k
    simp only [Fin.getElem_fin] at this
    omega

/-- Ten rows contribute at most twenty IFMA halves and five 12-bit carries per cell. -/
theorem mulAcc_bound (a b : Limbs) :
    ∀ k : Fin (2 * LIMBS + 1), (mulAcc a b)[k].toNat < 2 ^ 57 := by
  unfold mulAcc
  extract_lets p pinv t0 t1 t2 t3 t4 t5 t6 t7 t8 t9
  have b0 : ∀ k : Fin (2 * LIMBS + 1), t0[k].toNat ≤ 0 := by simp [t0, zero]
  have b1 := muladd_row_bound t0 a b[0] 0 _ b0
  have b2 := muladd_row_bound t1 a b[1] 1 _ b1
  have b3 := muladd_row_bound t2 a b[2] 2 _ b2
  have b4 := muladd_row_bound t3 a b[3] 3 _ b3
  have b5 := muladd_row_bound t4 a b[4] 4 _ b4
  have b6 := reduce_row_bound t5 p pinv 0 _ b5
  have b7 := reduce_row_bound t6 p pinv 1 _ b6
  have b8 := reduce_row_bound t7 p pinv 2 _ b7
  have b9 := reduce_row_bound t8 p pinv 3 _ b8
  have b10 := reduce_row_bound t9 p pinv 4 _ b9
  intro k
  exact (b10 k).trans_lt (by norm_num)

theorem mulRaw_bound (a b : Limbs) :
    ∀ j : Fin LIMBS, (mulRaw a b)[j].toNat < 2 ^ 57 := by
  intro j
  simpa only [mulRaw, Fin.getElem_fin, Vector.getElem_ofFn] using
    mulAcc_bound a b ⟨LIMBS + j.val, by have := j.isLt; omega⟩

def productAcc (a b : Limbs) : Acc :=
  let t : Acc := .replicate _ zero
  let t := muladd_row t a b[0] 0
  let t := muladd_row t a b[1] 1
  let t := muladd_row t a b[2] 2
  let t := muladd_row t a b[3] 3
  muladd_row t a b[4] 4

theorem productAcc_bound (a b : Limbs) :
    ∀ k : Fin (2 * LIMBS + 1), (productAcc a b)[k].toNat < 2 ^ 56 := by
  unfold productAcc
  extract_lets t0 t1 t2 t3 t4
  have b0 : ∀ k : Fin (2 * LIMBS + 1), t0[k].toNat ≤ 0 := by simp [t0, zero]
  have b1 := muladd_row_bound t0 a b[0] 0 _ b0
  have b2 := muladd_row_bound t1 a b[1] 1 _ b1
  have b3 := muladd_row_bound t2 a b[2] 2 _ b2
  have b4 := muladd_row_bound t3 a b[3] 3 _ b3
  have b5 := muladd_row_bound t4 a b[4] 4 _ b4
  intro k
  exact (b5 k).trans_lt (by norm_num)

theorem referenceRow_eq : @Reduction.referenceRow LIMBS = reduce_row := rfl

theorem referenceRows_productAcc (a b : Limbs) :
    Reduction.referenceRows (productAcc a b) (Limbs.ofList P) (.ofNat P_INV52) =
      mulAcc a b := by
  have hs (x : UInt64) : splat x = x := UInt64.toUInt64_toInt64 x
  have hp (x : Limbs) : splat_limbs x = x := by
    ext j hj
    simp [splat_limbs, hs]
  simp only [Reduction.referenceRows, finRange_LIMBS, List.foldl_cons, List.foldl_nil,
    referenceRow_eq, mulAcc, productAcc, hp, hs]

theorem earlyRows_productAcc (a b : Limbs) :
    Reduction.SameFrom LIMBS
      (Reduction.earlyRows (productAcc a b) (Limbs.ofList P) (.ofNat P_INV52))
      (mulAcc a b) := by
  rw [← referenceRows_productAcc]
  exact Reduction.rows_agree (by decide) _ _ _ (by decide)

theorem val_mulRaw (a b : Limbs) :
    val (mulRaw a b) =
      ∑ k : Fin LIMBS, (mulAcc a b)[LIMBS + k.val].toNat * 2 ^ (52 * k.val) := by
  simp [val, mulRaw, LIMB_BITS]

attribute [local irreducible] mulAcc mulRaw in
set_option exponentiation.threshold 1000 in
theorem mulRaw_value_spec {a b : Limbs}
    (ha : ∀ j : Fin LIMBS, a[j].toNat < 2 ^ LIMB_BITS)
    (hb : ∀ j : Fin LIMBS, b[j].toNat < 2 ^ LIMB_BITS)
    (hAB : val a * val b < Fr.modulus * R) :
    val (mulRaw a b) < 2 * Fr.modulus ∧
      (val (mulRaw a b) : ZMod Fr.modulus) =
        val a * val b * (R : ZMod Fr.modulus)⁻¹ := by
  obtain ⟨_, Q, hQ, hv⟩ := mulAcc_spec ha hb
  rw [valFrom_LIMBS, ← val_mulRaw] at hv
  generalize (mulAcc a b)[2 * LIMBS].toNat = y at hv
  have hvN := hv
  have hABN := hAB
  have hQN := hQ
  simp only [Fr.modulus, R, LIMBS, LIMB_BITS, Nat.reduceMul] at hvN hABN hQN
  have hlt : val (mulRaw a b) < 2 * Fr.modulus := by
    simp only [Fr.modulus]
    omega
  have hy : y = 0 := by omega
  refine ⟨hlt, ?_⟩
  have hR : (R : ZMod Fr.modulus) ≠ 0 := by
    rw [Ne, ZMod.natCast_eq_zero_iff]
    decide
  rw [eq_mul_inv_iff_mul_eq₀ hR]
  have := congrArg (Nat.cast : ℕ → ZMod Fr.modulus) hv
  rw [hy] at this
  push_cast [ZMod.natCast_self] at this
  simpa [mul_comm] using this

theorem mulRaw_spec {a b : Limbs}
    (ha : ∀ j : Fin LIMBS, a[j].toNat < 2 ^ LIMB_BITS)
    (hb : ∀ j : Fin LIMBS, b[j].toNat < 2 ^ LIMB_BITS)
    (hAB : val a * val b < Fr.modulus * R) :
    (∀ j : Fin LIMBS, (mulRaw a b)[j].toNat < 2 ^ 57) ∧
      val (mulRaw a b) < 2 * Fr.modulus ∧
      (val (mulRaw a b) : ZMod Fr.modulus) =
        val a * val b * (R : ZMod Fr.modulus)⁻¹ :=
  ⟨mulRaw_bound a b, mulRaw_value_spec ha hb hAB⟩

theorem val_mul_eq_mulRaw (a b : Limbs) : val (mul a b) = val (mulRaw a b) := by
  rw [val_mulRaw]
  exact (normalize_spec (mulAcc a b) (splat (.ofNat MASK52)) splat_MASK52
    (fun k => (mulAcc_bound a b k).le.trans (by norm_num))).2

end Lane

theorem Fr8.lane_mulRaw (a b : Fr8) (l : Fin 8) :
    (a.mulRaw b).lane l = Lane.mulRaw (a.lane l) (b.lane l) := by
  simp [Fr8.mulRaw, Fr8.lane_ofLanes]

theorem Fr8.mulRaw_spec {a b : Fr8} (l : Fin 8)
    (ha : ∀ j : Fin LIMBS, (a.lane l)[j].toNat < 2 ^ LIMB_BITS)
    (hb : ∀ j : Fin LIMBS, (b.lane l)[j].toNat < 2 ^ LIMB_BITS)
    (hAB : val (a.lane l) * val (b.lane l) < Fr.modulus * R) :
    (∀ j : Fin LIMBS, ((a.mulRaw b).lane l)[j].toNat < 2 ^ 57) ∧
      val ((a.mulRaw b).lane l) < 2 * Fr.modulus ∧
      (val ((a.mulRaw b).lane l) : ZMod Fr.modulus) =
        val (a.lane l) * val (b.lane l) * (R : ZMod Fr.modulus)⁻¹ := by
  rw [Fr8.lane_mulRaw]
  exact Lane.mulRaw_spec ha hb hAB

end LeanBlsSimd.FrModel
