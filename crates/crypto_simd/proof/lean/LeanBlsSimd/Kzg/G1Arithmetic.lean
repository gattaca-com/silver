import LeanBlsSimd.Kzg.G1Validity

open EthLib.Cryptography Bls
open WeierstrassCurve.Jacobian

namespace LeanBlsSimd.Kzg

theorem g1Valid_of_infinity {p : G1} (hp : p.isInfinity = true) : G1Valid p := by
  exact ⟨Or.inl hp, by simp only [G1.inSubgroup, hp, if_true]⟩

theorem g1Valid_zero : G1Valid G1.zero := g1Valid_of_infinity rfl

theorem g1_toPoint_of_infinity {p : G1} (hp : p.isInfinity = true) :
    G1.toPoint p = 0 := Point.toAffine_of_Z_eq_zero (G1.isZero_iff.mp hp)

theorem g1_groupValid_of_noninfinity {p : G1} (hp : G1Valid p)
    (hz : p.isInfinity ≠ true) : G1.Valid p :=
  g1_valid_of_affine hz (hp.1.resolve_left hz)

theorem g1Valid_of_groupValid {p : G1} (hp : G1.Valid p)
    (hs : Fr.modulus • G1.toPoint p = 0) : G1Valid p := by
  refine ⟨?_, (g1_inSubgroup_iff hp).mpr hs⟩
  by_cases hz : p.isInfinity = true
  · exact Or.inl hz
  · exact Or.inr (G1.affine_sqrt_witness hp hz)

theorem g1Valid_toPoint_zero_iff {p : G1} (hp : G1Valid p) :
    G1.toPoint p = 0 ↔ p.isInfinity = true := by
  by_cases hz : p.isInfinity = true
  · simp only [hz, g1_toPoint_of_infinity hz]
  · exact g1_toPoint_eq_zero_iff (g1_groupValid_of_noninfinity hp hz)

theorem g1Valid_subgroup {p : G1} (hp : G1Valid p) :
    Fr.modulus • G1.toPoint p = 0 := by
  by_cases hz : p.isInfinity = true
  · rw [g1_toPoint_of_infinity hz, nsmul_zero]
  · exact (g1_inSubgroup_iff (g1_groupValid_of_noninfinity hp hz)).mp hp.2

theorem g1_toPoint_eq_of_matches {p q : G1}
    (hinf : p.isInfinity = q.isInfinity) (haff : p.toAffine = q.toAffine) :
    G1.toPoint p = G1.toPoint q := by
  by_cases hpz : p.isInfinity = true
  · rw [g1_toPoint_of_infinity hpz, g1_toPoint_of_infinity (hinf ▸ hpz)]
  · have hqz : q.isInfinity ≠ true := by simpa only [hinf] using hpz
    rw [← G1.toPoint_affine_normalize hpz, ← G1.toPoint_affine_normalize hqz, haff]

private theorem affine_toPoint_injective {x y x' y' : Fp}
    (h : y * y = x * x * x + Fp.ofNat 4)
    (h' : y' * y' = x' * x' * x' + Fp.ofNat 4)
    (heq : G1.toPoint ⟨x, y, Fp.one⟩ = G1.toPoint ⟨x', y', Fp.one⟩) :
    (x, y) = (x', y') := by
  change Point.toAffine G1.curve ![x, y, 1] =
    Point.toAffine G1.curve ![x', y', 1] at heq
  rw [Point.toAffine_some (g1_valid_affine h),
    Point.toAffine_some (g1_valid_affine h')] at heq
  obtain ⟨hx, hy⟩ := WeierstrassCurve.Affine.Point.some.inj heq
  exact Prod.ext hx hy

theorem g1_toPoint_eq_iff {p q : G1} (hp : G1Valid p) (hq : G1Valid q) :
    G1.toPoint p = G1.toPoint q ↔
      p.isInfinity = q.isInfinity ∧ p.toAffine = q.toAffine := by
  refine ⟨?_, fun h => g1_toPoint_eq_of_matches h.1 h.2⟩
  intro heq
  have hinf : p.isInfinity = q.isInfinity := by
    apply Bool.eq_iff_iff.mpr
    rw [← g1Valid_toPoint_zero_iff hp, ← g1Valid_toPoint_zero_iff hq, heq]
  refine ⟨hinf, ?_⟩
  by_cases hpz : p.isInfinity = true
  · have hqz : q.isInfinity = true := hinf ▸ hpz
    change q.z.isZero = true at hqz
    simp only [G1.toAffine, show p.z.isZero = true from hpz, hqz, if_true]
  · have hqz : q.isInfinity ≠ true := by simpa only [hinf] using hpz
    apply affine_toPoint_injective (hp.1.resolve_left hpz) (hq.1.resolve_left hqz)
    rwa [G1.toPoint_affine_normalize hpz, G1.toPoint_affine_normalize hqz]

theorem g1Valid_neg {p : G1} (hp : G1Valid p) : G1Valid (G1.neg p) := by
  by_cases hz : p.isInfinity = true
  · exact g1Valid_of_infinity hz
  · have hpv := g1_groupValid_of_noninfinity hp hz
    apply g1Valid_of_groupValid (G1.valid_neg hpv)
    rw [G1.toPoint_neg hpv, neg_nsmul, g1Valid_subgroup hp, neg_zero]

theorem g1_toPoint_neg {p : G1} (hp : G1Valid p) :
    G1.toPoint (G1.neg p) = -G1.toPoint p := by
  by_cases hz : p.isInfinity = true
  · rw [g1_toPoint_of_infinity (p := G1.neg p) hz, g1_toPoint_of_infinity hz, neg_zero]
  · exact G1.toPoint_neg (g1_groupValid_of_noninfinity hp hz)

theorem g1_add_of_infinity_left {p q : G1} (hp : p.isInfinity = true) :
    G1.add p q = q := by
  simp only [G1.add, show p.z.isZero = true from hp, if_true]

theorem g1_add_of_infinity_right {p q : G1} (hp : p.isInfinity ≠ true)
    (hq : q.isInfinity = true) : G1.add p q = p := by
  simp only [G1.add, show p.z.isZero ≠ true from hp, Bool.false_eq_true, if_false,
    show q.z.isZero = true from hq, if_true]

theorem g1Valid_add {p q : G1} (hp : G1Valid p) (hq : G1Valid q) :
    G1Valid (G1.add p q) := by
  by_cases hpz : p.isInfinity = true
  · rw [g1_add_of_infinity_left hpz]
    exact hq
  by_cases hqz : q.isInfinity = true
  · rw [g1_add_of_infinity_right hpz hqz]
    exact hp
  have hpv := g1_groupValid_of_noninfinity hp hpz
  have hqv := g1_groupValid_of_noninfinity hq hqz
  apply g1Valid_of_groupValid (G1.valid_add hpv hqv)
  rw [G1.toPoint_add hpv hqv, nsmul_add, g1Valid_subgroup hp, g1Valid_subgroup hq,
    zero_add]

theorem g1_toPoint_add {p q : G1} (hp : G1Valid p) (hq : G1Valid q) :
    G1.toPoint (G1.add p q) = G1.toPoint p + G1.toPoint q := by
  by_cases hpz : p.isInfinity = true
  · rw [g1_add_of_infinity_left hpz, g1_toPoint_of_infinity hpz, zero_add]
  by_cases hqz : q.isInfinity = true
  · rw [g1_add_of_infinity_right hpz hqz, g1_toPoint_of_infinity hqz, add_zero]
  exact G1.toPoint_add (g1_groupValid_of_noninfinity hp hpz)
    (g1_groupValid_of_noninfinity hq hqz)

theorem g1_double_of_infinity {p : G1} (hp : p.isInfinity = true) :
    G1.double p = p := by
  simp only [G1.double, show p.z.isZero = true from hp, if_true]

theorem g1Valid_double {p : G1} (hp : G1Valid p) : G1Valid (G1.double p) := by
  by_cases hz : p.isInfinity = true
  · rwa [g1_double_of_infinity hz]
  have hpv := g1_groupValid_of_noninfinity hp hz
  apply g1Valid_of_groupValid (G1.valid_double hpv)
  rw [G1.toPoint_double hpv, nsmul_add, g1Valid_subgroup hp, zero_add]

theorem g1_toPoint_double {p : G1} (hp : G1Valid p) :
    G1.toPoint (G1.double p) = G1.toPoint p + G1.toPoint p := by
  by_cases hz : p.isInfinity = true
  · rw [g1_double_of_infinity hz, g1_toPoint_of_infinity hz, zero_add]
  exact G1.toPoint_double (g1_groupValid_of_noninfinity hp hz)

theorem g1_mulNat_of_infinity {p : G1} (hp : p.isInfinity = true) (k : Nat) :
    G1.mulNat p k = G1.zero := by
  induction k using Nat.strong_induction_on with
  | h k ih =>
    rw [G1.mulNat_def]
    by_cases hk : k = 0
    · simp only [hk, if_true]
    · simp only [hk, if_false]
      rw [g1_double_of_infinity hp, ih (k / 2) (by omega)]
      split
      · exact g1_add_of_infinity_left hp
      · rfl

theorem g1Valid_mulNat {p : G1} (hp : G1Valid p) (k : Nat) :
    G1Valid (G1.mulNat p k) := by
  by_cases hz : p.isInfinity = true
  · rw [g1_mulNat_of_infinity hz]
    exact g1Valid_zero
  have hpv := g1_groupValid_of_noninfinity hp hz
  apply g1Valid_of_groupValid (G1.valid_mulNat hpv k)
  rw [G1.toPoint_mulNat hpv, smul_comm Fr.modulus k, g1Valid_subgroup hp, nsmul_zero]

theorem g1_toPoint_mulNat {p : G1} (hp : G1Valid p) (k : Nat) :
    G1.toPoint (G1.mulNat p k) = k • G1.toPoint p := by
  by_cases hz : p.isInfinity = true
  · rw [g1_mulNat_of_infinity hz, G1.toPoint_zero, g1_toPoint_of_infinity hz, nsmul_zero]
  exact G1.toPoint_mulNat (g1_groupValid_of_noninfinity hp hz) k

theorem g1Valid_mul {p : G1} (hp : G1Valid p) (s : Fr) : G1Valid (G1.mul p s) :=
  g1Valid_mulNat hp s.val

theorem g1_toPoint_mul {p : G1} (hp : G1Valid p) (s : Fr) :
    G1.toPoint (G1.mul p s) = s.val • G1.toPoint p := g1_toPoint_mulNat hp s.val

theorem g1_neg_matches {p q : G1} (hp : G1Valid p) (hq : G1Valid q)
    (hinf : p.isInfinity = q.isInfinity) (haff : p.toAffine = q.toAffine) :
    (G1.neg p).isInfinity = (G1.neg q).isInfinity ∧
      (G1.neg p).toAffine = (G1.neg q).toAffine := by
  apply (g1_toPoint_eq_iff (g1Valid_neg hp) (g1Valid_neg hq)).mp
  rw [g1_toPoint_neg hp, g1_toPoint_neg hq, g1_toPoint_eq_of_matches hinf haff]

theorem g1_add_matches {p q p' q' : G1}
    (hp : G1Valid p) (hq : G1Valid q) (hp' : G1Valid p') (hq' : G1Valid q')
    (hpinf : p.isInfinity = p'.isInfinity) (hpaff : p.toAffine = p'.toAffine)
    (hqinf : q.isInfinity = q'.isInfinity) (hqaff : q.toAffine = q'.toAffine) :
    (G1.add p q).isInfinity = (G1.add p' q').isInfinity ∧
      (G1.add p q).toAffine = (G1.add p' q').toAffine := by
  apply (g1_toPoint_eq_iff (g1Valid_add hp hq) (g1Valid_add hp' hq')).mp
  rw [g1_toPoint_add hp hq, g1_toPoint_add hp' hq',
    g1_toPoint_eq_of_matches hpinf hpaff, g1_toPoint_eq_of_matches hqinf hqaff]

end LeanBlsSimd.Kzg
