import LeanBlsSimd.Model.DecompressG1
import LeanBlsSimd.Proofs.DecompressG2
import EthLib.Cryptography.Proofs.Bls.G1Order
import EthLib.Cryptography.Kzg.Core
import LeanBlsSimd.Spec.PointCount
import LeanBlsSimd.Spec.ScottCardinality

namespace LeanBlsSimd.G1Spec

open EthLib.Cryptography Bls
open WeierstrassCurve
open DecompressG1

abbrev E := G1.curve.toAffine

open Affine

@[simp] theorem a₁_eq : E.a₁ = 0 := rfl
@[simp] theorem a₂_eq : E.a₂ = 0 := rfl
@[simp] theorem a₃_eq : E.a₃ = 0 := rfl
@[simp] theorem a₄_eq : E.a₄ = 0 := rfl
@[simp] theorem a₆_eq : E.a₆ = (4 : ZMod Fp.modulus) := rfl

theorem Δ_eq : E.Δ = -432 * (4 : ZMod Fp.modulus) ^ 2 := by
  simp only [Δ, b₂, b₄, b₆, b₈, a₁_eq, a₂_eq, a₃_eq, a₄_eq, a₆_eq]
  ring

theorem Δ_ne_zero : E.Δ ≠ 0 := by
  rw [Δ_eq]
  decide +kernel

instance instIsElliptic : E.IsElliptic := ⟨isUnit_iff_ne_zero.mpr Δ_ne_zero⟩

theorem equation_iff (x y : ZMod Fp.modulus) : E.Equation x y ↔ y ^ 2 = x ^ 3 + (4 : ZMod Fp.modulus) := by
  rw [Affine.equation_iff]
  simp

theorem nonsingular_iff (x y : ZMod Fp.modulus) : E.Nonsingular x y ↔ y ^ 2 = x ^ 3 + (4 : ZMod Fp.modulus) := by
  rw [← Affine.equation_iff_nonsingular_of_Δ_ne_zero Δ_ne_zero, equation_iff]

@[simp] theorem negY_eq (x y : ZMod Fp.modulus) : E.negY x y = -y := by
  simp

private theorem beta_ne_zero : (beta : ZMod Fp.modulus) ≠ 0 := by decide +kernel

private theorem beta_polynomial : (beta : ZMod Fp.modulus) ^ 2 + beta + 1 = 0 := by
  have h : ((beta : ZMod Fp.modulus) - 1) * ((beta : ZMod Fp.modulus) ^ 2 + beta + 1) = 0 := by
    linear_combination beta_cube
  exact (mul_eq_zero.mp h).resolve_left (sub_ne_zero.mpr beta_ne_one)

theorem nonsingular_sigma {x y : ZMod Fp.modulus} (h : E.Nonsingular x y) :
    E.Nonsingular (beta * x) y := by
  rw [nonsingular_iff] at h ⊢
  linear_combination h - x ^ 3 * beta_cube

def sigma : E.Point → E.Point
  | 0 => 0
  | .some x y h => .some (beta * x) y (nonsingular_sigma h)

private theorem slope_sigma (x₁ x₂ y₁ y₂ : ZMod Fp.modulus) :
    E.slope (beta * x₁) (beta * x₂) y₁ y₂ =
      (beta : ZMod Fp.modulus) ^ 2 * E.slope x₁ x₂ y₁ y₂ := by
  have hx : (beta : ZMod Fp.modulus) * x₁ = beta * x₂ ↔ x₁ = x₂ :=
    mul_right_inj' beta_ne_zero
  simp only [slope, negY_eq, a₁_eq, a₂_eq, a₄_eq, hx, mul_zero, zero_mul, add_zero, sub_zero]
  split_ifs
  · simp
  · ring
  · rename_i hne
    rw [show (beta : ZMod Fp.modulus) * x₁ - beta * x₂ = beta * (x₁ - x₂) by ring]
    field_simp [sub_ne_zero.mpr hne, beta_ne_zero]
    linear_combination -(y₁ - y₂) * beta_cube

private theorem addX_sigma (x₁ x₂ l : ZMod Fp.modulus) :
    E.addX (beta * x₁) (beta * x₂) (beta ^ 2 * l) = beta * E.addX x₁ x₂ l := by
  simp only [addX, a₁_eq, a₂_eq, zero_mul, add_zero, sub_zero]
  linear_combination (beta : ZMod Fp.modulus) * l ^ 2 * beta_cube

private theorem addY_sigma (x₁ x₂ y₁ l : ZMod Fp.modulus) :
    E.addY (beta * x₁) (beta * x₂) y₁ (beta ^ 2 * l) = E.addY x₁ x₂ y₁ l := by
  rw [addY, negAddY, addX_sigma, addY, negAddY, negY_eq, negY_eq]
  linear_combination (-l * (E.addX x₁ x₂ l - x₁)) * beta_cube

theorem sigma_add (P Q : E.Point) : sigma (P + Q) = sigma P + sigma Q := by
  rcases P with _ | ⟨x₁, y₁, h₁⟩ <;> rcases Q with _ | ⟨x₂, y₂, h₂⟩
  any_goals rfl
  have hx : (beta : ZMod Fp.modulus) * x₁ = beta * x₂ ↔ x₁ = x₂ :=
    mul_right_inj' beta_ne_zero
  by_cases hxy : x₁ = x₂ ∧ y₁ = E.negY x₂ y₂
  · rw [Point.add_of_Y_eq hxy.left hxy.right]
    simp only [sigma]
    rw [Point.add_of_Y_eq (hx.mpr hxy.left) (by simpa using hxy.right)]
  · rw [Point.add_some hxy]
    simp only [sigma]
    rw [Point.add_some (fun h => hxy ⟨hx.mp h.1, by simpa using h.2⟩)]
    simp only [slope_sigma, addX_sigma, addY_sigma]

private def sigmaHom : E.Point →+ E.Point where
  toFun := sigma
  map_zero' := rfl
  map_add' := sigma_add

theorem sigma_polynomial (P : E.Point) : P + sigma P + sigma (sigma P) = 0 := by
  rcases P with _ | ⟨x, y, h⟩
  · rfl
  by_cases hx : x = 0
  · subst hx
    have hφ : sigma (.some 0 y h) = .some 0 y h := by
      simp only [sigma, mul_zero]
    have hy : y ≠ E.negY 0 y := by
      rw [negY_eq]
      intro hy
      have hb : (4 : ZMod Fp.modulus) = 0 := by
        have h2 : (2 : ZMod Fp.modulus) * y = 0 := by linear_combination hy
        have hy0 : y = 0 := (mul_eq_zero.mp h2).resolve_left (by decide +kernel)
        rw [nonsingular_iff, hy0] at h
        linear_combination -h
      exact absurd hb (by decide +kernel)
    have h2P : Point.some 0 y h + Point.some 0 y h = -Point.some 0 y h := by
      rw [Point.add_self_of_Y_ne hy, Point.neg_some, Point.some.injEq]
      simp [slope_of_Y_ne rfl hy]
    rw [hφ, hφ, h2P, neg_add_cancel]
  · have hxζ : x ≠ beta * x := by
      intro hxζ
      apply hx
      have h1 : ((beta : ZMod Fp.modulus) - 1) * x = 0 := by linear_combination -hxζ
      exact (mul_eq_zero.mp h1).resolve_left (sub_ne_zero.mpr beta_ne_one)
    have hs : Point.some x y h + sigma (.some x y h) = -sigma (sigma (.some x y h)) := by
      simp only [sigma]
      rw [Point.add_of_X_ne hxζ, Point.neg_some, Point.some.injEq]
      simp only [slope_of_X_ne hxζ, sub_self, zero_div, addX, addY, negAddY, negY_eq,
        a₁_eq, a₂_eq, zero_mul, add_zero, sub_zero, zero_add]
      constructor
      · linear_combination (-x) * beta_polynomial
      · trivial
    rw [hs, neg_add_cancel]

theorem scott_sound (P : E.Point) (h : sigma (sigma P) = (-(z ^ 2)) • P) :
    Fr.modulus • P = 0 := by
  have hs3 : sigma (sigma (sigma P)) = P := by
    rcases P with _ | ⟨x, y, h⟩
    · rfl
    · simp only [sigma, Point.some.injEq]
      constructor
      · linear_combination x * beta_cube
      · trivial
  have hs4 : sigma (sigma (sigma (sigma P))) = sigma P := by rw [hs3]
  have h4 : sigma P = (z ^ 4) • P := by
    rw [← hs4]
    change sigmaHom (sigmaHom (sigma (sigma P))) = _
    rw [h, map_zsmul, map_zsmul]
    change (-(z ^ 2)) • sigma (sigma P) = _
    rw [h, smul_smul]
    congr 1
  have hp := sigma_polynomial P
  rw [h, h4] at hp
  rw [← natCast_zsmul, r_eq]
  calc (z ^ 4 - z ^ 2 + 1) • P = P + z ^ 4 • P + (-(z ^ 2)) • P := by module
       _ = 0 := hp

private def generatorMulAux : Nat → G1 → Nat → G1
  | 0, _, _ => G1.zero
  | fuel + 1, p, k =>
    if k = 0 then G1.zero
    else
      let half := generatorMulAux fuel (G1.double p) (k / 2)
      if k % 2 = 1 then G1.add p half else half

private theorem generatorMulAux_eq (fuel : Nat) (p : G1) (k : Nat)
    (hk : k < 2 ^ fuel) : generatorMulAux fuel p k = G1.mulNat p k := by
  induction fuel generalizing p k with
  | zero =>
    have : k = 0 := by simpa using hk
    subst this
    rw [generatorMulAux, G1.mulNat_def]
    simp
  | succ fuel ih =>
    rw [generatorMulAux, G1.mulNat_def]
    by_cases h0 : k = 0
    · simp [h0]
    · have h2 : k / 2 < 2 ^ fuel := by
        rw [Nat.pow_succ] at hk
        omega
      rw [if_neg h0, if_neg h0, ih (G1.double p) (k / 2) h2]

theorem nonsingular_generator :
    E.Nonsingular G1.generator.x G1.generator.y := by
  rw [nonsingular_iff]
  decide +kernel

theorem toPoint_generator :
    G1.toPoint G1.generator = .some _ _ nonsingular_generator := by
  rw [G1.toPoint, Jacobian.Point.toAffine_of_Z_ne_zero G1.valid_generator (by decide +kernel)]
  congr 1

-- Kernel evaluation of the 128-bit generator multiplication needs deeper recursion
-- and more heartbeats than symbolic curve proofs.
set_option maxRecDepth 10000 in
set_option maxHeartbeats 2000000 in
theorem sigma2_generator :
    sigma (sigma (G1.toPoint G1.generator)) = (-(z ^ 2)) • G1.toPoint G1.generator := by
  let k := (z ^ 2).toNat
  have hk : (k : ℤ) = z ^ 2 := Int.toNat_of_nonneg (sq_nonneg z)
  have heq : generatorMulAux 128 G1.generator k = G1.mulNat G1.generator k :=
    generatorMulAux_eq _ _ _ (by decide +kernel)
  let q := G1.neg (generatorMulAux 128 G1.generator k)
  have hq : G1.Valid q := by
    dsimp [q]
    rw [heq]
    exact G1.valid_neg (G1.valid_mulNat G1.valid_generator _)
  have htarget : G1.toPoint q = (-(z ^ 2)) • G1.toPoint G1.generator := by
    dsimp [q]
    rw [heq, G1.toPoint_neg (G1.valid_mulNat G1.valid_generator _),
      G1.toPoint_mulNat G1.valid_generator, ← natCast_zsmul, hk, neg_zsmul]
  rw [← htarget, toPoint_generator]
  simp only [sigma]
  rw [G1.toPoint, Jacobian.Point.toAffine_of_Z_ne_zero hq (by decide +kernel), Point.some.injEq]
  constructor
  · decide +kernel
  · change (G1.generator.y : ZMod Fp.modulus) = _
    decide +kernel

instance : Finite E.Point :=
  Finite.of_equiv (Option {xy : ZMod Fp.modulus × ZMod Fp.modulus // E.Nonsingular xy.1 xy.2})
    E.nonsingularPointEquiv.symm

theorem point_count_bound : Nat.card E.Point ≤ 2 * Fp.modulus + 1 := by
  classical
  have he : E.Point ≃ Option {xy : ZMod Fp.modulus × ZMod Fp.modulus // xy.2 ^ 2 = xy.1 ^ 3 + 4} :=
    E.nonsingularPointEquiv.trans
      (Equiv.subtypeEquivRight (fun xy : ZMod Fp.modulus × ZMod Fp.modulus => nonsingular_iff xy.1 xy.2)).optionCongr
  have hcard : (Nat.card E.Point : ℤ) = Fp.modulus +
      ∑ x : ZMod Fp.modulus, quadraticChar (ZMod Fp.modulus) (x ^ 3 + 4) + 1 := by
    rw [Nat.card_congr he, Nat.card_eq_fintype_card, Fintype.card_option, Nat.cast_add,
      Nat.cast_one, ← Nat.card_eq_fintype_card, card_solution_pairs]
    · simp [ZMod.card]
    · rw [ZMod.ringChar_zmod_n]
      decide
  have hsum : (∑ x : ZMod Fp.modulus, quadraticChar (ZMod Fp.modulus) (x ^ 3 + 4)) ≤
      (Fp.modulus : ℤ) := by
    calc
      _ ≤ ∑ _ : ZMod Fp.modulus, (1 : ℤ) := by
        apply Finset.sum_le_sum
        intro x hx
        by_cases hzero : x ^ 3 + 4 = 0
        · simp [hzero]
        · rcases quadraticChar_dichotomy hzero with h | h <;> simp [h]
      _ = _ := by simp [ZMod.card]
  zify
  omega

theorem point_count_lt_r_squared : Nat.card E.Point < Fr.modulus ^ 2 :=
  lt_of_le_of_lt point_count_bound (by decide +kernel)

theorem r_torsion_cyclic (P : E.Point) (h : Fr.modulus • P = 0) :
    ∃ k : ℕ, P = k • G1.toPoint G1.generator := by
  let H := AddSubgroup.zmultiples (G1.toPoint G1.generator)
  have hH : Nat.card H = Fr.modulus := by
    rw [Nat.card_zmultiples, G1.addOrderOf_toPoint_generator]
  have hcard : Nat.card E.Point = Fr.modulus * H.index := by
    rw [← hH, H.card_mul_index]
  have hcop : (Nat.card (E.Point ⧸ H)).Coprime Fr.modulus := by
    rw [← H.index_eq_card]
    apply Nat.Coprime.symm
    apply Fr.modulus_prime.coprime_iff_not_dvd.mpr
    intro hdiv
    have hdiv2 : Fr.modulus ^ 2 ∣ Nat.card E.Point := by
      obtain ⟨k, hk⟩ := hdiv
      rw [hcard, hk, pow_two, ← Nat.mul_assoc]
      exact dvd_mul_right _ _
    have := Nat.le_of_dvd (Nat.card_pos (α := E.Point)) hdiv2
    exact (Nat.not_le_of_lt point_count_lt_r_squared) this
  have hq : (QuotientAddGroup.mk' H) P = 0 := by
    apply hcop.nsmul_right_bijective.injective
    dsimp only
    rw [← map_nsmul, h, map_zero, smul_zero]
  have hm : P ∈ H := (QuotientAddGroup.eq_zero_iff P).mp hq
  obtain ⟨k, hk⟩ := AddSubgroup.mem_zmultiples_iff.mp hm
  refine ⟨(k % (Fr.modulus : ℤ)).toNat, ?_⟩
  rw [hk.symm, ← natCast_zsmul, Int.toNat_of_nonneg (Int.emod_nonneg _ (by decide)),
    ← G1.addOrderOf_toPoint_generator, mod_addOrderOf_zsmul]

theorem scott_complete (P : E.Point) (h : Fr.modulus • P = 0) :
    sigma (sigma P) = (-(z ^ 2)) • P := by
  obtain ⟨k, rfl⟩ := r_torsion_cyclic P h
  change sigmaHom (sigmaHom (k • G1.toPoint G1.generator)) = _
  rw [map_nsmul, map_nsmul]
  change k • sigma (sigma (G1.toPoint G1.generator)) = _
  rw [sigma2_generator, smul_comm]

private theorem toPoint_eq_zero_iff {P : G1} (h : G1.Valid P) :
    G1.toPoint P = 0 ↔ P.z.isZero = true := by
  rw [G1.isZero_iff]
  refine ⟨fun h0 => ?_, fun hz => Jacobian.Point.toAffine_of_Z_eq_zero (P := G1.rep P) hz⟩
  by_contra hz
  rw [G1.toPoint, Jacobian.Point.toAffine_of_Z_ne_zero h hz] at h0
  exact Affine.Point.some_ne_zero _ h0

theorem inSubgroup_iff (P : G1) (h : G1.Valid P) :
    G1.inSubgroup P = true ↔ Fr.modulus • G1.toPoint P = 0 := by
  rw [G1.inSubgroup, G1.isInfinity, G1.isInfinity]
  by_cases hz : P.z.isZero = true
  · rw [if_pos hz, (toPoint_eq_zero_iff h).mpr hz, nsmul_zero]
    exact iff_of_true rfl rfl
  · rw [if_neg hz, ← G1.toPoint_mulNat h, toPoint_eq_zero_iff (G1.valid_mulNat h _)]

end LeanBlsSimd.G1Spec
