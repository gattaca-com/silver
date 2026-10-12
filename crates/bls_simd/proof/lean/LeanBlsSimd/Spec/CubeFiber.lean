import Mathlib.NumberTheory.MulChar.Lemmas
import Mathlib.RingTheory.RootsOfUnity.PrimitiveRoots
import Mathlib.GroupTheory.Perm.Cycle.Type
import Mathlib.RingTheory.IntegralDomain

/-! The number of cube roots of `t` in a finite field, through a character of order 3. -/

namespace LeanBlsSimd

open MulChar

variable {F : Type*} [Field F]

theorem mulChar_apply_eq_one_iff_exists_cube [Fintype F] {χ : MulChar F ℂ}
    (hχ : orderOf χ = 3) {t : F} (ht : t ≠ 0) : χ t = 1 ↔ ∃ a, a ^ 3 = t := by
  classical
  constructor
  · intro h1
    obtain ⟨g, hg⟩ := IsCyclic.exists_generator (α := Fˣ)
    have hpow : ∀ n : ℕ, equivToUnitHom χ g ^ n = 1 ↔ χ ^ n = 1 := by
      intro n
      rw [MulChar.eq_iff hg (χ ^ n) 1, pow_apply_coe, one_apply_coe, ← Units.val_eq_one,
        Units.val_pow_eq_pow_val, coe_equivToUnitHom]
    have hord : orderOf (equivToUnitHom χ g) = 3 := by
      rw [← hχ]
      exact orderOf_eq_orderOf_iff.mpr hpow
    obtain ⟨k, hk⟩ := Subgroup.mem_zpowers_iff.mp (hg (Units.mk0 t ht))
    have hk1 : equivToUnitHom χ g ^ k = 1 := by
      rw [← map_zpow, hk]
      ext
      rw [coe_equivToUnitHom, Units.val_mk0, h1, Units.val_one]
    have hd := orderOf_dvd_iff_zpow_eq_one.mpr hk1
    rw [hord] at hd
    obtain ⟨m, rfl⟩ : (3 : ℤ) ∣ k := by exact_mod_cast hd
    have hcube : (g ^ m) ^ 3 = Units.mk0 t ht := by
      rw [← hk, ← zpow_natCast, ← zpow_mul]
      congr 1
      push_cast
      ring
    refine ⟨((g ^ m : Fˣ) : F), ?_⟩
    rw [← Units.val_pow_eq_pow_val, hcube, Units.val_mk0]
  · rintro ⟨a, rfl⟩
    have ha : a ≠ 0 := fun h => ht (by rw [h, zero_pow three_ne_zero])
    have h3 : χ ^ 3 = 1 := by
      rw [← hχ]
      exact pow_orderOf_eq_one χ
    rw [map_pow, ← χ.pow_apply' three_ne_zero, h3, MulChar.one_apply ha.isUnit]

theorem exists_isPrimitiveRoot_three [Fintype F] (h : 3 ∣ Fintype.card F - 1) :
    ∃ ζ : F, IsPrimitiveRoot ζ 3 := by
  classical
  have : Fact (Nat.Prime 3) := ⟨Nat.prime_three⟩
  obtain ⟨g, hg⟩ := exists_prime_orderOf_dvd_card (G := Fˣ) 3 (by rwa [Fintype.card_units])
  exact ⟨(g : F), IsPrimitiveRoot.coe_units_iff.mpr (IsPrimitiveRoot.iff_orderOf.mpr hg)⟩

theorem card_cube_fiber_zero : Nat.card {x : F // x ^ 3 = 0} = 1 := by
  rw [Nat.card_eq_one_iff_exists]
  exact ⟨⟨0, zero_pow three_ne_zero⟩, fun y => Subtype.ext ((pow_eq_zero_iff three_ne_zero).mp y.2)⟩

theorem card_cube_fiber_of_cube {ζ : F} (hζ : IsPrimitiveRoot ζ 3) {t : F} (ht : t ≠ 0)
    (h : ∃ a, a ^ 3 = t) : Nat.card {x : F // x ^ 3 = t} = 3 := by
  classical
  have hcard := hζ.card_nthRoots t
  rw [if_pos h] at hcard
  have e : {x : F // x ^ 3 = t} ≃ {x : F // x ∈ (Polynomial.nthRoots 3 t).toFinset} :=
    Equiv.subtypeEquivRight fun x => by
      rw [Multiset.mem_toFinset, Polynomial.mem_nthRoots (by norm_num)]
  rw [Nat.card_congr e, Nat.card_eq_finsetCard, Multiset.toFinset_card_of_nodup
    (hζ.nthRoots_nodup ht), hcard]

theorem card_cube_fiber_of_not_cube {t : F} (h : ¬ ∃ a, a ^ 3 = t) :
    Nat.card {x : F // x ^ 3 = t} = 0 := by
  have : IsEmpty {x : F // x ^ 3 = t} := ⟨fun x => h ⟨x.1, x.2⟩⟩
  exact Nat.card_of_isEmpty

theorem card_cube_fiber [Fintype F] {χ : MulChar F ℂ} (hχ : orderOf χ = 3) (t : F) :
    (Nat.card {x : F // x ^ 3 = t} : ℂ) = 1 + χ t + χ⁻¹ t := by
  by_cases ht : t = 0
  · subst ht
    rw [card_cube_fiber_zero, MulChar.map_zero, MulChar.map_zero]
    norm_num
  obtain ⟨ζ, hζ⟩ := exists_isPrimitiveRoot_three (F := F) (by
    rw [← hχ]
    exact MulChar.orderOf_dvd_card_sub_one F χ)
  have h3 : χ ^ 3 = 1 := by
    rw [← hχ]
    exact pow_orderOf_eq_one χ
  have hz3 : χ t ^ 3 = 1 := by
    rw [← χ.pow_apply' three_ne_zero, h3, MulChar.one_apply (isUnit_iff_ne_zero.mpr ht)]
  have hz0 : χ t ≠ 0 := fun h => by
    rw [h, zero_pow three_ne_zero] at hz3
    exact zero_ne_one hz3
  rw [MulChar.inv_apply_eq_inv']
  by_cases hc : ∃ a, a ^ 3 = t
  · rw [card_cube_fiber_of_cube hζ ht hc, (mulChar_apply_eq_one_iff_exists_cube hχ ht).mpr hc]
    norm_num
  · rw [card_cube_fiber_of_not_cube hc, Nat.cast_zero]
    have hne : χ t ≠ 1 := fun h => hc ((mulChar_apply_eq_one_iff_exists_cube hχ ht).mp h)
    have key : (χ t - 1) * (1 + χ t + χ t ^ 2) = 0 := by linear_combination hz3
    have hq : 1 + χ t + χ t ^ 2 = 0 :=
      (mul_eq_zero.mp key).resolve_left (sub_ne_zero.mpr hne)
    have hinv : χ t * (χ t)⁻¹ = 1 := mul_inv_cancel₀ hz0
    linear_combination (1 + χ t) * hinv - (χ t)⁻¹ * hq

end LeanBlsSimd
