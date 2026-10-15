import LeanBlsSimd.Spec.Generator
import EthCryptographySpecs.Proofs.Bls.FrZMod
import Mathlib.GroupTheory.Index
import Mathlib.GroupTheory.QuotientGroup.Basic

/-!
# Scott completeness from a point count

The generator has exact order r. If E′ has r · h points with h coprime to r, the quotient by
the generator's cyclic subgroup has order h and contains no nonzero r-torsion. This puts every
r-torsion point in that cyclic subgroup, where `psi_generator` proves the Scott identity.

It suffices that r² does not divide the point count. The numerical Hasse interval lies strictly
between consecutive multiples of r², so `scottComplete_of_hasse_bounds` reduces completeness to
the two Hasse bounds for E′. `Spec/CubicHasse.lean` supplies those bounds and concludes
`ScottComplete`; the reductions here retain their explicit hypotheses.
-/

namespace LeanBlsSimd

open EthCryptographySpecs.Bls

theorem generator_ne_zero : G2.toPoint G2.generator ≠ 0 := by
  rw [toPoint_generator]
  exact WeierstrassCurve.Affine.Point.some_ne_zero _

theorem addOrderOf_generator : addOrderOf (G2.toPoint G2.generator) = Fr.modulus :=
  addOrderOf_eq_prime generator_torsion generator_ne_zero

/-- A point count with a coprime cofactor makes G generate all rational r-torsion. -/
theorem torsion_eq_zsmul_generator_of_card (h : ℕ)
    (hcard : Nat.card E'.Point = Fr.modulus * h)
    (hcoprime : h.Coprime Fr.modulus)
    (P : E'.Point) (hP : Fr.modulus • P = 0) :
    ∃ k : ℤ, P = k • G2.toPoint G2.generator := by
  let H := AddSubgroup.zmultiples (G2.toPoint G2.generator)
  have hH : Nat.card H = Fr.modulus := by
    rw [Nat.card_zmultiples, addOrderOf_generator]
  have hi : H.index = h := by
    apply Nat.eq_of_mul_eq_mul_left Fr.modulus_pos
    rw [← hcard, ← hH, H.card_mul_index]
  have hc : (Nat.card (E'.Point ⧸ H)).Coprime Fr.modulus := by
    rw [← H.index_eq_card, hi]
    exact hcoprime
  have hq : (QuotientAddGroup.mk' H) P = 0 := by
    apply hc.nsmul_right_bijective.injective
    dsimp only
    rw [← map_nsmul, hP, map_zero, smul_zero]
  have hm : P ∈ H := (QuotientAddGroup.eq_zero_iff P).mp hq
  obtain ⟨k, hk⟩ := AddSubgroup.mem_zmultiples_iff.mp hm
  exact ⟨k, hk.symm⟩

/-- Conditional on a point count; the curve's cardinality is not established here. -/
theorem scottComplete_of_card (h : ℕ)
    (hcard : Nat.card E'.Point = Fr.modulus * h)
    (hcoprime : h.Coprime Fr.modulus) : ScottComplete :=
  scottComplete_of_cyclic (torsion_eq_zsmul_generator_of_card h hcard hcoprime)

/-- The generator supplies a factor r in the point count; excluding a second factor suffices. -/
theorem scottComplete_of_card_not_dvd
    (h : ¬ Fr.modulus ^ 2 ∣ Nat.card E'.Point) : ScottComplete := by
  have hd : Fr.modulus ∣ Nat.card E'.Point := by
    rw [← addOrderOf_generator]
    exact addOrderOf_dvd_natCard _
  obtain ⟨c, hc⟩ := hd
  apply scottComplete_of_card c hc
  apply Nat.Coprime.symm
  apply Fr.modulus_prime.coprime_iff_not_dvd.mpr
  intro hrc
  apply h
  obtain ⟨d, hd⟩ := hrc
  rw [hc, hd, pow_two, ← Nat.mul_assoc]
  exact dvd_mul_right _ _

/-- Every integer in the Hasse interval for Fp² avoids divisibility by r². -/
theorem r_sq_not_dvd_of_hasse_bounds (n : ℕ)
    (hlo : (Fp.modulus - 1) ^ 2 ≤ n)
    (hhi : n ≤ (Fp.modulus + 1) ^ 2) : ¬ Fr.modulus ^ 2 ∣ n := by
  intro hd
  obtain ⟨k, hk⟩ := hd
  let q := (Fp.modulus - 1) ^ 2 / Fr.modulus ^ 2
  have hlow : Fr.modulus ^ 2 * q < (Fp.modulus - 1) ^ 2 := by decide +kernel
  have hhigh : (Fp.modulus + 1) ^ 2 < Fr.modulus ^ 2 * (q + 1) := by decide +kernel
  have hqk : q < k := by
    apply Nat.lt_of_mul_lt_mul_left (a := Fr.modulus ^ 2)
    rw [← hk]
    exact lt_of_lt_of_le hlow hlo
  have hkq : k < q + 1 := by
    apply Nat.lt_of_mul_lt_mul_left (a := Fr.modulus ^ 2)
    rw [← hk]
    exact lt_of_le_of_lt hhi hhigh
  omega

/-- Reduce completeness to the Hasse bounds supplied by `Spec/CubicHasse.lean`. -/
theorem scottComplete_of_hasse_bounds
    (hlo : (Fp.modulus - 1) ^ 2 ≤ Nat.card E'.Point)
    (hhi : Nat.card E'.Point ≤ (Fp.modulus + 1) ^ 2) : ScottComplete :=
  scottComplete_of_card_not_dvd (r_sq_not_dvd_of_hasse_bounds _ hlo hhi)

end LeanBlsSimd
