import LeanBlsSimd.Spec.Generator
import EthLib.Cryptography.Proofs.Bls.FrZMod
import Mathlib.GroupTheory.Index
import Mathlib.GroupTheory.QuotientGroup.Basic

/-!
# Scott completeness from a point count

The generator has exact order r. If E′ has r · h points with h coprime to r, the quotient by
the generator's cyclic subgroup has order h and contains no nonzero r-torsion. This puts every
r-torsion point in that cyclic subgroup, where `psi_generator` proves the Scott identity.

`Spec/G2Cardinality.lean` supplies an exact count and concludes `ScottComplete`.
-/

namespace LeanBlsSimd

open EthLib.Cryptography.Bls

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

theorem scottComplete_of_card (h : ℕ)
    (hcard : Nat.card E'.Point = Fr.modulus * h)
    (hcoprime : h.Coprime Fr.modulus) : ScottComplete :=
  scottComplete_of_cyclic (torsion_eq_zsmul_generator_of_card h hcard hcoprime)

end LeanBlsSimd
