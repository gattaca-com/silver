import LeanBlsSimd.Spec.G2Group

/-! An off-curve point shows that the subgroup implications require validity. -/

namespace LeanBlsSimd

open EthLib.Cryptography.Bls WeierstrassCurve Jacobian

/-! ## Validity cannot be dropped

(0, 0, 1) is off E′, so `toPoint` sends it to 0, and both premises below hold. Its double has
Z = 2·Y·Z = 0, so [r]P comes out as P itself, and the spec's test rejects it. -/

def offCurve : G2 := ⟨Fp2.zero, Fp2.zero, Fp2.one⟩

theorem toPoint_offCurve : G2.toPoint offCurve = 0 := by
  rw [G2.toPoint_eq_toAffine]
  simp only [offCurve, EthLib.Cryptography.Bls.G2.rep, comp_fin3,
    Fp2.toField_zero, Fp2.toField_one]
  refine Point.toAffine_of_singular fun h => ?_
  have h' := (E'.nonsingular_iff _ _).mp ((nonsingular_some _ _).mp h)
  revert h'
  decide +kernel

theorem mulNat_of_isZero (k : ℕ) {Q : G2} (hQ : Q.z.isZero = true) :
    (G2.mulNat Q k).z.isZero = true := by
  induction k using Nat.strongRecOn generalizing Q with
  | _ k ih =>
    rw [G2.mulNat_def]
    have hd : G2.double Q = Q := by rw [G2.double, ite_eq_left hQ]
    split
    · rfl
    · rw [hd]
      split
      · rw [G2.add, ite_eq_left hQ]
        exact ih (k / 2) (by omega) hQ
      · exact ih (k / 2) (by omega) hQ

theorem inSubgroup_offCurve : G2.inSubgroup offCurve = false := by
  have hd : (G2.double offCurve).z.isZero = true := by decide +kernel
  have hr : Fr.modulus ≠ 0 := by decide +kernel
  have hodd : Fr.modulus % 2 = 1 := by decide +kernel
  have hz : ¬offCurve.z.isZero = true := by decide +kernel
  have hm : G2.mulNat offCurve Fr.modulus = offCurve := by
    rw [G2.mulNat_def, ite_eq_right hr, ite_eq_left hodd, G2.add, ite_eq_right hz,
      ite_eq_left (mulNat_of_isZero _ hd)]
  rw [G2.inSubgroup, G2.isInfinity, ite_eq_right hz, G2.isInfinity, hm]
  decide +kernel

example : ¬∀ P : G2, Fr.modulus • G2.toPoint P = 0 → G2.inSubgroup P = true := fun h => by
  have := h offCurve (by rw [toPoint_offCurve, nsmul_zero])
  rw [inSubgroup_offCurve] at this
  exact Bool.false_ne_true this

example : ¬∀ P : G2, psi (G2.toPoint P) = z • G2.toPoint P → G2.inSubgroup P = true := fun h => by
  have := h offCurve (by rw [toPoint_offCurve, map_zero, zsmul_zero])
  rw [inSubgroup_offCurve] at this
  exact Bool.false_ne_true this

end LeanBlsSimd
