import LeanBlsSimd.Spec.Scott
import EthLib.Cryptography.Bls.Compress
import EthLib.Cryptography.Proofs.Bls.G2Group

/-! The total point map sends singular triples to zero, so subgroup implications need validity. -/

namespace LeanBlsSimd.G2

open EthLib.Cryptography.Bls WeierstrassCurve Jacobian

private theorem curve_map :
    EthLib.Cryptography.Bls.G2.curve.toAffine.map Fp2.toField.toRingHom = E' := rfl

noncomputable def pointEquiv :
    EthLib.Cryptography.Bls.G2.curve.toAffine.Point ≃+ E'.Point := by
  letI : Algebra Fp2 Fp2Field := Fp2.toField.toRingHom.toAlgebra
  let f := Affine.Point.map (W' := EthLib.Cryptography.Bls.G2.curve.toAffine)
    (Algebra.ofId Fp2 Fp2Field)
  refine AddEquiv.ofBijective f ⟨Affine.Point.map_injective _, ?_⟩
  intro Q
  cases Q with
  | zero => exact ⟨0, map_zero f⟩
  | some x y h =>
    have hs : EthLib.Cryptography.Bls.G2.curve.toAffine.Nonsingular
        (Fp2.toField.symm x) (Fp2.toField.symm y) := by
      apply (Affine.map_nonsingular _ (f := Fp2.toField.toRingHom)
        Fp2.toField.injective _ _).mp
      rw [curve_map]
      change E'.Nonsingular (Fp2.toField (Fp2.toField.symm x))
        (Fp2.toField (Fp2.toField.symm y))
      simpa only [RingEquiv.apply_symm_apply] using h
    refine ⟨.some _ _ hs, ?_⟩
    change Affine.Point.some (Fp2.toField (Fp2.toField.symm x))
      (Fp2.toField (Fp2.toField.symm y)) _ = .some x y h
    simp only [RingEquiv.apply_symm_apply]

private theorem valid_iff_nonsingular (P : G2) :
    EthLib.Cryptography.Bls.G2.Valid P ↔
      E'.toJacobian.Nonsingular (Fp2.toField ∘ EthLib.Cryptography.Bls.G2.rep P) := by
  rw [← curve_map]
  exact (Jacobian.map_nonsingular _ Fp2.toField.injective _).symm

noncomputable def toPoint (P : G2) : E'.Point :=
  pointEquiv (EthLib.Cryptography.Bls.G2.toPoint P)

theorem toPoint_eq_toAffine (P : G2) :
    toPoint P = Point.toAffine E'.toJacobian
      (Fp2.toField ∘ EthLib.Cryptography.Bls.G2.rep P) := by
  by_cases hv : EthLib.Cryptography.Bls.G2.Valid P
  · by_cases hz : P.z = 0
    · rw [toPoint, EthLib.Cryptography.Bls.G2.toPoint,
        Point.toAffine_of_Z_eq_zero hz, map_zero,
        Point.toAffine_of_Z_eq_zero (P := Fp2.toField ∘ EthLib.Cryptography.Bls.G2.rep P)
          (by simpa only [Function.comp_apply, EthLib.Cryptography.Bls.G2.rep_z, hz]
            using map_zero Fp2.toField)]
    · have hzm : (Fp2.toField ∘ EthLib.Cryptography.Bls.G2.rep P) 2 ≠ 0 :=
        (map_ne_zero_iff _ Fp2.toField.injective).mpr hz
      rw [toPoint, EthLib.Cryptography.Bls.G2.toPoint,
        Point.toAffine_of_Z_ne_zero hv hz,
        Point.toAffine_of_Z_ne_zero ((valid_iff_nonsingular P).mp hv) hzm]
      change Affine.Point.some (Fp2.toField (P.x / P.z ^ 2))
        (Fp2.toField (P.y / P.z ^ 3)) _ = Affine.Point.some
          (Fp2.toField P.x / Fp2.toField P.z ^ 2) (Fp2.toField P.y / Fp2.toField P.z ^ 3) _
      simp only [map_div₀, map_pow]
  · rw [toPoint, EthLib.Cryptography.Bls.G2.toPoint,
      Point.toAffine_of_singular hv, map_zero,
      Point.toAffine_of_singular (fun h => hv ((valid_iff_nonsingular P).mpr h))]

private theorem toPoint_eq_zero_iff {P : G2} (h : EthLib.Cryptography.Bls.G2.Valid P) :
    toPoint P = 0 ↔ P.z.isZero = true := by
  rw [toPoint, ← map_zero pointEquiv, pointEquiv.injective.eq_iff,
    EthLib.Cryptography.Bls.G2.isZero_iff]
  refine ⟨fun h0 => ?_, fun hz => Point.toAffine_of_Z_eq_zero
    (P := EthLib.Cryptography.Bls.G2.rep P) hz⟩
  by_contra hz
  rw [EthLib.Cryptography.Bls.G2.toPoint, Point.toAffine_of_Z_ne_zero h hz] at h0
  exact Affine.Point.some_ne_zero _ h0

theorem inSubgroup_iff {P : G2} (h : EthLib.Cryptography.Bls.G2.Valid P) :
    G2.inSubgroup P = true ↔ Fr.modulus • toPoint P = 0 := by
  rw [G2.inSubgroup, G2.isInfinity, G2.isInfinity]
  by_cases hz : P.z.isZero = true
  · rw [ite_eq_left hz, (toPoint_eq_zero_iff h).mpr hz, nsmul_zero]
    exact iff_of_true rfl rfl
  · have hm : toPoint (G2.mulNat P Fr.modulus) = Fr.modulus • toPoint P := by
      simp only [toPoint, EthLib.Cryptography.Bls.G2.toPoint_mulNat h, map_nsmul]
    rw [ite_eq_right hz, ← hm,
      toPoint_eq_zero_iff (EthLib.Cryptography.Bls.G2.valid_mulNat h _)]

theorem inSubgroup_of_psi {P : G2} (h : EthLib.Cryptography.Bls.G2.Valid P)
    (hψ : psi (toPoint P) = z • toPoint P) : G2.inSubgroup P = true :=
  (inSubgroup_iff h).mpr (scott_sound _ hψ)

theorem valid_mk_one {x y : Fp2} (h : E'.Nonsingular (Fp2.toField x) (Fp2.toField y)) :
    EthLib.Cryptography.Bls.G2.Valid ⟨x, y, Fp2.one⟩ := by
  apply (valid_iff_nonsingular _).mpr
  simpa only [EthLib.Cryptography.Bls.G2.rep, comp_fin3, Fp2.toField_one] using
    (nonsingular_some _ _).mpr h

theorem toPoint_mk_one {x y : Fp2} (h : E'.Nonsingular (Fp2.toField x) (Fp2.toField y)) :
    toPoint ⟨x, y, Fp2.one⟩ = .some _ _ h := by
  rw [toPoint_eq_toAffine]
  simp only [EthLib.Cryptography.Bls.G2.rep, comp_fin3, Fp2.toField_one]
  exact Point.toAffine_some ((nonsingular_some _ _).mpr h)

end LeanBlsSimd.G2
