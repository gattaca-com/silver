import LeanBlsSimd.Kzg.RepresentationLemmas
import EthLib.Cryptography.Proofs.Bls.Compress

open EthLib.Cryptography Bls
open WeierstrassCurve.Jacobian
open scoped EthLib.Cryptography.Bls.Fp

namespace LeanBlsSimd.Kzg

private theorem affine_nonsingular {x y : ZMod Fp.modulus}
    (h : y * y = x * x * x + 4) : G1.curve.Nonsingular ![x, y, 1] := by
  rw [nonsingular_iff]
  constructor
  · rw [equation_iff]
    change (y : ZMod Fp.modulus) ^ 2 + 0 * x * y * 1 + 0 * y * 1 ^ 3 -
      (x ^ 3 + 0 * x ^ 2 * 1 ^ 2 + 0 * x * 1 ^ 4 + 4 * 1 ^ 6) = 0
    change (y : ZMod Fp.modulus) * y = x * x * x + 4 at h
    linear_combination h
  · apply Or.inr (Or.inr _)
    change (0 : ZMod Fp.modulus) * x * y + 3 * 0 * y * 1 ^ 2 -
      (2 * 0 * x ^ 2 * 1 + 4 * 0 * x * 1 ^ 3 + 6 * 4 * 1 ^ 5) ≠ 0
    norm_num
    decide

theorem g1_valid_affine {x y : Fp}
    (h : y * y = x * x * x + Fp.ofNat 4) :
    G1.Valid ⟨x, y, Fp.one⟩ := affine_nonsingular h

private theorem x_scaled (x z w : ZMod Fp.modulus) (hw : z * w = 1) :
    x * (w * w) * z ^ 2 = x * 1 ^ 2 := by
  linear_combination x * (z * w + 1) * hw

private theorem y_scaled (y z w : ZMod Fp.modulus) (hw : z * w = 1) :
    y * (w * w * w) * z ^ 3 = y * 1 ^ 3 := by
  linear_combination y * ((z * w) ^ 2 + z * w + 1) * hw

theorem g1_rep_affine_equiv {p : G1} (hz : p.isInfinity ≠ true) :
    G1.rep ⟨p.toAffine.1, p.toAffine.2, Fp.one⟩ ≈ G1.rep p := by
  change p.z.isZero ≠ true at hz
  have hzne : (p.z : ZMod Fp.modulus) ≠ 0 :=
    fun hh => hz (G1.isZero_iff.mpr hh)
  have hw : (p.z : ZMod Fp.modulus) * p.z.inverse = 1 := by
    rw [Fp.inverse_eq_inv]
    exact mul_inv_cancel₀ hzne
  refine equiv_of_X_eq_of_Y_eq one_ne_zero hzne ?_ ?_
  · simp only [G1.rep, G1.toAffine, if_neg hz, Matrix.cons_val_zero,
      Matrix.cons_val_two, Matrix.head_cons, Matrix.tail_cons]
    exact x_scaled p.x p.z p.z.inverse hw
  · simp only [G1.rep, G1.toAffine, if_neg hz, Matrix.cons_val_zero,
      Matrix.cons_val_one, Matrix.cons_val_two, Matrix.head_cons, Matrix.tail_cons]
    exact y_scaled p.y p.z p.z.inverse hw

theorem g1_valid_of_affine {p : G1} (hz : p.isInfinity ≠ true)
    (h : p.toAffine.2 * p.toAffine.2 =
      p.toAffine.1 * p.toAffine.1 * p.toAffine.1 + Fp.ofNat 4) :
    G1.Valid p :=
  (nonsingular_of_equiv (g1_rep_affine_equiv hz)).mp (g1_valid_affine h)

theorem g1_toPoint_eq_zero_iff {p : G1} (hp : G1.Valid p) :
    G1.toPoint p = 0 ↔ p.isInfinity = true := by
  by_cases hz : p.isInfinity = true
  · have he : G1.toPoint p = 0 :=
      Point.toAffine_of_Z_eq_zero (G1.isZero_iff.mp hz)
    simp only [he, hz]
  · have hzne : (p.z : ZMod Fp.modulus) ≠ 0 :=
      fun hh => hz (G1.isZero_iff.mpr hh)
    rw [G1.toPoint, Point.toAffine_of_Z_ne_zero hp hzne]
    exact iff_of_false (WeierstrassCurve.Affine.Point.some_ne_zero _) hz

theorem g1_inSubgroup_iff {p : G1} (hp : G1.Valid p) :
    p.inSubgroup = true ↔ Fr.modulus • G1.toPoint p = 0 := by
  unfold G1.inSubgroup
  by_cases hz : p.isInfinity = true
  · simp only [hz, if_true, (g1_toPoint_eq_zero_iff hp).mpr hz, nsmul_zero]
  · simp only [hz, Bool.false_eq_true, if_false]
    rw [← g1_toPoint_eq_zero_iff (G1.valid_mulNat hp Fr.modulus), G1.toPoint_mulNat hp]

theorem g1Valid_transport {p q : G1} (hinf : p.isInfinity = q.isInfinity)
    (haff : p.toAffine = q.toAffine) (hq : G1Valid q) : G1Valid p := by
  have hcurve : p.isInfinity = true ∨ p.toAffine.2 * p.toAffine.2 =
      p.toAffine.1 * p.toAffine.1 * p.toAffine.1 + Fp.ofNat 4 := by
    simpa only [hinf, haff] using hq.1
  refine ⟨hcurve, ?_⟩
  by_cases hpz : p.isInfinity = true
  · simp only [G1.inSubgroup, hpz, if_true]
  · have hqz : q.isInfinity ≠ true := by simpa only [hinf] using hpz
    have hpv := g1_valid_of_affine hpz (hcurve.resolve_left hpz)
    have hqv := g1_valid_of_affine hqz (hq.1.resolve_left hqz)
    have hpoint : G1.toPoint p = G1.toPoint q := by
      rw [← G1.toPoint_affine_normalize hpz, ← G1.toPoint_affine_normalize hqz, haff]
    apply (g1_inSubgroup_iff hpv).mpr
    rw [hpoint]
    exact (g1_inSubgroup_iff hqv).mp hq.2

theorem g1Valid_of_rep {p : silver_crypto_simd.blst.blst_p1} {q : G1}
    (hrep : G1Rep p q) (hq : G1Valid q) : G1Valid (g1ReadJacobian p) :=
  g1Valid_transport hrep.2.1 hrep.2.2 hq

private theorem affine_one_aux (x y one : ZMod Fp.modulus) (ho : one = 1) :
    (x * (one⁻¹ * one⁻¹), y * (one⁻¹ * one⁻¹ * one⁻¹)) = (x, y) := by
  subst one
  simp

theorem g1_toAffine_of_one (x y : Fp) :
    (G1.mk x y Fp.one).toAffine = (x, y) := by
  simp only [G1.toAffine, show Fp.one.isZero = false from rfl, Bool.false_eq_true,
    if_false, Fp.inverse_eq_inv]
  exact affine_one_aux x y Fp.one rfl

theorem g1ReadAffine_g1Affine {p : G1} (hp : G1Valid p) :
    g1ReadAffine (g1Affine p) =
      if p.isInfinity then G1.zero else ⟨p.toAffine.1, p.toAffine.2, Fp.one⟩ := by
  unfold g1ReadAffine g1Affine
  simp only [fpRead_fpEncode]
  by_cases hz : p.isInfinity = true
  · have haff : p.toAffine = (Fp.zero, Fp.zero) := by
      simp only [G1.toAffine, show p.z.isZero = true from hz, if_true]
    simp only [haff, show Fp.zero.isZero = true from rfl, Bool.and_self, if_true, hz]
  · have hn : ¬(p.toAffine.1.isZero && p.toAffine.2.isZero) = true := by
      rw [Bool.and_eq_true]
      rintro ⟨hx, hy⟩
      have hx' := G1.isZero_iff.mp hx
      have hy' := G1.isZero_iff.mp hy
      have hc := hp.1.resolve_left hz
      change (p.toAffine.2 : ZMod Fp.modulus) * p.toAffine.2 =
        p.toAffine.1 * p.toAffine.1 * p.toAffine.1 + 4 at hc
      rw [hx', hy'] at hc
      norm_num at hc
      exact (by decide : (0 : ZMod Fp.modulus) ≠ 4) hc
    simp only [hn, hz, Bool.false_eq_true, if_false]

theorem g1ReadAffine_g1Affine_matches {p : G1} (hp : G1Valid p) :
    (g1ReadAffine (g1Affine p)).isInfinity = p.isInfinity ∧
      (g1ReadAffine (g1Affine p)).toAffine = p.toAffine := by
  rw [g1ReadAffine_g1Affine hp]
  by_cases hz : p.isInfinity = true
  · simp only [hz, if_true]
    constructor
    · rfl
    · simp only [G1.toAffine, G1.zero, show Fp.zero.isZero = true from rfl,
        show p.z.isZero = true from hz, if_true]
  · simp only [hz, Bool.false_eq_true, if_false]
    constructor
    · rfl
    · exact g1_toAffine_of_one _ _

theorem g1Affine_valid {p : G1} (hp : G1Valid p) : G1AffineValid (g1Affine p) := by
  obtain ⟨hinf, haff⟩ := g1ReadAffine_g1Affine_matches hp
  refine ⟨?_, g1Valid_transport hinf haff hp⟩
  exact congrArg (fun xy : Fp × Fp =>
    silver_crypto_simd.blst.blst_p1_affine.mk (fpEncode xy.1) (fpEncode xy.2)) haff.symm

end LeanBlsSimd.Kzg
