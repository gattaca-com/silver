import LeanBlsSimd.Kzg.PointValidity

open Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.CheckedPoints

noncomputable def g1Spec (raw : blst.blst_p1_affine) : Option g1_point.G1Point := by
  classical
  exact if Kzg.G1AffineValid raw then some raw else none

noncomputable def g2Spec (raw : blst.blst_p2_affine) : Option g2_point.G2Point := by
  classical
  exact if Kzg.G2AffineValid raw then some raw else none

/-- Contracts for blst-backed raw constructors, independent of the decoder and CPU dictionaries. -/
structure ConstructorsMatchSpec [PointExternals] : Prop where
  g1 : ∀ raw, PointExternals.fromG1 raw = g1Spec raw
  g2 : ∀ raw, PointExternals.fromG2 raw = g2Spec raw

theorem g1_from_blst_some_iff [PointExternals] (h : ConstructorsMatchSpec)
    (raw : blst.blst_p1_affine) (p : g1_point.G1Point) :
    g1_point.G1Point.from_blst raw = ok (some p) ↔
      p = raw ∧ Kzg.G1AffineValid p := by
  classical
  simp only [g1_point.G1Point.from_blst, h.g1, g1Spec, ok.injEq]
  by_cases hv : Kzg.G1AffineValid raw <;> simp [hv, eq_comm] <;>
    intro heq <;> subst p <;> exact hv

theorem g2_from_blst_some_iff [PointExternals] (h : ConstructorsMatchSpec)
    (raw : blst.blst_p2_affine) (p : g2_point.G2Point) :
    g2_point.G2Point.from_blst raw = ok (some p) ↔
      p = raw ∧ Kzg.G2AffineValid p := by
  classical
  simp only [g2_point.G2Point.from_blst, h.g2, g2Spec, ok.injEq]
  by_cases hv : Kzg.G2AffineValid raw <;> simp [hv, eq_comm] <;>
    intro heq <;> subst p <;> exact hv

theorem g1_accessors (p : g1_point.G1Point) :
    g1_point.G1Point.as_blst p = ok p ∧ g1_point.G1Point.into_blst p = ok p := by
  exact ⟨rfl, rfl⟩

theorem g2_accessors (p : g2_point.G2Point) :
    g2_point.G2Point.as_blst p = ok p ∧ g2_point.G2Point.into_blst p = ok p := by
  exact ⟨rfl, rfl⟩

end LeanBlsSimd.CheckedPoints
