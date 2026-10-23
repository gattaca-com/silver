import LeanBlsSimd.Msm8.Output
import LeanBlsSimd.Msm8.Lanes
import LeanBlsSimd.Kzg.G1Msm

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.Msm8
open EthLib.Cryptography Bls

/-- Group equality transports the represented Jacobian to any valid subgroup target. -/
theorem lane_zero_pointRep (p : g1x8.G1x8) (Q : G1) (hq : Kzg.G1Valid Q)
    (h : (ofG1x8 p).PointRep 0 (G1.toPoint Q)) :
    ∃ out, msm8.lane_zero_in_blst p = ok out ∧ Kzg.G1Rep out Q := by
  obtain ⟨P, hholds, hvalid, heq⟩ := h
  have hp : Kzg.G1Valid P := Kzg.g1Valid_of_groupValid hvalid (by
    rw [heq]
    exact Kzg.g1Valid_subgroup hq)
  have hmatches := (Kzg.g1_toPoint_eq_iff hp hq).mp heq
  obtain ⟨hcall, hrep⟩ := lane_zero_in_blst_rep p P hholds
  exact ⟨Kzg.g1Jacobian P, hcall, hrep.1, hrep.2.1.trans hmatches.1,
    hrep.2.2.trans hmatches.2⟩

/-- The specification MSM accepts the broader Kzg validity predicate, including infinity. -/
theorem lane_zero_msm_rep (p : g1x8.G1x8) (points : _root_.Array G1)
    (scalars : _root_.Array Fr)
    (hp : ∀ j, j < (if points.size ≤ scalars.size then points.size else scalars.size) →
      Kzg.G1Valid points[j]!)
    (h : (ofG1x8 p).PointRep 0
      (∑ j ∈ Finset.range (if points.size ≤ scalars.size then points.size else scalars.size),
        scalars[j]!.val • G1.toPoint points[j]!)) :
    ∃ out, msm8.lane_zero_in_blst p = ok out ∧ Kzg.G1Rep out (G1.msm points scalars) := by
  obtain ⟨hvalid, heq⟩ := Kzg.g1_msm_spec points scalars hp
  apply lane_zero_pointRep p (G1.msm points scalars) hvalid
  rwa [heq]

/-- Canonical affine encodings supply Kzg validity without requiring G1.Valid at infinity. -/
theorem lane_zero_encoded_msm_rep (p : g1x8.G1x8)
    (points : _root_.Array blst.blst_p1_affine) (scalars : _root_.Array Fr)
    (hp : ∀ j (hj : j < points.size), Kzg.G1AffineValid points[j])
    (h : (ofG1x8 p).PointRep 0
      (∑ j ∈ Finset.range (if points.size ≤ scalars.size then points.size else scalars.size),
        scalars[j]!.val • G1.toPoint (points.map Kzg.g1ReadAffine)[j]!)) :
    ∃ out, msm8.lane_zero_in_blst p = ok out ∧
      Kzg.G1Rep out (G1.msm (points.map Kzg.g1ReadAffine) scalars) := by
  apply lane_zero_msm_rep p (points.map Kzg.g1ReadAffine) scalars
  · intro j hj
    have hjp : j < points.size := by simp only [Array.size_map] at hj; split at hj <;> omega
    rw [getElem!_pos _ j (by simpa only [Array.size_map] using hjp), Array.getElem_map]
    exact (hp j hjp).2
  · simpa only [Array.size_map] using h

end LeanBlsSimd.Msm8
