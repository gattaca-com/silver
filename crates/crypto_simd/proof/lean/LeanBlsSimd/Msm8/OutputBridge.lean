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

end LeanBlsSimd.Msm8
