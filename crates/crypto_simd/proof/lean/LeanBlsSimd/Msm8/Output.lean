import LeanBlsSimd.Kzg.FpEncoding
import LeanBlsSimd.Proofs.G1x8

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.Msm8
open EthCryptographySpecs.Bls

def laneZero (p : G1x8) : blst.blst_p1 :=
  ⟨⟨toArray toU64 p.x.to_blst_limbs[0]⟩,
   ⟨toArray toU64 p.y.to_blst_limbs[0]⟩,
   ⟨toArray toU64 p.z.to_blst_limbs[0]⟩⟩

theorem lane_zero_in_blst_refines (p : g1x8.G1x8) :
    msm8.lane_zero_in_blst p = ok (laneZero (ofG1x8 p)) := by
  simp only [msm8.lane_zero_in_blst, Fp8.to_blst_limbs_refines, bind_tc_ok]
  rfl


theorem fp_to_blst_eq {x : Fp8} {l : Fin 8} {a : Fp} (h : x.Holds l a) :
    (⟨toArray toU64 x.to_blst_limbs[l]⟩ : blst.blst_fp) = Kzg.fpEncode a := by
  rw [Kzg.fpEncode_eq_bls]
  exact congrArg DecompressG2.toBlstFp (DecompressG2.blstFp_eq h.val64_to_blst_limbs)

theorem laneZero_eq {p : G1x8} {P : G1} (h : p.Holds 0 P) :
    laneZero p = Kzg.g1Jacobian P := by
  unfold laneZero Kzg.g1Jacobian
  congr 1
  · exact fp_to_blst_eq (G1x8.Holds.x h)
  · exact fp_to_blst_eq (G1x8.Holds.y h)
  · exact fp_to_blst_eq (G1x8.Holds.z h)

theorem lane_zero_in_blst_rep (p : g1x8.G1x8) (P : G1) (h : (ofG1x8 p).Holds 0 P) :
    msm8.lane_zero_in_blst p = ok (Kzg.g1Jacobian P) ∧
      Kzg.G1Rep (Kzg.g1Jacobian P) P :=
  ⟨(lane_zero_in_blst_refines p).trans (congrArg ok (laneZero_eq h)), Kzg.g1Jacobian_rep P⟩

end LeanBlsSimd.Msm8
