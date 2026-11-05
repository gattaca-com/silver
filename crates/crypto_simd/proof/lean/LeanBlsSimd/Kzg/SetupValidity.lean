import LeanBlsSimd.Kzg.Refines.Setup
import LeanBlsSimd.Kzg.RepresentationLemmas

open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls
open private rhs0 norm0Root from LeanBlsSimd.Kzg.SetupPoints

namespace LeanBlsSimd.Kzg

set_option maxRecDepth 16000
set_option maxHeartbeats 2000000

theorem setup_g1_roundtrip (i : Fin 64) :
    g1ReadAffine (g1Affine SetupPoints.g1Points[i.val]!) = SetupPoints.g1Points[i.val]! := by
  simp only [g1ReadAffine, g1Affine, fpRead_fpEncode]
  fin_cases i <;> decide +kernel

theorem setup_g1_valid (i : Fin 64) : G1Valid SetupPoints.g1Points[i.val]! := by
  refine ⟨Or.inr ?_, SetupPoints.g1_subgroup i⟩
  fin_cases i <;> decide +kernel

theorem setup_g1_affine_valid (i : Fin 64) :
    G1AffineValid (g1Affine SetupPoints.g1Points[i.val]!) := by
  rw [G1AffineValid, setup_g1_roundtrip]
  exact ⟨rfl, setup_g1_valid i⟩

end LeanBlsSimd.Kzg
