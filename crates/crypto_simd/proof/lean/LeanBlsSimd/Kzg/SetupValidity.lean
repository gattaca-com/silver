import LeanBlsSimd.Kzg.Refines.Setup
import LeanBlsSimd.Kzg.RepresentationLemmas

open EthCryptographySpecs Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg

set_option maxRecDepth 16000
set_option maxHeartbeats 2000000

theorem setup_g1_roundtrip (i : Fin 64) :
    g1ReadAffine (g1Affine SetupPoints.g1Points[i.val]!) = SetupPoints.g1Points[i.val]! := by
  simp only [g1ReadAffine, g1Affine, fpRead_fpEncode, G1.toAffine, SetupArithmetic.inverse_eq]
  fin_cases i <;> decide +kernel

theorem setup_g1_valid (i : Fin 64) : G1Valid SetupPoints.g1Points[i.val]! := by
  refine ⟨Or.inr ?_, SetupPoints.g1_subgroup i⟩
  simp only [G1.toAffine, SetupArithmetic.inverse_eq]
  fin_cases i <;> decide +kernel

theorem setup_g1_affine_valid (i : Fin 64) :
    G1AffineValid (g1Affine SetupPoints.g1Points[i.val]!) := by
  rw [G1AffineValid, setup_g1_roundtrip]
  exact ⟨rfl, setup_g1_valid i⟩

theorem setup_g2_cell_valid : G2AffineValid (g2Affine SetupPoints.g2Point64) := by
  rw [G2AffineValid, setup_g2_cell_roundtrip]
  exact ⟨rfl, arrayBytes trusted_setup.G2_MONOMIAL_64,
    SetupPoints.g2_64_decoded, SetupPoints.g2_64_subgroup⟩

private def negGeneratorBytes : ByteArray :=
  let b := arrayBytes trusted_setup.G2_MONOMIAL_0
  b.set! 0 (b[0]! ^^^ 0x20)

theorem setup_g2_neg_zero_decoded :
    G2.uncompress negGeneratorBytes = .ok (G2.neg SetupPoints.g2Point0) := by
  rw [G2.uncompress]
  simp only [Fp2.sqrt, SetupArithmetic.sqrt_eq, SetupArithmetic.inverse_eq]
  decide +kernel

theorem setup_g2_neg_zero_subgroup : (G2.neg SetupPoints.g2Point0).inSubgroup = true := by
  rw [G2.inSubgroup, ← SetupArithmetic.g2Mul_eq 256 _ Fr.modulus (by decide)]
  decide +kernel

theorem setup_g2_neg_zero_roundtrip :
    g2ReadAffine (g2Affine (G2.neg SetupPoints.g2Point0)) = G2.neg SetupPoints.g2Point0 := by
  simp only [g2ReadAffine, g2Affine, fp2Read_fp2Encode, G2.toAffine,
    Fp2.inverse, SetupArithmetic.inverse_eq]
  decide +kernel

theorem setup_g2_neg_zero_valid : G2AffineValid (g2Affine (G2.neg SetupPoints.g2Point0)) := by
  rw [G2AffineValid, setup_g2_neg_zero_roundtrip]
  exact ⟨rfl, negGeneratorBytes, setup_g2_neg_zero_decoded, setup_g2_neg_zero_subgroup⟩

end LeanBlsSimd.Kzg
