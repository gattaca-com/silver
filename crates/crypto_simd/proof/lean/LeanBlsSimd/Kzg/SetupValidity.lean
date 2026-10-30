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
  exact ⟨rfl, arrayBytes SetupPoints.g2Bytes64,
    SetupPoints.g2_64_decoded, SetupPoints.g2_64_subgroup⟩

private def negGeneratorBytes : ByteArray :=
  let b := arrayBytes SetupPoints.g2Bytes0
  b.set! 0 (b[0]! ^^^ 0x20)

theorem setup_g2_neg_zero_decoded :
    G2.uncompress negGeneratorBytes = .ok (G2.neg SetupPoints.g2Point0) := by
  have hs : Fp.sqrt (rhs0.c0 * rhs0.c0 + rhs0.c1 * rhs0.c1) = .ok norm0Root := by
    simp only [SetupArithmetic.sqrt_eq]
    decide +kernel
  have hc : Fp.sqrt ((rhs0.c0 + norm0Root) * (Fp.ofNat 2).inverse) =
      .ok SetupPoints.g2Point0.y.c0 := by
    simp only [SetupArithmetic.sqrt_eq, SetupArithmetic.inverse_eq]
    decide +kernel
  rw [SetupArithmetic.g2_uncompress_of negGeneratorBytes
    SetupPoints.g2Point0.x.c0 SetupPoints.g2Point0.x.c1 _
    (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by simp only [Fp.fromBytesBE, SetupArithmetic.bytesBEToNat_eq]; decide +kernel)
    (by simp only [Fp.fromBytesBE, SetupArithmetic.bytesBEToNat_eq]; decide +kernel)
    (SetupArithmetic.fp2_sqrt_of_plus rhs0 _ _ (by decide +kernel) hs hc)]
  simp only [SetupArithmetic.inverse_eq]
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
