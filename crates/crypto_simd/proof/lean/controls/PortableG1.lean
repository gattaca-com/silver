import LeanBlsSimd.Portable.G1.Scott

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.G1.Controls
set_option maxRecDepth 4096
set_option exponentiation.threshold 4096

theorem doubling_infinity_retains_zero_z [RuntimeFeatures] :
    (do let out ← portable.g1.G1.double (encode Bls.G1.zero)
        ok out.z) = ok (Kzg.fpEncode Bls.Fp.zero).l := by
  rw [double_encoded]
  rfl

theorem complete_add_opposites [RuntimeFeatures] :
    portable.g1.G1.add_complete (encode Bls.G1.generator) (encode (Bls.G1.neg Bls.G1.generator)) =
      ok (encode Bls.G1.zero) := by
  rw [add_complete_encoded]
  rfl

theorem mixed_add_opposites [RuntimeFeatures] :
    portable.g1.G1.add_affine_complete (encode Bls.G1.generator)
      (Kzg.fpEncode Bls.G1.generator.x).l (Kzg.fpEncode (-Bls.G1.generator.y)).l =
      ok (encode Bls.G1.zero) := by
  rw [add_affine_complete_encoded]
  rfl

theorem scott_accepts_generator [RuntimeFeatures] :
    portable.g1.G1.in_g1 (Kzg.fpEncode Bls.G1.generator.x).l
      (Kzg.fpEncode Bls.G1.generator.y).l = ok true := by
  exact (in_g1_encoded Bls.G1.generator.x Bls.G1.generator.y Bls.G1.valid_generator).trans
    (congrArg ok ((G1Spec.inSubgroup_iff _ Bls.G1.valid_generator).mpr Bls.G1.modulus_smul_generator))

theorem scott_rejects_false_generator_result [RuntimeFeatures] :
    portable.g1.G1.in_g1 (Kzg.fpEncode Bls.G1.generator.x).l
      (Kzg.fpEncode Bls.G1.generator.y).l ≠ ok false := by
  rw [scott_accepts_generator]
  intro h
  cases Result.ok.inj h

#print axioms double_values_point
#print axioms add_affine_complete_encoded
#print axioms timesZ_valid_point
#print axioms in_g1_encoded

end LeanBlsSimd.Portable.G1.Controls
