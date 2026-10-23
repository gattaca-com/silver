import LeanBlsSimd.Kzg.ScalarContracts

open Aeneas Aeneas.Std
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.kzg
namespace LeanBlsSimd.Kzg

open scoped EthLib.Cryptography.Bls.Fr

set_option maxRecDepth 16000
set_option maxHeartbeats 2000000

@[simp] theorem fr_zero_eq : FR_ZERO = frEncode (Fr.ofNat 0) := by
  unfold FR_ZERO
  congr 1
@[simp] theorem fr_one_eq : FR_ONE = frEncode (Fr.ofNat 1) := by
  unfold FR_ONE
  congr 1
@[simp] theorem primitive_root_of_unity_eq :
    PRIMITIVE_ROOT_OF_UNITY = frEncode (Fr.ofNat 7) := by
  unfold PRIMITIVE_ROOT_OF_UNITY
  congr 1
@[simp] theorem fr8_scale_eq : fr8.SCALE = frEncode (Fr.ofNat 16) := by
  unfold fr8.SCALE
  congr 1

private theorem inverse_eq (n candidate : Nat) (hn : Fr.ofNat n ≠ 0)
    (hproduct : Fr.ofNat n * Fr.ofNat candidate = 1) :
    (Fr.ofNat n).inverse = Fr.ofNat candidate := by
  rw [Fr.inverse_eq_inv]
  calc
    (Fr.ofNat n)⁻¹ = (Fr.ofNat n)⁻¹ * 1 := (mul_one _).symm
    _ = (Fr.ofNat n)⁻¹ * (Fr.ofNat n * Fr.ofNat candidate) := by rw [hproduct]
    _ = ((Fr.ofNat n)⁻¹ * Fr.ofNat n) * Fr.ofNat candidate := (mul_assoc _ _ _).symm
    _ = Fr.ofNat candidate := by
      have hc : (Fr.ofNat n)⁻¹ * Fr.ofNat n = (1 : Fr) := inv_mul_cancel₀ hn
      exact (congrArg (fun x : Fr => x * Fr.ofNat candidate) hc).trans (one_mul _)

@[simp] theorem inverse_cell_size_eq :
    INVERSE_CELL_SIZE = frEncode (Fr.ofNat 64).inverse := by
  have hi := inverse_eq 64 (Fr.modulus - (Fr.modulus - 1) / 64)
    (by decide +kernel) (by decide +kernel)
  rw [hi]
  unfold INVERSE_CELL_SIZE
  congr 1

@[simp] theorem inverse_blob_size_eq :
    INVERSE_BLOB_SIZE = frEncode (Fr.ofNat 4096).inverse := by
  have hi := inverse_eq 4096 (Fr.modulus - (Fr.modulus - 1) / 4096)
    (by decide +kernel) (by decide +kernel)
  rw [hi]
  unfold INVERSE_BLOB_SIZE
  congr 1

end LeanBlsSimd.Kzg
