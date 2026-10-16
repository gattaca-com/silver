import LeanBlsSimd.Kzg.RepresentationWords
import EthCryptographySpecs.Proofs.Bls.FrZMod
import EthCryptographySpecs.Proofs.Bls.FpZMod
import Aeneas

open Aeneas Aeneas.Std
open EthCryptographySpecs Bls

namespace LeanBlsSimd.Kzg

open scoped EthCryptographySpecs.Bls.Fr EthCryptographySpecs.Bls.Fp

set_option exponentiation.threshold 512
set_option maxRecDepth 8000
set_option maxHeartbeats 2000000

theorem frRead_frEncode (x : Fr) : frRead (frEncode x) = x := by
  unfold frRead frEncode
  rw [limbs_words_four _ (Nat.lt_trans (Nat.mod_lt _ Fr.modulus_pos) (by decide))]
  have hm : Fr.ofNat ((x.val * 2^256) % Fr.modulus) = x * Fr.ofNat (2^256) := by
    apply Fin.ext
    norm_num [Fr.ofNat, Fin.val_mul, Nat.mul_mod, Fr.modulus]
  rw [hm, Fr.inverse_eq_inv]
  have hc : Fr.ofNat (2^256) * (Fr.ofNat (2^256))⁻¹ = (1 : Fr) :=
    mul_inv_cancel₀ (by decide)
  exact (mul_assoc x _ _).trans ((congrArg (fun y : Fr => x * y) hc).trans (mul_one x))

theorem fpRead_fpEncode (x : Fp) : fpRead (fpEncode x) = x := by
  unfold fpRead fpEncode
  rw [limbs_words_six _ (Nat.lt_trans (Nat.mod_lt _ Fp.modulus_pos) (by decide))]
  have hm : Fp.ofNat ((x.val * 2^384) % Fp.modulus) = x * Fp.ofNat (2^384) := by
    apply Fin.ext
    norm_num [Fp.ofNat, Fin.val_mul, Nat.mul_mod, Fp.modulus]
  rw [hm, Fp.inverse_eq_inv]
  have hc : Fp.ofNat (2^384) * (Fp.ofNat (2^384))⁻¹ = (1 : Fp) :=
    mul_inv_cancel₀ (by decide)
  exact (mul_assoc x _ _).trans ((congrArg (fun y : Fp => x * y) hc).trans (mul_one x))

theorem fp2Read_fp2Encode (x : Fp2) : fp2Read (fp2Encode x) = x := by
  cases x
  simp [fp2Read, fp2Encode, fpRead_fpEncode]

theorem g1ReadJacobian_g1Jacobian (p : G1) : g1ReadJacobian (g1Jacobian p) = p := by
  cases p
  simp [g1ReadJacobian, g1Jacobian, fpRead_fpEncode]

theorem g1Jacobian_reduced (p : G1) : JacobianReduced (g1Jacobian p) := by
  exact ⟨fpEncode_reduced _, fpEncode_reduced _, fpEncode_reduced _⟩

theorem g1Jacobian_rep (p : G1) : G1Rep (g1Jacobian p) p := by
  exact ⟨g1Jacobian_reduced p, by rw [g1ReadJacobian_g1Jacobian],
    by rw [g1ReadJacobian_g1Jacobian]⟩

end LeanBlsSimd.Kzg
