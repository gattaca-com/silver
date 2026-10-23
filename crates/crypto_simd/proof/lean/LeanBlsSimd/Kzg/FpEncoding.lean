import LeanBlsSimd.Kzg.RepresentationLemmas
import LeanBlsSimd.Refines.G1x8

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

open EthLib.Cryptography Bls
namespace LeanBlsSimd.Kzg

theorem fpEncode_eq_bls (x : Fp) :
    fpEncode x = DecompressG2.toBlstFp (DecompressG2.blstFp x) := by
  have hpow : (2 ^ 384 : ZMod Fp.modulus).val = 2 ^ 384 % Fp.modulus := by
    rw [show (2 ^ 384 : ZMod Fp.modulus) = ((2 ^ 384 : ℕ) : ZMod Fp.modulus) by
      simp only [Nat.cast_pow, Nat.cast_ofNat], ZMod.val_natCast]
  have hmont (a : ZMod Fp.modulus) : (a * 2 ^ 384).val =
      a.val * 2 ^ 384 % Fp.modulus := by
    rw [ZMod.val_mul, hpow]
    exact Nat.mul_mod_mod _ _ _
  simp only [fpEncode, DecompressG2.toBlstFp, DecompressG2.blstFp]
  apply congrArg blst.blst_fp.mk
  apply Subtype.ext
  apply List.ext_getElem
  · simp only [words, toArray, List.length_map, List.length_range,
      Vector.length_toList]
    rfl
  · intro i hi hj
    simp only [words, toArray, List.getElem_map, List.getElem_range,
      Vector.getElem_toList, Vector.getElem_ofFn, hmont]
    rfl

end LeanBlsSimd.Kzg
