import LeanBlsSimd.Kzg.FpEncoding
import LeanBlsSimd.Kzg.G1Compression
import LeanBlsSimd.Refines.DecompressG1
import LeanBlsSimd.Spec.G1Encoding
import LeanBlsSimd.Spec.G2Encoding

open Aeneas.Std
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg

theorem g1Affine_eq_bls (p : G1) :
    g1Affine p = DecompressG1.toBlstP1Affine (G1Spec.blstLimbs p) := by
  simp [g1Affine, DecompressG1.toBlstP1Affine, G1Spec.blstLimbs, fpEncode_eq_bls]

theorem g2Affine_eq_bls (p : G2) :
    g2Affine p = DecompressG2.toBlstP2Affine (G2Spec.blstLimbs p) := by
  simp only [g2Affine, fp2Encode, DecompressG2.toBlstP2Affine, G2Spec.blstLimbs,
    DecompressG2.blstPoint, DecompressG2.toBlstFp2, toArray, fpEncode_eq_bls,
    Fp2.re_toField, Fp2.im_toField]
  rfl

private theorem g2_toAffine_one (x y : Fp2) :
    G2.toAffine ⟨x, y, Fp2.one⟩ = (x, y) := by
  have hz : Fp2.one.isZero = false := by
    apply Bool.eq_false_iff.mpr
    simp [Fp2.isZero_iff]
  simp only [G2.toAffine, hz, Bool.false_eq_true, if_false]
  apply Prod.ext <;> apply Fp2.toField.injective <;>
    simp [map_mul, Fp2.toField_inverse]

private theorem g2ReadAffine_zero : g2ReadAffine (g2Affine G2.zero) = G2.zero := by
  simp only [g2ReadAffine, g2Affine, fp2Read_fp2Encode, G2.toAffine, G2.zero]
  rfl

theorem g2ReadAffine_decoded {bytes : ByteArray} {p : G2}
    (hd : G2.uncompress bytes = .ok p) : g2ReadAffine (g2Affine p) = p := by
  unfold G2.uncompress at hd
  split at hd
  · cases hd
  · dsimp only at hd
    split at hd
    · cases hd
    · split at hd
      · split at hd
        · cases hd
        · cases hd
          exact g2ReadAffine_zero
      · split at hd
        · rename_i c1 c0 hc1 hc0
          split at hd
          · cases hd
          · rename_i y hy
            cases hd
            simp only [g2ReadAffine, g2Affine, g2_toAffine_one, fp2Read_fp2Encode]
            have hroot := Fp2.sqrt_sound hy
            have hne : Fp2.toField y ≠ 0 := by
              intro hz
              have hrhs : Kernel.rhs (Fp2.toField (⟨c0, c1⟩ : Fp2)) = 0 := by
                simpa [Kernel.rhs, map_add, map_mul, G2.bTwist, hz, pow_succ] using hroot.symm
              exact Kernel.rhs_ne_zero _ hrhs
            have hn (choice : Prop) [Decidable choice] :
                (if choice then y else -y).isZero = false := by
              apply Bool.eq_false_iff.mpr
              split <;> simpa [Fp2.isZero_iff] using hne
            simp only [hn, Bool.and_false, Bool.false_eq_true, if_false]
        · cases hd

theorem g2Affine_decoded_valid {bytes : ByteArray} {p : G2}
    (hd : G2.uncompress bytes = .ok p) (hg : p.inSubgroup = true) :
    G2AffineValid (g2Affine p) := by
  rw [G2AffineValid, g2ReadAffine_decoded hd]
  exact ⟨rfl, bytes, hd, hg⟩

theorem g1_verdict_valid (bytes : Vector UInt8 48) (p : DecompressG1.BlstP1Affine)
    (h : G1Spec.verdict bytes = some p) :
    G1AffineValid (DecompressG1.toBlstP1Affine p) := by
  obtain ⟨hk, P, hd, rfl⟩ := (G1Spec.verdict_some_iff bytes p).mp h
  rw [← g1Affine_eq_bls]
  apply g1Affine_valid
  refine ⟨g1_uncompress_curve hd, ?_⟩
  have hv : EthLib.Cryptography.Kzg.validateKzgG1 (G1Spec.toBytes bytes) = true := by
    by_cases hv : EthLib.Cryptography.Kzg.validateKzgG1 (G1Spec.toBytes bytes) = true
    · exact hv
    · simp [EthLib.Cryptography.Kzg.bytesToKzgProof, hv, Except.isOk, Except.toBool] at hk
  simpa [G1Spec.validate_eq_decode, hd] using hv

theorem g2_verdict_valid (bytes : Vector UInt8 96) (p : DecompressG2.BlstP2Affine)
    (h : G2Spec.verdict bytes = some p) :
    G2AffineValid (DecompressG2.toBlstP2Affine p) := by
  obtain ⟨P, hd, hg, rfl⟩ := (G2Spec.verdict_some_iff bytes p).mp h
  rw [← g2Affine_eq_bls]
  exact g2Affine_decoded_valid hd hg

end LeanBlsSimd.Kzg
