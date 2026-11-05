import LeanBlsSimd.Kzg.Representation
import LeanBlsSimd.Extracted.Funs

open EthLib.Cryptography Bls LeanBlsSimd.Kzg silver_crypto_simd silver_crypto_simd.kzg
deriving instance DecidableEq for BlsError
deriving instance DecidableEq for Fp2
deriving instance DecidableEq for G1
deriving instance DecidableEq for G2

namespace LeanBlsSimd.Kzg.SetupDecoding

/-! The kernel evaluates `Fp.sqrt` and `Fp.inverse` on a symbolic argument when it compares two
unfoldings of `Fp2.sqrt` or `G2.uncompress`; the exponent is concrete, so that evaluation does not
finish. The lemmas below take those functions as opaque variables, and the decoding proofs supply
each square root separately. -/

theorem fp2_sqrt_of_plus (a : Fp2) (s c : Fp) (ha : a.c1.isZero = false)
    (hs : Fp.sqrt (a.c0 * a.c0 + a.c1 * a.c1) = .ok s)
    (hc : Fp.sqrt ((a.c0 + s) * (Fp.ofNat 2).inverse) = .ok c) :
    Fp2.sqrt a = .ok ⟨c, a.c1 * (Fp.ofNat 2 * c).inverse⟩ := by
  obtain ⟨sq, hsq⟩ : ∃ sq, sq = Fp.sqrt := ⟨_, rfl⟩
  obtain ⟨inv, hinv⟩ : ∃ inv, inv = Fp.inverse := ⟨_, rfl⟩
  unfold Fp2.sqrt
  rw [← hsq] at hs hc ⊢
  rw [← hinv] at hc ⊢
  simp only [ha, hs, hc, Bool.false_eq_true, ite_false]

theorem fp2_sqrt_of_minus (a : Fp2) (s c : Fp) (e : BlsError) (ha : a.c1.isZero = false)
    (hs : Fp.sqrt (a.c0 * a.c0 + a.c1 * a.c1) = .ok s)
    (hp : Fp.sqrt ((a.c0 + s) * (Fp.ofNat 2).inverse) = .error e)
    (hc : Fp.sqrt ((a.c0 - s) * (Fp.ofNat 2).inverse) = .ok c) :
    Fp2.sqrt a = .ok ⟨c, a.c1 * (Fp.ofNat 2 * c).inverse⟩ := by
  obtain ⟨sq, hsq⟩ : ∃ sq, sq = Fp.sqrt := ⟨_, rfl⟩
  obtain ⟨inv, hinv⟩ : ∃ inv, inv = Fp.inverse := ⟨_, rfl⟩
  unfold Fp2.sqrt
  rw [← hsq] at hs hp hc ⊢
  rw [← hinv] at hp hc ⊢
  simp only [ha, hs, hp, hc, Bool.false_eq_true, ite_false]

theorem g2_uncompress_of (bytes : ByteArray) (c0 c1 : Fp) (y : Fp2)
    (hsize : bytes.size = 96) (hcomp : bytes.get! 0 &&& 0x80 ≠ 0)
    (hinf : bytes.get! 0 &&& 0x40 = 0)
    (hc1 : Fp.fromBytesBE ((bytes.set! 0 (bytes.get! 0 &&& 0x1f)).extract 0 48) = .ok c1)
    (hc0 : Fp.fromBytesBE ((bytes.set! 0 (bytes.get! 0 &&& 0x1f)).extract 48 96) = .ok c0)
    (hy : Fp2.sqrt (⟨c0, c1⟩ * ⟨c0, c1⟩ * ⟨c0, c1⟩ + G2.bTwist) = .ok y) :
    G2.uncompress bytes = .ok ⟨⟨c0, c1⟩,
      if Fp2.signBit y = decide (bytes.get! 0 &&& 0x20 ≠ 0) then y else -y, Fp2.one⟩ := by
  obtain ⟨sq, hsq⟩ : ∃ sq, sq = Fp2.sqrt := ⟨_, rfl⟩
  obtain ⟨fb, hfb⟩ : ∃ fb, fb = Fp.fromBytesBE := ⟨_, rfl⟩
  unfold G2.uncompress
  rw [← hsq] at hy ⊢
  rw [← hfb] at hc1 hc0 ⊢
  have hcomp' : decide (bytes.get! 0 &&& 0x80 ≠ 0) = true := decide_eq_true hcomp
  have hinf' : decide (bytes.get! 0 &&& 0x40 ≠ 0) = false := decide_eq_false (not_not.mpr hinf)
  simp only [hsize, hcomp', hc1, hc0, hy, Bool.not_true, Bool.false_eq_true, ite_false,
    ne_eq, not_true_eq_false]
  rw [ite_eq_right (not_not.mpr hinf)]
  congr 2
  by_cases hp : bytes.get! 0 &&& 32 = 0 <;> cases y.signBit <;> simp [hp]

end LeanBlsSimd.Kzg.SetupDecoding
