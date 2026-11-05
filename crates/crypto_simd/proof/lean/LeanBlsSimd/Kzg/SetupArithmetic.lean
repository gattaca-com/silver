import LeanBlsSimd.Kzg.Representation
import LeanBlsSimd.Extracted.Funs
import EthLib.Cryptography.Proofs.IdLoops

open EthLib.Cryptography Bls LeanBlsSimd.Kzg silver_crypto_simd silver_crypto_simd.kzg
deriving instance DecidableEq for BlsError
deriving instance DecidableEq for Fp2
deriving instance DecidableEq for G1
deriving instance DecidableEq for G2

namespace LeanBlsSimd.Kzg.SetupArithmetic

def g1Mul : Nat → G1 → Nat → G1
  | 0, _, _ => G1.zero
  | fuel + 1, p, k =>
    if k = 0 then G1.zero
    else
      let half := g1Mul fuel (G1.double p) (k / 2)
      if k % 2 = 1 then G1.add p half else half

theorem g1Mul_eq (fuel : Nat) (p : G1) (k : Nat)
    (hk : k < 2 ^ fuel) : g1Mul fuel p k = G1.mulNat p k := by
  induction fuel generalizing p k with
  | zero =>
    have : k = 0 := by simpa using hk
    subst this
    rw [g1Mul, G1.mulNat]
    simp
  | succ fuel ih =>
    rw [g1Mul, G1.mulNat]
    by_cases h0 : k = 0
    · simp [h0]
    · have h2 : k / 2 < 2 ^ fuel := by
        rw [Nat.pow_succ] at hk
        omega
      rw [ite_eq_right h0, ite_eq_right h0, ih (G1.double p) (k / 2) h2]

def g2Mul : Nat → G2 → Nat → G2
  | 0, _, _ => G2.zero
  | fuel + 1, p, k =>
    if k = 0 then G2.zero
    else
      let half := g2Mul fuel (G2.double p) (k / 2)
      if k % 2 = 1 then G2.add p half else half

theorem g2Mul_eq (fuel : Nat) (p : G2) (k : Nat)
    (hk : k < 2 ^ fuel) : g2Mul fuel p k = G2.mulNat p k := by
  induction fuel generalizing p k with
  | zero =>
    have : k = 0 := by simpa using hk
    subst this
    rw [g2Mul, G2.mulNat]
    simp
  | succ fuel ih =>
    rw [g2Mul, G2.mulNat]
    by_cases h0 : k = 0
    · simp [h0]
    · have h2 : k / 2 < 2 ^ fuel := by
        rw [Nat.pow_succ] at hk
        omega
      rw [ite_eq_right h0, ite_eq_right h0, ih (G2.double p) (k / 2) h2]

/-- The spec's `for` loop recurses on a well-founded measure, which the kernel evaluates slowly. -/
theorem bytesBEToNat_eq (b : ByteArray) :
    Fp.bytesBEToNat b = (List.range' 0 b.size).foldl (fun acc i => (acc <<< 8) ||| b[i]!.toNat) 0 := by
  change forIn (m := Id) [:b.size] 0 (fun i acc => ForInStep.yield ((acc <<< 8) ||| b[i]!.toNat)) = _
  exact IdLoops.forIn_range_yield _ _ _

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

end LeanBlsSimd.Kzg.SetupArithmetic
