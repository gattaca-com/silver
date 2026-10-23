import LeanBlsSimd.Kzg.Representation
import LeanBlsSimd.Extracted.Funs

open EthLib.Cryptography Bls LeanBlsSimd.Kzg silver_crypto_simd silver_crypto_simd.kzg
deriving instance DecidableEq for BlsError
deriving instance DecidableEq for Fp2
deriving instance DecidableEq for G1
deriving instance DecidableEq for G2

namespace LeanBlsSimd.Kzg.SetupArithmetic
set_option maxRecDepth 16000
set_option exponentiation.threshold 512
set_option maxHeartbeats 2000000

/-- Structural evaluation for kernel checking the embedded setup. -/
def fpPow : Nat → Fp → Nat → Fp
  | 0, _, _ => Fp.one
  | fuel + 1, p, k =>
    if k = 0 then Fp.one
    else
      let half := fpPow fuel (p * p) (k / 2)
      if k % 2 = 1 then p * half else half

theorem fpPow_eq (fuel : Nat) (p : Fp) (k : Nat)
    (hk : k < 2 ^ fuel) : fpPow fuel p k = Fp.powNat p k := by
  induction fuel generalizing p k with
  | zero =>
    have : k = 0 := by simpa using hk
    subst this
    rw [fpPow, Fp.powNat]
    simp
  | succ fuel ih =>
    rw [fpPow, Fp.powNat]
    by_cases h0 : k = 0
    · simp [h0]
    · have h2 : k / 2 < 2 ^ fuel := by
        rw [Nat.pow_succ] at hk
        omega
      rw [if_neg h0, if_neg h0, ih (p * p) (k / 2) h2]

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
      rw [if_neg h0, if_neg h0, ih (G1.double p) (k / 2) h2]

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
      rw [if_neg h0, if_neg h0, ih (G2.double p) (k / 2) h2]

theorem sqrt_eq (a : Fp) : Fp.sqrt a =
    (let cand := fpPow 384 a ((Fp.modulus + 1) / 4)
     if (cand * cand).beq a then .ok cand else .error .notASquare) := by
  unfold Fp.sqrt
  rw [fpPow_eq 384 a _ (by decide)]

theorem inverse_eq (a : Fp) : a.inverse = fpPow 384 a (Fp.modulus - 2) := by
  exact (fpPow_eq 384 a _ (by decide)).symm

end LeanBlsSimd.Kzg.SetupArithmetic
