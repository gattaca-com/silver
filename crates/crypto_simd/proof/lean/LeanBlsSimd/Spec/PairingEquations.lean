import EthLib.Cryptography.Bls.Pairing

namespace LeanBlsSimd.SpecPairing

open EthLib.Cryptography.Bls

theorem fp2_powNat_zero (a : Fp2) : Fp2.powNat a 0 = Fp2.one := by
  rw [Fp2.powNat]
  rfl

theorem fp2_powNat_step (a : Fp2) (n : Nat) (hn : n ≠ 0) :
    Fp2.powNat a n =
      if n % 2 = 1 then a * Fp2.powNat (a * a) (n / 2)
      else Fp2.powNat (a * a) (n / 2) := by
  rw [Fp2.powNat, if_neg hn]

theorem fp12_powNat_zero (a : Fp12) : Fp12.powNat a 0 = Fp12.one := by
  rw [Fp12.powNat]
  rfl

theorem fp12_powNat_step (a : Fp12) (n : Nat) (hn : n ≠ 0) :
    Fp12.powNat a n =
      if n % 2 = 1 then a * Fp12.powNat (a * a) (n / 2)
      else Fp12.powNat (a * a) (n / 2) := by
  rw [Fp12.powNat, if_neg hn]

theorem millerSteps_zero (s : Nat) (R P T : Embedded.Point) (f : Fp12) :
    millerSteps s R P 0 T f = f := rfl

theorem millerSteps_succ (s n : Nat) (R P T : Embedded.Point) (f : Fp12) :
    millerSteps s R P (n + 1) T f =
      let doubled := millerDouble T P f
      let next := if (s >>> n) &&& 1 = 1 then
          millerAdd doubled.1 R P doubled.2 else doubled
      millerSteps s R P n next.1 next.2 := rfl

theorem millerLoop_eq (s : Nat) (R P : Embedded.Point) :
    millerLoop s R P = millerSteps s R P s.log2 R Fp12.one := rfl

theorem millerLoop_zero (R P : Embedded.Point) :
    millerLoop 0 R P = Fp12.one := rfl

theorem finalExponentiation_eq (f : Fp12) :
    finalExponentiation f = Fp12.powNat f ((Fp.modulus ^ 12 - 1) / Fr.modulus) := rfl

/-- Accumulate a single pair, preserving the specification's identity skip. -/
def pairingFoldStep (acc : Fp12) (pair : G1 × G2) : Fp12 :=
  if pair.1.isInfinity || pair.2.isInfinity then acc
  else acc * (millerLoop blsX (Embedded.ofG2 pair.2) (Embedded.ofG1 pair.1)).conjugate

/-- The Miller product before final exponentiation. -/
def pairingFold (pairs : Array (G1 × G2)) : Fp12 :=
  pairs.foldl pairingFoldStep Fp12.one

theorem pairingCheck_eq (pairs : Array (G1 × G2)) :
    pairingCheck pairs = (finalExponentiation (pairingFold pairs)).isOne := by
  simp [pairingCheck]
  have step (pair : G1 × G2) (acc : Fp12) :
      (if pair.1.isInfinity || pair.2.isInfinity then
        pure (ForInStep.yield acc)
      else pure (ForInStep.yield
        (acc * (millerLoop blsX (Embedded.ofG2 pair.2) (Embedded.ofG1 pair.1)).conjugate))) =
      (pure (ForInStep.yield (pairingFoldStep acc pair)) : Id (ForInStep Fp12)) := by
    unfold pairingFoldStep
    split <;> rfl
  simp only [Bool.or_eq_true] at step
  simp only [step, Array.forIn_pure_yield_eq_foldl]
  rfl

theorem pairingFold_empty : pairingFold #[] = Fp12.one := rfl

theorem pairingFold_push (pairs : Array (G1 × G2)) (pair : G1 × G2) :
    pairingFold (pairs.push pair) = pairingFoldStep (pairingFold pairs) pair := by
  exact Array.foldl_push

end LeanBlsSimd.SpecPairing
