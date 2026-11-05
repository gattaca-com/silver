import EthLib.Cryptography.Bls.Pairing

namespace LeanBlsSimd.SpecPairing

open EthLib.Cryptography.Bls

theorem millerSteps_succ (s n : Nat) (R P T : Embedded.Point) (f : Fp12) :
    millerSteps s R P (n + 1) T f =
      let doubled := millerDouble T P f
      let next := if (s >>> n) &&& 1 = 1 then
          millerAdd doubled.1 R P doubled.2 else doubled
      millerSteps s R P n next.1 next.2 := rfl

theorem millerLoop_eq (s : Nat) (R P : Embedded.Point) :
    millerLoop s R P = millerSteps s R P s.log2 R Fp12.one := rfl

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

end LeanBlsSimd.SpecPairing
