import LeanBlsSimd.Pairing.CombinedMiller

open EthLib.Cryptography Bls

namespace LeanBlsSimd.Pairing

theorem FinalEq.verdict {a b : Fp12} (h : FinalEq a b) :
    (finalExponentiation a).isOne = (finalExponentiation b).isOne := by
  rw [Bool.eq_iff_iff, finalExponentiation_isOne_iff, finalExponentiation_isOne_iff, h]

theorem pairingFactor_congr {p q : G1} (Q : G2)
    (hi : p.isInfinity = q.isInfinity) (ha : p.toAffine = q.toAffine) :
    pairingFactor (p, Q) = pairingFactor (q, Q) := by
  simp only [pairingFactor, Embedded.ofG1, hi, ha]

theorem pairingCheck_two (p q : G1) (P Q : G2) :
    Bls.pairingCheck #[(p, P), (q, Q)] =
      (finalExponentiation (pairingFactor (p, P) * pairingFactor (q, Q))).isOne := by
  rw [SpecPairing.pairingCheck_eq, Bool.eq_iff_iff,
    finalExponentiation_isOne_iff, finalExponentiation_isOne_iff,
    toField_pairingFold, map_mul]
  simp

theorem pairingCheck_two_congr {p q p' q' : G1} (P Q : G2)
    (hpi : p.isInfinity = p'.isInfinity) (hpa : p.toAffine = p'.toAffine)
    (hqi : q.isInfinity = q'.isInfinity) (hqa : q.toAffine = q'.toAffine) :
    Bls.pairingCheck #[(p, P), (q, Q)] = Bls.pairingCheck #[(p', P), (q', Q)] := by
  rw [pairingCheck_two, pairingCheck_two,
    pairingFactor_congr P hpi hpa, pairingFactor_congr Q hqi hqa]

theorem combined_verdict (points : Fin 2 → G1) :
    (finalExponentiation (combinedMiller points).conjugate).isOne =
      Bls.pairingCheck #[(points 0, Kzg.SetupPoints.g2Point64),
        (points 1, G2.neg Kzg.SetupPoints.g2Point0)] := by
  rw [pairingCheck_two]
  exact (combined_final_eq points).verdict.symm

end LeanBlsSimd.Pairing
