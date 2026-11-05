import LeanBlsSimd.Kzg.PolynomialModel
import EthLib.Cryptography.Proofs.Kzg.Polynomials

open EthLib.Cryptography Bls Kzg
open scoped EthLib.Cryptography.Bls.Fr

namespace LeanBlsSimd.Kzg

theorem coefficientPolynomial_injective (a b : Array Fr) (hs : a.size = b.size)
    (hp : EthLib.Cryptography.Kzg.coefficientPolynomial a =
      EthLib.Cryptography.Kzg.coefficientPolynomial b) : a = b := by
  apply Array.ext hs
  intro i hi hi'
  have he := congrArg (fun p : _root_.Polynomial Fr => p.coeff i) hp
  simpa only [EthLib.Cryptography.Kzg.coeff_coefficientPolynomial,
    getElem!_pos a i hi, getElem!_pos b i hi'] using he

@[simp] theorem coefficientPolynomial_replicate_zero (n : Nat) :
    EthLib.Cryptography.Kzg.coefficientPolynomial (Array.replicate n Fr.zero) = 0 := by
  apply _root_.Polynomial.ext
  intro i
  rw [EthLib.Cryptography.Kzg.coeff_coefficientPolynomial]
  by_cases hi : i < n
  · rw [getElem!_pos _ i (by simpa using hi), Array.getElem_replicate]
    rfl
  · rw [getElem!_neg _ i (by simpa using hi)]
    rfl

@[simp] theorem coefficientPolynomial_singleton (r : Fr) :
    EthLib.Cryptography.Kzg.coefficientPolynomial #[r] = _root_.Polynomial.C r := by
  apply _root_.Polynomial.ext
  intro i
  cases i with
  | zero => simp [EthLib.Cryptography.Kzg.coeff_coefficientPolynomial]
  | succ i => simp [EthLib.Cryptography.Kzg.coeff_coefficientPolynomial]

theorem coefficientPolynomial_add (a b : Array Fr) :
    EthLib.Cryptography.Kzg.coefficientPolynomial (addPolynomialcoeff a b) =
      EthLib.Cryptography.Kzg.coefficientPolynomial a +
        EthLib.Cryptography.Kzg.coefficientPolynomial b := by
  apply _root_.Polynomial.ext
  intro i
  simp only [_root_.Polynomial.coeff_add, EthLib.Cryptography.Kzg.coeff_coefficientPolynomial]
  exact EthLib.Cryptography.Kzg.addPolynomialcoeff_getElem! a b i

end LeanBlsSimd.Kzg
