import LeanBlsSimd.Kzg.PolynomialModel
import EthLib.Cryptography.Proofs.Kzg.Polynomials

open EthLib.Cryptography Bls Kzg
open scoped EthLib.Cryptography.Bls.Fr BigOperators

attribute [-instance] Fin.instNatPow

namespace LeanBlsSimd.Kzg

theorem coefficientPolynomial_injective (a b : Array Fr) (hs : a.size = b.size)
    (hp : EthLib.Cryptography.Kzg.coefficientPolynomial a =
      EthLib.Cryptography.Kzg.coefficientPolynomial b) : a = b := by
  apply Array.ext hs
  intro i hi hi'
  have he := congrArg (fun p : _root_.Polynomial Fr => p.coeff i) hp
  simpa only [EthLib.Cryptography.Kzg.coeff_coefficientPolynomial,
    getElem!_pos a i hi, getElem!_pos b i hi'] using he

theorem coefficientPolynomial_sum (a : Array Fr) :
    EthLib.Cryptography.Kzg.coefficientPolynomial a =
      ∑ i ∈ Finset.range a.size, _root_.Polynomial.monomial i a[i]! := by
  rw [EthLib.Cryptography.Kzg.coefficientPolynomial, _root_.Polynomial.ofFn_eq_sum_monomial]
  simp only [Finset.sum_range]
  apply Finset.sum_congr rfl
  intro i _
  rw [getElem!_pos a i.val i.isLt]

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

@[simp] theorem coefficientPolynomial_pair (a b : Fr) :
    EthLib.Cryptography.Kzg.coefficientPolynomial #[a, b] =
      _root_.Polynomial.C a + _root_.Polynomial.C b * _root_.Polynomial.X := by
  rw [coefficientPolynomial_sum]
  simp [← _root_.Polynomial.C_mul_X_pow_eq_monomial, Finset.sum_range_succ]

theorem coefficientPolynomial_add (a b : Array Fr) :
    EthLib.Cryptography.Kzg.coefficientPolynomial (addPolynomialcoeff a b) =
      EthLib.Cryptography.Kzg.coefficientPolynomial a +
        EthLib.Cryptography.Kzg.coefficientPolynomial b := by
  apply _root_.Polynomial.ext
  intro i
  simp only [_root_.Polynomial.coeff_add, EthLib.Cryptography.Kzg.coeff_coefficientPolynomial]
  exact EthLib.Cryptography.Kzg.addPolynomialcoeff_getElem! a b i

theorem coefficientPolynomial_map_mul (a : Array Fr) (r : Fr) :
    EthLib.Cryptography.Kzg.coefficientPolynomial (a.map (· * r)) =
      EthLib.Cryptography.Kzg.coefficientPolynomial a * _root_.Polynomial.C r := by
  apply _root_.Polynomial.ext
  intro i
  rw [_root_.Polynomial.coeff_mul_C, EthLib.Cryptography.Kzg.coeff_coefficientPolynomial,
    EthLib.Cryptography.Kzg.coeff_coefficientPolynomial]
  by_cases hi : i < a.size
  · rw [getElem!_pos _ i (by simpa using hi), Array.getElem_map, getElem!_pos a i hi]
    rfl
  · rw [getElem!_neg _ i (by simpa using hi), getElem!_neg a i hi]
    exact (zero_mul r).symm

theorem coefficientPolynomial_prepend_zero (n : Nat) (a : Array Fr) :
    EthLib.Cryptography.Kzg.coefficientPolynomial (Array.replicate n Fr.zero ++ a) =
      _root_.Polynomial.X ^ n * EthLib.Cryptography.Kzg.coefficientPolynomial a := by
  apply _root_.Polynomial.ext
  intro i
  rw [_root_.Polynomial.coeff_X_pow_mul']
  simp only [EthLib.Cryptography.Kzg.coeff_coefficientPolynomial]
  by_cases hin : i < n
  · rw [ite_eq_right (by omega), getElem!_pos _ i (by simp; omega),
      Array.getElem_append_left (by simpa using hin), Array.getElem_replicate]
    rfl
  · rw [ite_eq_left (by omega)]
    by_cases hia : i - n < a.size
    · rw [getElem!_pos _ i (by simp; omega),
        Array.getElem_append_right (by simp; omega)]
      simpa only [Array.size_replicate] using (getElem!_pos a (i-n) hia).symm
    · rw [getElem!_neg (Array.replicate n Fr.zero ++ a) i (Nat.not_lt.mpr (by simp; omega)),
        getElem!_neg a (i-n) (Nat.not_lt.mpr (by omega))]

theorem coefficientPolynomial_monomial_summand (a : Array Fr) (n : Nat) (r : Fr) :
    EthLib.Cryptography.Kzg.coefficientPolynomial (Array.replicate n Fr.zero ++ a.map (· * r)) =
      _root_.Polynomial.monomial n r * EthLib.Cryptography.Kzg.coefficientPolynomial a := by
  rw [coefficientPolynomial_prepend_zero, coefficientPolynomial_map_mul,
    ← _root_.Polynomial.C_mul_X_pow_eq_monomial]
  ring

private def productStep (a b : Array Fr) (r : Array Fr) (k : Nat) : Array Fr :=
  addPolynomialcoeff r (Array.replicate k Fr.zero ++ b.map (· * a[k]!))

private theorem product_fold_polynomial (a b : Array Fr) (n : Nat) :
    EthLib.Cryptography.Kzg.coefficientPolynomial
        ((List.range n).foldl (productStep a b) #[Fr.zero]) =
      (∑ k ∈ Finset.range n, _root_.Polynomial.monomial k a[k]!) *
        EthLib.Cryptography.Kzg.coefficientPolynomial b := by
  induction n with
  | zero => simp
  | succ n ih =>
    simp only [List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil,
      productStep, coefficientPolynomial_add, coefficientPolynomial_monomial_summand,
      Finset.sum_range_succ]
    rw [ih]
    ring

theorem coefficientPolynomial_multiply (a b : Array Fr)
    (ha : 0 < a.size) (hb : 0 < b.size) (hlen : a.size + b.size ≤ 8192) :
    ∃ out, multiplyPolynomialcoeff a b = .ok out ∧
      out.size = a.size + b.size - 1 ∧
      EthLib.Cryptography.Kzg.coefficientPolynomial out =
        EthLib.Cryptography.Kzg.coefficientPolynomial a *
          EthLib.Cryptography.Kzg.coefficientPolynomial b := by
  let out := (List.range a.size).foldl (productStep a b) #[Fr.zero]
  have hcall : multiplyPolynomialcoeff a b = .ok out := by
    simp only [multiplyPolynomialcoeff, Constants.FIELD_ELEMENTS_PER_EXT_BLOB,
      Constants.FIELD_ELEMENTS_PER_BLOB, Nat.reduceMul,
      show ¬ a.size + b.size > 8192 from Nat.not_lt.mpr hlen, ite_false,
      Bind.bind, Except.bind, Pure.pure, Except.pure, ← Array.foldl_toList, Array.toList_range]
    rfl
  refine ⟨out, hcall, ?_, ?_⟩
  · have hne : ¬ a.isEmpty :=
      fun h => Nat.ne_of_gt ha (Array.isEmpty_iff_size_eq_zero.mp h)
    rw [EthLib.Cryptography.Kzg.size_multiplyPolynomialcoeff hcall, ite_eq_right hne]
    exact Nat.max_eq_left (by omega)
  · rw [show out = (List.range a.size).foldl (productStep a b) #[Fr.zero] from rfl,
      product_fold_polynomial, ← coefficientPolynomial_sum]

theorem multiply_scalar64 (r : Fr) (a : Array Fr) (ha : a.size = 64) :
    ∃ out, multiplyPolynomialcoeff #[r] a = .ok out ∧
      out.size = 64 ∧ EthLib.Cryptography.Kzg.coefficientPolynomial out =
        r • EthLib.Cryptography.Kzg.coefficientPolynomial a := by
  obtain ⟨out, hcall, hs, hp⟩ := coefficientPolynomial_multiply #[r] a (by simp)
    (by omega) (by simp [ha])
  refine ⟨out, hcall, by simpa [ha] using hs, ?_⟩
  simpa only [coefficientPolynomial_singleton, _root_.Polynomial.smul_eq_C_mul] using hp

end LeanBlsSimd.Kzg
