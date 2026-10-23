import LeanBlsSimd.Kzg.PolynomialModel
import EthLib.Cryptography.Proofs.Kzg.Polynomials

open EthLib.Cryptography Bls Kzg
open scoped EthLib.Cryptography.Bls.Fr BigOperators

attribute [-instance] Lean.Grind.Fin.instHPowFinNatOfNeZero
attribute [-instance] Lean.Grind.Fin.instPowFinNatOfNeZero

namespace LeanBlsSimd.Kzg

set_option maxHeartbeats 3000000
set_option maxRecDepth 2000

theorem coeffPolynomial_coeff_lt (a : Array Fr) (i : Nat) (hi : i < a.size) :
    (coeffPolynomial a).coeff i = a[i] :=
  _root_.Polynomial.ofFn_coeff_eq_val_of_lt _ hi

theorem coeffPolynomial_coeff_ge (a : Array Fr) (i : Nat) (hi : a.size ≤ i) :
    (coeffPolynomial a).coeff i = 0 :=
  _root_.Polynomial.ofFn_coeff_eq_zero_of_ge _ hi

theorem coeffPolynomial_coeff (a : Array Fr) (i : Nat) :
    (coeffPolynomial a).coeff i = if i < a.size then a[i]! else 0 := by
  by_cases hi : i < a.size
  · rw [if_pos hi, coeffPolynomial_coeff_lt a i hi, getElem!_pos a i hi]
  · rw [if_neg hi, coeffPolynomial_coeff_ge a i (by omega)]

theorem coeffPolynomial_injective (a b : Array Fr) (hs : a.size = b.size)
    (hp : coeffPolynomial a = coeffPolynomial b) : a = b := by
  apply Array.ext hs
  intro i hi hi'
  have he := congrArg (fun p : _root_.Polynomial Fr => p.coeff i) hp
  simpa only [coeffPolynomial_coeff_lt a i hi, coeffPolynomial_coeff_lt b i hi'] using he

theorem coeffPolynomial_degree_lt_size (a : Array Fr) :
    (coeffPolynomial a).degree < a.size := _root_.Polynomial.ofFn_degree_lt _

theorem coeffPolynomial_sum (a : Array Fr) :
    coeffPolynomial a = ∑ i ∈ Finset.range a.size, _root_.Polynomial.monomial i a[i]! := by
  rw [coeffPolynomial, _root_.Polynomial.ofFn_eq_sum_monomial]
  simp only [Finset.sum_range]
  apply Finset.sum_congr rfl
  intro i _
  rw [getElem!_pos a i.val i.isLt]

theorem coeffPolynomial_eval (a : Array Fr) (z : Fr) :
    (coeffPolynomial a).eval z = ∑ i ∈ Finset.range a.size, a[i]! * z^i := by
  rw [coeffPolynomial_sum]
  simp only [_root_.Polynomial.eval_finset_sum, _root_.Polynomial.eval_monomial]
  rfl

@[simp] theorem coeffPolynomial_replicate_zero (n : Nat) :
    coeffPolynomial (Array.replicate n Fr.zero) = 0 := by
  apply _root_.Polynomial.ext
  intro i
  rw [coeffPolynomial_coeff]
  split <;> simp_all

@[simp] theorem coeffPolynomial_singleton (r : Fr) :
    coeffPolynomial #[r] = _root_.Polynomial.C r := by
  apply _root_.Polynomial.ext
  intro i
  cases i with
  | zero => simp [coeffPolynomial_coeff]
  | succ i => simp [coeffPolynomial_coeff]

@[simp] theorem coeffPolynomial_pair (a b : Fr) :
    coeffPolynomial #[a, b] = _root_.Polynomial.C a + _root_.Polynomial.C b * _root_.Polynomial.X := by
  rw [coeffPolynomial_sum]
  simp [← _root_.Polynomial.C_mul_X_pow_eq_monomial, Finset.sum_range_succ]

private theorem add_longer (a b : Array Fr) (h : b.size ≤ a.size) :
    coeffPolynomial (Array.ofFn (n := a.size) fun i =>
      a[i.val]! + if i.val < b.size then b[i.val]! else Fr.zero) =
      coeffPolynomial a + coeffPolynomial b := by
  apply _root_.Polynomial.ext
  intro i
  rw [_root_.Polynomial.coeff_add]
  by_cases ha : i < a.size
  · rw [coeffPolynomial_coeff_lt _ i (by simpa using ha), Array.getElem_ofFn,
      coeffPolynomial_coeff, coeffPolynomial_coeff, if_pos ha]
    rfl
  · have hb : ¬ i < b.size := by omega
    rw [coeffPolynomial_coeff_ge _ i (by simpa using Nat.le_of_not_lt ha),
      coeffPolynomial_coeff_ge a i (by omega), coeffPolynomial_coeff_ge b i (by omega)]
    simp

theorem coeffPolynomial_add (a b : Array Fr) :
    coeffPolynomial (addPolynomialcoeff a b) = coeffPolynomial a + coeffPolynomial b := by
  by_cases h : b.size ≤ a.size
  · unfold addPolynomialcoeff
    rw [if_pos h]
    exact add_longer a b h
  · unfold addPolynomialcoeff
    rw [if_neg h]
    exact (add_longer b a (by omega)).trans (add_comm _ _)

theorem coeffPolynomial_map_mul (a : Array Fr) (r : Fr) :
    coeffPolynomial (a.map (· * r)) = coeffPolynomial a * _root_.Polynomial.C r := by
  apply _root_.Polynomial.ext
  intro i
  rw [_root_.Polynomial.coeff_mul_C]
  by_cases hi : i < a.size
  · rw [coeffPolynomial_coeff_lt _ i (by simpa using hi), Array.getElem_map,
      coeffPolynomial_coeff_lt a i hi]
    rfl
  · rw [coeffPolynomial_coeff_ge _ i (by simpa using Nat.le_of_not_lt hi),
      coeffPolynomial_coeff_ge a i (by omega)]
    exact (zero_mul r).symm

theorem coeffPolynomial_prepend_zero (n : Nat) (a : Array Fr) :
    coeffPolynomial (Array.replicate n Fr.zero ++ a) =
      _root_.Polynomial.X ^ n * coeffPolynomial a := by
  apply _root_.Polynomial.ext
  intro i
  rw [_root_.Polynomial.coeff_X_pow_mul']
  by_cases hin : i < n
  · rw [if_neg (by omega), coeffPolynomial_coeff_lt _ i (by simp; omega),
      Array.getElem_append_left (by simpa using hin), Array.getElem_replicate]
    rfl
  · rw [if_pos (by omega)]
    by_cases hia : i - n < a.size
    · rw [coeffPolynomial_coeff_lt _ i (by simp; omega),
        Array.getElem_append_right (by simp; omega)]
      simpa only [Array.size_replicate] using (coeffPolynomial_coeff_lt a (i-n) hia).symm
    · rw [coeffPolynomial_coeff_ge _ i (by simp; omega),
        coeffPolynomial_coeff_ge a (i-n) (by omega)]

theorem coeffPolynomial_monomial_summand (a : Array Fr) (n : Nat) (r : Fr) :
    coeffPolynomial (Array.replicate n Fr.zero ++ a.map (· * r)) =
      _root_.Polynomial.monomial n r * coeffPolynomial a := by
  rw [coeffPolynomial_prepend_zero, coeffPolynomial_map_mul,
    ← _root_.Polynomial.C_mul_X_pow_eq_monomial]
  ring

private def productStep (a b : Array Fr) (r : Array Fr) (k : Nat) : Array Fr :=
  addPolynomialcoeff r (Array.replicate k Fr.zero ++ b.map (· * a[k]!))

private theorem product_fold_polynomial (a b : Array Fr) (n : Nat) :
    coeffPolynomial ((List.range n).foldl (productStep a b) #[Fr.zero]) =
      (∑ k ∈ Finset.range n, _root_.Polynomial.monomial k a[k]!) * coeffPolynomial b := by
  induction n with
  | zero => simp
  | succ n ih =>
    simp only [List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil,
      productStep, coeffPolynomial_add, coeffPolynomial_monomial_summand,
      Finset.sum_range_succ]
    rw [ih]
    ring

private theorem product_fold_size (a b : Array Fr) (hb : 0 < b.size) (n : Nat) :
    ((List.range n).foldl (productStep a b) #[Fr.zero]).size =
      if n = 0 then 1 else n + b.size - 1 := by
  induction n with
  | zero => simp
  | succ n ih =>
    simp only [List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil,
      productStep, size_addPolynomialcoeff, Array.size_append, Array.size_replicate,
      Array.size_map, ih, Nat.add_eq_zero_iff, Nat.one_ne_zero, and_false, if_false]
    split <;> omega

theorem coeffPolynomial_multiply (a b : Array Fr)
    (ha : 0 < a.size) (hb : 0 < b.size) (hlen : a.size + b.size ≤ 8192) :
    ∃ out, multiplyPolynomialcoeff a b = .ok out ∧
      out.size = a.size + b.size - 1 ∧ coeffPolynomial out = coeffPolynomial a * coeffPolynomial b := by
  let out := (List.range a.size).foldl (productStep a b) #[Fr.zero]
  refine ⟨out, ?_, ?_, ?_⟩
  · simp only [multiplyPolynomialcoeff, Constants.FIELD_ELEMENTS_PER_EXT_BLOB,
      Constants.FIELD_ELEMENTS_PER_BLOB, Nat.reduceMul,
      show ¬ a.size + b.size > 8192 from Nat.not_lt.mpr hlen, if_false,
      Bind.bind, Except.bind, Pure.pure, Except.pure, ← Array.foldl_toList, Array.toList_range]
    rfl
  · simpa only [out, if_neg (by omega : a.size ≠ 0)] using product_fold_size a b hb a.size
  · rw [show out = (List.range a.size).foldl (productStep a b) #[Fr.zero] from rfl,
      product_fold_polynomial, ← coeffPolynomial_sum]

theorem multiply_scalar64 (r : Fr) (a : Array Fr) (ha : a.size = 64) :
    ∃ out, multiplyPolynomialcoeff #[r] a = .ok out ∧
      out.size = 64 ∧ coeffPolynomial out = r • coeffPolynomial a := by
  obtain ⟨out, hcall, hs, hp⟩ := coeffPolynomial_multiply #[r] a (by simp)
    (by omega) (by simp [ha])
  refine ⟨out, hcall, by simpa [ha] using hs, ?_⟩
  simpa only [coeffPolynomial_singleton, _root_.Polynomial.smul_eq_C_mul] using hp

end LeanBlsSimd.Kzg
