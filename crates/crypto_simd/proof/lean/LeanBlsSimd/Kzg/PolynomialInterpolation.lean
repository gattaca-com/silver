import LeanBlsSimd.Kzg.PolynomialArithmetic

open EthLib.Cryptography Bls Kzg
open scoped EthLib.Cryptography.Bls.Fr BigOperators

namespace LeanBlsSimd.Kzg.PolynomialInterpolation

set_option maxHeartbeats 3000000
set_option maxRecDepth 2000

private def innerStep (xs : Array Fr) (i : Nat) (summand : Array Fr) (j : Nat) :
    Except KzgError (Array Fr) :=
  if j ≠ i then
    let w := (xs[i]! - xs[j]!).inverse
    multiplyPolynomialcoeff summand #[(-w) * xs[j]!, w]
  else pure summand

private noncomputable def basisProduct (xs : Array Fr) (i n : Nat) : _root_.Polynomial Fr :=
  ∏ j ∈ Finset.range n,
    if j = i then 1 else Lagrange.basisDivisor xs[i]! xs[j]!

private theorem factor_identity {F : Type*} [Field F] (x y : F) :
    _root_.Polynomial.C (-(x-y)⁻¹ * y) +
        _root_.Polynomial.C ((x-y)⁻¹) * _root_.Polynomial.X = Lagrange.basisDivisor x y := by
  simp only [Lagrange.basisDivisor, map_mul, map_neg]
  ring

private theorem factor_polynomial (x y : Fr) :
    coeffPolynomial #[(-(x-y).inverse) * y, (x-y).inverse] = Lagrange.basisDivisor x y := by
  rw [coeffPolynomial_pair, Fr.inverse_eq_inv]
  exact factor_identity x y

private theorem inner_prefix (xs : Array Fr) (value : Fr) (i : Nat)
    (n : Nat) (hn : n ≤ 64) :
    ∃ out, (List.range n).foldlM (innerStep xs i) #[value] = .ok out ∧
      out.size = (if i < n then n else n+1) ∧
      coeffPolynomial out = _root_.Polynomial.C value * basisProduct xs i n := by
  induction n with
  | zero =>
    refine ⟨#[value], rfl, by simp, ?_⟩
    simp [basisProduct]
  | succ n ih =>
    obtain ⟨current, hcurrent, hsize, hpoly⟩ := ih (by omega)
    have hpos : 0 < current.size := by rw [hsize]; split <;> omega
    have hbound : current.size + 2 ≤ 8192 := by rw [hsize]; split <;> omega
    by_cases hni : n = i
    · refine ⟨current, ?_, ?_, ?_⟩
      · rw [List.range_succ, List.foldlM_append, hcurrent]
        simp [List.foldlM_cons, List.foldlM_nil, innerStep, hni]
      · rw [hsize]
        simp [hni]
      · rw [hpoly]
        simp [basisProduct, Finset.prod_range_succ, hni]
    · obtain ⟨out, hcall, houtsize, houtpoly⟩ := coeffPolynomial_multiply current
        #[(-(xs[i]! - xs[n]!).inverse) * xs[n]!, (xs[i]! - xs[n]!).inverse]
        hpos (by simp) (by simpa using hbound)
      refine ⟨out, ?_, ?_, ?_⟩
      · rw [List.range_succ, List.foldlM_append, hcurrent]
        simp only [Bind.bind, Except.bind, List.foldlM_cons, innerStep, ne_eq, hni,
          not_false_eq_true, if_true, hcall, List.foldlM_nil, Pure.pure, Except.pure]
      · change out.size = current.size + 2 - 1 at houtsize
        rw [houtsize, hsize]
        split <;> split <;> omega
      · rw [houtpoly, hpoly, factor_polynomial]
        simp only [basisProduct, Finset.prod_range_succ, hni, if_false]
        ring

private theorem basisProduct_eq (xs : Array Fr) (i : Fin 64) :
    basisProduct xs i.val 64 =
      Lagrange.basis Finset.univ (fun j : Fin 64 => xs[j.val]!) i := by
  unfold basisProduct
  rw [Finset.prod_range]
  rw [Lagrange.basis]
  let f := fun j : Fin 64 =>
    if j.val = i.val then (1 : _root_.Polynomial Fr)
    else Lagrange.basisDivisor xs[i.val]! xs[j.val]!
  change (∏ j : Fin 64, f j) = _
  rw [← Finset.prod_erase Finset.univ (f := f) (a := i) (by simp [f])]
  apply Finset.prod_congr rfl
  intro j hj
  have hji : j.val ≠ i.val := by
    intro he
    exact (Finset.mem_erase.mp hj).1 (Fin.ext he)
  simp only [f, hji, if_false]

private def outerStep (xs ys : Array Fr) (acc : Array Fr) (i : Nat) :
    Except KzgError (Array Fr) := do
  let summand ← (List.range 64).foldlM (innerStep xs i) #[ys[i]!]
  pure (addPolynomialcoeff acc summand)

private theorem outer_prefix (xs ys : Array Fr) (n : Nat) (hn : n ≤ 64) :
    ∃ out, (List.range n).foldlM (outerStep xs ys) #[Fr.zero] = .ok out ∧
      out.size = (if n = 0 then 1 else 64) ∧
      coeffPolynomial out = ∑ i ∈ Finset.range n,
        _root_.Polynomial.C ys[i]! * basisProduct xs i 64 := by
  induction n with
  | zero => exact ⟨#[Fr.zero], rfl, rfl, by simp⟩
  | succ n ih =>
    obtain ⟨current, hcurrent, hsize, hpoly⟩ := ih (by omega)
    obtain ⟨summand, hsummand, hssize, hspoly⟩ := inner_prefix xs ys[n]! n 64 (by omega)
    have hssize' : summand.size = 64 := by simpa only [if_pos (by omega : n < 64)] using hssize
    refine ⟨addPolynomialcoeff current summand, ?_, ?_, ?_⟩
    · rw [List.range_succ, List.foldlM_append, hcurrent]
      simp only [Bind.bind, Except.bind, List.foldlM_cons, outerStep, hsummand,
        List.foldlM_nil, Pure.pure, Except.pure]
    · rw [size_addPolynomialcoeff, hsize, hssize']
      split <;> simp_all
    · rw [coeffPolynomial_add, hpoly, hspoly, Finset.sum_range_succ]

end LeanBlsSimd.Kzg.PolynomialInterpolation

namespace LeanBlsSimd.Kzg

theorem interpolatePolynomialcoeff_eq (xs ys : Array Fr)
    (hxs : xs.size = 64) (hys : ys.size = 64) :
    ∃ out, interpolatePolynomialcoeff xs ys = .ok out ∧ out.size = 64 ∧
      coeffPolynomial out = Lagrange.interpolate Finset.univ
        (fun i : Fin 64 => xs[i.val]!) (fun i : Fin 64 => ys[i.val]!) := by
  obtain ⟨out, hcall, hsize, hpoly⟩ := PolynomialInterpolation.outer_prefix xs ys 64 (by omega)
  refine ⟨out, ?_, by simpa using hsize, ?_⟩
  · simpa only [interpolatePolynomialcoeff, hxs, hys, ne_eq, not_true_eq_false,
      if_false, Bind.bind, Except.bind, Pure.pure, Except.pure, ← Array.foldlM_toList,
      Array.toList_range, PolynomialInterpolation.outerStep,
      PolynomialInterpolation.innerStep] using hcall
  · rw [hpoly, Lagrange.interpolate_apply, Finset.sum_range]
    apply Finset.sum_congr rfl
    intro i _
    rw [PolynomialInterpolation.basisProduct_eq xs i]

end LeanBlsSimd.Kzg
