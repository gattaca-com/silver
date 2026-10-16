import LeanBlsSimd.Kzg.InterpolationIdentity
import LeanBlsSimd.Kzg.ModelSpec

open Lean Elab Command

run_cmd do
  let allowed := [``propext, ``Classical.choice, ``Quot.sound]
  for c in #[``LeanBlsSimd.Kzg.coeffPolynomial_coeff, ``LeanBlsSimd.Kzg.coeffPolynomial_injective,
      ``LeanBlsSimd.Kzg.coeffPolynomial_degree_lt_size, ``LeanBlsSimd.Kzg.coeffPolynomial_eval,
      ``LeanBlsSimd.Kzg.coeffPolynomial_add, ``LeanBlsSimd.Kzg.coeffPolynomial_multiply,
      ``LeanBlsSimd.Kzg.multiply_scalar64, ``LeanBlsSimd.Kzg.interpolatePolynomialcoeff_eq,
      ``LeanBlsSimd.Kzg.cellNode_layout, ``LeanBlsSimd.Kzg.cellNodes_injective,
      ``LeanBlsSimd.Kzg.cosetForCell_eq, ``LeanBlsSimd.Kzg.cellIfft_eval,
      ``LeanBlsSimd.Kzg.cellIfft_interpolant, ``LeanBlsSimd.Kzg.columnValues_get,
      ``LeanBlsSimd.Kzg.columnRli_polynomial, ``LeanBlsSimd.Kzg.specRli_polynomial,
      ``LeanBlsSimd.Kzg.columnRli_size, ``LeanBlsSimd.Kzg.column_ifft_interpolation,
      ``LeanBlsSimd.Kzg.ModelSpec.frontHalf_rli_inputs,
      ``LeanBlsSimd.Kzg.ModelSpec.verifyPure_spec_eq_column,
      ``LeanBlsSimd.Kzg.ModelSpec.verifyWith_spec_eq_column,
      ``LeanBlsSimd.Kzg.ModelSpec.upstream_spec_eq_column,
      ``LeanBlsSimd.Kzg.ModelSpec.rejectErrors_spec_eq_model] do
    let axioms ← collectAxioms c
    unless axioms.all allowed.contains do
      throwError m!"{c} has unexpected axioms: {axioms.toList}"
    logInfo m!"{c}: {axioms.toList}"
