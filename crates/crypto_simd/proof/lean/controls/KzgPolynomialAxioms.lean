import LeanBlsSimd.Kzg.InterpolationIdentity
import LeanBlsSimd.Kzg.ModelSpec

open Lean Elab Command

run_cmd do
  let allowed := [``propext, ``Classical.choice, ``Quot.sound]
  for c in #[``LeanBlsSimd.Kzg.coefficientPolynomial_injective,
      ``LeanBlsSimd.Kzg.coefficientPolynomial_add, ``LeanBlsSimd.Kzg.cellNodes_injective,
      ``LeanBlsSimd.Kzg.cosetForCell_eq, ``LeanBlsSimd.Kzg.cellIfft_eval,
      ``LeanBlsSimd.Kzg.cellIfft_interpolant, ``LeanBlsSimd.Kzg.columnValues_get,
      ``LeanBlsSimd.Kzg.columnRli_polynomial, ``LeanBlsSimd.Kzg.specRli_polynomial,
      ``LeanBlsSimd.Kzg.columnRli_size, ``LeanBlsSimd.Kzg.interpolateCosetEvals_eq_cellIfft,
      ``LeanBlsSimd.Kzg.ModelSpec.shiftOf_ok, ``LeanBlsSimd.Kzg.ModelSpec.mapM_shiftOf,
      ``LeanBlsSimd.Kzg.ModelSpec.verifyPure_spec_eq_column,
      ``LeanBlsSimd.Kzg.ModelSpec.rejectErrors_spec_eq_model] do
    let axioms ← collectAxioms c
    unless axioms.all allowed.contains do
      throwError m!"{c} has unexpected axioms: {axioms.toList}"
    logInfo m!"{c}: {axioms.toList}"
