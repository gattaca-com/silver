import LeanBlsSimd.Kzg.SpecBridge

open Lean Elab Command

run_cmd do
  let allowed := [``propext, ``Classical.choice, ``Quot.sound]
  for c in #[``LeanBlsSimd.Kzg.estLawful, ``LeanBlsSimd.Kzg.ioLawful,
      ``LeanBlsSimd.Kzg.g1Lincomb_eq, ``LeanBlsSimd.Kzg.verifyWith_pure,
      ``LeanBlsSimd.Kzg.front_decomposition, ``LeanBlsSimd.Kzg.impl_decomposition,
      ``LeanBlsSimd.Kzg.upstream_eq_verifyWith] do
    let axioms ← collectAxioms c
    unless axioms.all allowed.contains do
      throwError m!"{c} has unexpected axioms: {axioms.toList}"
    logInfo m!"{c}: {axioms.toList}"
