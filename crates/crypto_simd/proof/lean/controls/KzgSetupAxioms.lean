import LeanBlsSimd.Kzg.Setup

open Lean Elab Command

run_cmd do
  let allowed := [``propext, ``Classical.choice, ``Quot.sound]
  for c in #[``LeanBlsSimd.Kzg.SetupPoints.g1_decoded, ``LeanBlsSimd.Kzg.SetupPoints.g1_subgroup,
      ``LeanBlsSimd.Kzg.SetupPoints.g1_finite, ``LeanBlsSimd.Kzg.SetupPoints.g2_0_decoded,
      ``LeanBlsSimd.Kzg.SetupPoints.g2_0_subgroup, ``LeanBlsSimd.Kzg.SetupPoints.g2_64_decoded,
      ``LeanBlsSimd.Kzg.SetupPoints.g2_64_subgroup, ``LeanBlsSimd.Kzg.embedded_setup_matches] do
    let axioms ← collectAxioms c
    unless axioms.all allowed.contains do
      throwError m!"{c} has unexpected axioms: {axioms.toList}"
    logInfo m!"{c}: {axioms.toList}"
