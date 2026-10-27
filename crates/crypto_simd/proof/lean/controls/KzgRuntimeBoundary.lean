import LeanBlsSimd.Axioms

open Lean Elab Command

namespace LeanBlsSimd.Controls.KzgRuntimeBoundary

private def dependencies (env : Environment) (roots : Array Name) : NameSet := Id.run do
  let mut visited : NameSet := {}
  let mut todo := roots
  while h : todo.size > 0 do
    let declName := todo[todo.size - 1]
    todo := todo.pop
    unless visited.contains declName do
      visited := visited.insert declName
      todo := todo ++ LeanBlsSimd.collectDeps env declName
  return visited

run_cmd do
  let roots := #[
    ``LeanBlsSimd.Kzg.verify_eq_spec,
    ``LeanBlsSimd.Kzg.verify_eq_upstream,
    ``LeanBlsSimd.Kzg.new_returns_ok,
    ``LeanBlsSimd.Kzg.new_returns_ok_route,
    ``LeanBlsSimd.Kzg.Extender.new_returns_ok,
    ``LeanBlsSimd.Kzg.Extender.compute_eq_spec,
    ``silver_crypto_simd.kzg.verify.CellBatchVerifier.new,
    ``silver_crypto_simd.kzg.verify.CellBatchVerifier.verify,
    ``silver_crypto_simd.kzg.verify.CellBatchVerifier.Insts.CoreDefaultDefault.default,
    ``silver_crypto_simd.kzg.cell_extender.CellExtender.new,
    ``silver_crypto_simd.kzg.cell_extender.CellExtender.compute,
    ``silver_crypto_simd.kzg.cell_extender.CellExtender.Insts.CoreDefaultDefault.default]
  let forbidden := #[``silver_crypto_simd.bls.BlsExternals,
    ``silver_crypto_simd.bls.BlsExternals.uncompressG2,
    ``silver_crypto_simd.bls.uncompress_in_g2_blst]
  let env ← getEnv
  let used := dependencies env roots
  for declName in forbidden do
    if used.contains declName then
      throwError "KZG dependency closure reaches signature-only external {declName}"
  let signature := dependencies env #[``silver_crypto_simd.bls.uncompress_in_g2]
  unless signature.contains ``silver_crypto_simd.bls.uncompress_in_g2_blst do
    throwError "signature-path control no longer reaches the opaque G2 decoder"
  logInfo m!"{roots.size} KZG headlines and runtime entry points exclude the opaque G2 decoder; \
    signature-path control reaches it"

private def requireIndependent (root : Name) : CommandElabM Unit := do
  let env ← getEnv
  let laws := #[``LeanBlsSimd.UncompressG1.FallbackCorrect,
    ``LeanBlsSimd.UncompressG1.BlstMatchesSpec,
    ``LeanBlsSimd.Kzg.BlstPairing.Correct,
    ``LeanBlsSimd.Kzg.BlstPairing.CorrectFor,
    ``LeanBlsSimd.Kzg.BlstPairing.BlstMatchesSpec]
  let used := dependencies env (← getConstInfo root).type.getUsedConstants
  for law in laws do
    if used.contains law then
      throwError "headline type requires a blst correctness law"

run_cmd do
  let roots := #[``LeanBlsSimd.Kzg.verify_eq_spec_ifma,
    ``LeanBlsSimd.Kzg.verify_eq_upstream_ifma,
    ``LeanBlsSimd.UncompressG1.uncompress_in_g1_eq_spec_list_ifma,
    ``LeanBlsSimd.Kzg.Extender.new_returns_ok,
    ``LeanBlsSimd.Kzg.Extender.compute_eq_spec]
  for root in roots do
    requireIndependent root
  logInfo "IFMA verifier and G1 headlines, and both extender routes, require no blst laws"

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.kzg
open LeanBlsSimd LeanBlsSimd.Kzg

/-- Every invariant state is admitted, with a route-scoped premise and a preserved route. -/
example [cpu : RuntimeFeatures] [KzgExternals] [UncompressG1.FallbackCorrect] :
    ∃ initial, verify.CellBatchVerifier.new = ok initial ∧ StateInvariant initial ∧
      ∀ v : verify.CellBatchVerifier, StateInvariant v →
      BlstPairing.CorrectFor v.curve_work → ∀ i : Input, i.Representable →
      ∃ verdict next, i.generated v = ok (verdict, next) ∧ StateInvariant next ∧
        CurveWork.isLanes next.curve_work = CurveWork.isLanes v.curve_work ∧
        Model.rejectErrors i.embeddedSpec = verdict := verify_eq_spec

private theorem decoderPremiseMutation [silver_crypto_simd.KzgExternals]
    (h : LeanBlsSimd.UncompressG1.BlstMatchesSpec) : LeanBlsSimd.UncompressG1.BlstMatchesSpec := h

/-- error: headline type requires a blst correctness law -/
#guard_msgs in
run_cmd requireIndependent ``decoderPremiseMutation

private theorem pairingPremiseMutation [silver_crypto_simd.KzgExternals]
    (h : LeanBlsSimd.Kzg.BlstPairing.BlstMatchesSpec) : LeanBlsSimd.Kzg.BlstPairing.BlstMatchesSpec := h

/-- error: headline type requires a blst correctness law -/
#guard_msgs in
run_cmd requireIndependent ``pairingPremiseMutation

end LeanBlsSimd.Controls.KzgRuntimeBoundary
