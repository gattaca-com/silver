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

end LeanBlsSimd.Controls.KzgRuntimeBoundary
