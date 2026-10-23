import LeanBlsSimd.Kzg.SetupLiterals
import LeanBlsSimd.Kzg.Fr.Arithmetic
import LeanBlsSimd.Constants
import LeanBlsSimd.Spec.Fp2
import LeanBlsSimd.Spec.PairingEquations
import LeanBlsSimd.Spec.G2Curve
import LeanBlsSimd.Spec.Scott
import LeanBlsSimd.Spec.ScottCardinality
import LeanBlsSimd.Spec.CubicHasse
import LeanBlsSimd.Spec.Sqrt
import LeanBlsSimd.Spec.G2Group
import LeanBlsSimd.Proofs.Pow
import LeanBlsSimd.Proofs.Convert
import LeanBlsSimd.Proofs.Kernel
import LeanBlsSimd.Extracted.Funs
import LeanBlsSimd.Refines.G2x8
import LeanBlsSimd.Refines.DecompressG2
import LeanBlsSimd.Refines.Kernel
import LeanBlsSimd.Refines.Complete
import LeanBlsSimd.Refines.UncompressG1
import LeanBlsSimd.Refines.UncompressG2
import LeanBlsSimd.Kzg
import LeanBlsSimd.Kzg.Routes

/-!
Fails the build if any theorem under `LeanBlsSimd`, or any of `checkedDefinitions`, uses an axiom
outside `propext`, `Classical.choice`, `Quot.sound` and `acceptedAxioms`. `controls/AxiomLog.lean`
lists each one's axioms; it is the source of `axioms.txt`.

An allow-list, because native evaluation enters a proof under more than one name. On Lean v4.29.1
and v4.31.0, `native_decide` and `bv_decide` each add a fresh axiom per use. Their names are
`<theorem>._native.native_decide.ax_…` and `<theorem>._native.bv_decide.ax_…`. A direct
`Lean.ofReduceBool` adds `Lean.ofReduceBool` and `Lean.trustCompiler`.

The check runs Lean's own `CollectAxioms.collect` over all of them with one shared visited set,
which gives the exact union of their axioms and walks Mathlib's shared dependencies once. A union
holding a disallowed axiom fails the check. To name the offenders, it walks that closure's edges
backwards from the disallowed axioms, then collects each one reached separately.
-/

open Lean Elab Command

namespace LeanBlsSimd

/-- The native axioms accepted in the trust base, by exact name. Each entry is a decision to
trust one evaluation, so it belongs next to a note saying why. -/
def acceptedAxioms : List Name := []

/-- Definitions checked with the theorems. Aeneas's library holds `sorry`s, and the generated
entry points must reach none of them. -/
def checkedDefinitions : Array Name := #[``silver_crypto_simd.bls.decompress_g2.decompress,
  ``silver_crypto_simd.bls.uncompress_in_g1, ``silver_crypto_simd.bls.uncompress_in_g2,
  ``silver_crypto_simd.kzg.verify.CellBatchVerifier.new,
  ``silver_crypto_simd.kzg.verify.CellBatchVerifier.verify,
  ``silver_crypto_simd.kzg.verify.CellBatchVerifier.Insts.CoreDefaultDefault.default,
  ``silver_crypto_simd.kzg.cell_extender.CellExtender.new,
  ``silver_crypto_simd.kzg.cell_extender.CellExtender.compute,
  ``silver_crypto_simd.kzg.cell_extender.CellExtender.Insts.CoreDefaultDefault.default,
  ``silver_crypto_simd.kzg.fr8.Fr8.zero,
  ``silver_crypto_simd.kzg.fr8.Fr8.load,
  ``silver_crypto_simd.kzg.fr8.Fr8.splat,
  ``silver_crypto_simd.kzg.fr8.Fr8.transpose,
  ``silver_crypto_simd.kzg.fr8.Fr8.from_bytes,
  ``silver_crypto_simd.kzg.fr8.Fr8.to_bytes,
  ``silver_crypto_simd.kzg.fr8.Fr8.add,
  ``silver_crypto_simd.kzg.fr8.Fr8.sub,
  ``silver_crypto_simd.kzg.fr8.Fr8.mul,
  ``silver_crypto_simd.kzg.fr8.Fr8.canonical,
  ``silver_crypto_simd.kzg.fr8.multiplier,
  ``silver_crypto_simd.bls.fp8.transpose8,
  ``silver_crypto_simd.kzg.fft8.Fft8.new,
  ``silver_crypto_simd.kzg.fft8.Fft8.dit,
  ``silver_crypto_simd.kzg.fft8.Fft8.dif,
  ``silver_crypto_simd.kzg.extension_kernel.ExtensionKernel.new,
  ``silver_crypto_simd.kzg.extension_kernel.ExtensionKernel.decode,
  ``silver_crypto_simd.kzg.extension_kernel.ExtensionKernel.extend,
  ``silver_crypto_simd.kzg.interpolation_kernel.InterpolationKernel.new,
  ``silver_crypto_simd.kzg.interpolation_kernel.InterpolationKernel.check_cell,
  ``silver_crypto_simd.kzg.interpolation_kernel.InterpolationKernel.check,
  ``silver_crypto_simd.kzg.interpolation_kernel.InterpolationKernel.add_cell,
  ``silver_crypto_simd.kzg.interpolation_kernel.InterpolationKernel.add_column,
  ``silver_crypto_simd.kzg.interpolation_kernel.InterpolationKernel.interpolate,
  ``silver_crypto_simd.kzg.interpolation_kernel.store_canonical,
  ``silver_crypto_simd.bls.fp8.Fp8.inverse,
  ``silver_crypto_simd.bls.g1x8.G1x8.infinity,
  ``silver_crypto_simd.bls.g1x8.G1x8.double_complete,
  ``silver_crypto_simd.bls.g1x8.G1x8.add_affine_complete,
  ``silver_crypto_simd.bls.g1x8.G1x8.add_complete,
  ``silver_crypto_simd.bls.g1x8.G1x8.times_two_pow,
  ``silver_crypto_simd.bls.g1x8.G1x8.sum_lanes_shifted,
  ``silver_crypto_simd.bls.msm8.store.PointStore.reset,
  ``silver_crypto_simd.bls.msm8.store.PointStore.push_blst,
  ``silver_crypto_simd.bls.msm8.store.PointStore.load_signed,
  ``silver_crypto_simd.bls.msm8.store.PointStore.store_points,
  ``silver_crypto_simd.bls.msm8.pairs.batch_inverse,
  ``silver_crypto_simd.bls.msm8.pairs.BatchedAdds.run,
  ``silver_crypto_simd.bls.signed_digits.SignedDigits.next_digit,
  ``silver_crypto_simd.bls.msm8.buckets.Buckets.fill,
  ``silver_crypto_simd.bls.msm8.buckets.Buckets.queue_round,
  ``silver_crypto_simd.bls.msm8.buckets.Buckets.sum,
  ``silver_crypto_simd.bls.glv.decompose,
  ``silver_crypto_simd.bls.msm8.Msm8.Insts.CoreDefaultDefault.default,
  ``silver_crypto_simd.bls.msm8.Msm8.chunk_sum,
  ``silver_crypto_simd.bls.msm8.Msm8.msm,
  ``silver_crypto_simd.bls.msm8.lane_zero_in_blst,
  ``silver_crypto_simd.kzg.fr8.Fr8.plain_words,
  ``silver_crypto_simd.kzg.verify.CurveWork.new,
  ``silver_crypto_simd.kzg.verify.CurveWork.sum,
  ``silver_crypto_simd.kzg.fr.fr_add,
  ``silver_crypto_simd.kzg.fr.fr_sub,
  ``silver_crypto_simd.kzg.fr.fr_mul,
  ``silver_crypto_simd.kzg.fr.fr_from_bytes,
  ``silver_crypto_simd.kzg.fr.fr_from_bytes_reduced,
  ``silver_crypto_simd.kzg.fr.fr_to_bytes,
  ``silver_crypto_simd.kzg.fr.fr_to_words,
  ``silver_crypto_simd.sha256.extensions.Sha256.new,
  ``silver_crypto_simd.sha256.extensions.Sha256.update,
  ``silver_crypto_simd.sha256.extensions.Sha256.finish,
  ``silver_crypto_simd.sha256.portable.Sha256.new,
  ``silver_crypto_simd.sha256.portable.Sha256.update,
  ``silver_crypto_simd.sha256.portable.Sha256.finish,
  ``silver_crypto_simd.portable.fp.Fp.add,
  ``silver_crypto_simd.portable.fp.Fp.sub,
  ``silver_crypto_simd.portable.fp.Fp.mul,
  ``silver_crypto_simd.portable.fp.Fp.mul_on_baseline,
  ``silver_crypto_simd.portable.fp.Fp.mul_on_bmi2,
  ``silver_crypto_simd.portable.fp.Fp.is_zero,
  ``silver_crypto_simd.portable.g1.G1.from_blst,
  ``silver_crypto_simd.portable.g1.G1.to_blst,
  ``silver_crypto_simd.portable.g1.G1.neg,
  ``silver_crypto_simd.portable.g1.G1.add_complete,
  ``silver_crypto_simd.portable.decompress.uncompress_in_g1,
  ``silver_crypto_simd.portable.decompress.uncompress_pair_in_g1,
  ``silver_crypto_simd.portable.msm.Msm.msm,
  ``silver_crypto_simd.portable.pairing.PairingLines.new,
  ``silver_crypto_simd.portable.pairing.PairingLines.pairing_check,
  ``silver_crypto_simd.bls.pairing.MillerLines.pairing_check,
  ``silver_crypto_simd.kzg.verify.CurveWork.portable,
  ``silver_crypto_simd.kzg.verify.CurveWork.pairing_check,
  ``silver_crypto_simd.kzg.verify.PairingSums.points,
  ``silver_crypto_simd.kzg.verify.PairingSums.points_in_lanes,
  ``silver_crypto_simd.kzg.verify.two_lanes]

def libraryTheorems : CommandElabM (Array Name) := do
  let theorems := (← getEnv).constants.fold (init := #[]) fun found c info =>
    if (`LeanBlsSimd).isPrefixOf c && !c.isInternal && info matches .thmInfo _ then
      found.push c
    else found
  if theorems.isEmpty then throwError "no theorems under LeanBlsSimd"
  return theorems.qsort (·.toString < ·.toString)

/-- The constants `CollectAxioms.collect` visits from `c`. -/
def collectDeps (env : Environment) (c : Name) : Array Name :=
  let used (e : Expr) := e.getUsedConstants
  match env.checked.get.find? c with
  | some (.axiomInfo v) => used v.type
  | some (.defnInfo v) => used v.type ++ used v.value
  | some (.thmInfo v) => used v.type ++ used v.value
  | some (.opaqueInfo v) => used v.type ++ used v.value
  | some (.ctorInfo v) => used v.type
  | some (.recInfo v) => used v.type
  | some (.inductInfo v) => used v.type ++ v.ctors.toArray
  | _ => #[]

/-- The constants of `visited` from which `collect` reaches one of `targets`, found by walking
the dependency edges backwards. Exact on cycles, unlike a per-constant cache. -/
def reaching (env : Environment) (visited : NameSet) (targets : Array Name) : NameSet := Id.run do
  let mut users : NameMap (Array Name) := {}
  for c in visited do
    for d in collectDeps env c do
      users := users.insert d (((users.get? d).getD #[]).push c)
  let mut found : NameSet := {}
  let mut todo := targets
  while h : todo.size > 0 do
    let c := todo[todo.size - 1]
    todo := todo.pop
    unless found.contains c do
      found := found.insert c
      todo := todo ++ (users.get? c).getD #[]
  return found

/-- Fails unless every checked constant uses only the standard axioms and `accepted`. -/
def checkAxioms (accepted : List Name) : CommandElabM Unit := do
  let allowed := [``propext, ``Classical.choice, ``Quot.sound] ++ accepted
  let theorems ← libraryTheorems
  let checked := theorems ++ checkedDefinitions
  let env ← getEnv
  let (_, union) := ((checked.forM CollectAxioms.collect).run env).run {}
  if union.axioms.all allowed.contains then
    logInfo m!"{theorems.size} theorems and {checkedDefinitions.toList}; \
      axioms used: {union.axioms.toList}"
    return
  let disallowed := union.axioms.filter (!allowed.contains ·)
  let suspects := reaching env union.visited disallowed
  let mut offenders := #[]
  for c in checked.filter suspects.contains do
    let extra := (← collectAxioms c).filter (!allowed.contains ·)
    unless extra.isEmpty do offenders := offenders.push m!"{c} depends on {extra.toList}"
  if offenders.isEmpty then
    throwError m!"no checked constant found to reach the disallowed axioms {disallowed.toList}"
  throwError MessageData.joinSep offenders.toList "\n"

def logAxioms : CommandElabM Unit := do
  for c in (← libraryTheorems) ++ checkedDefinitions do
    logInfo m!"{c}: {(← collectAxioms c).toList}"

elab "#assert_standard_axioms" : command => checkAxioms acceptedAxioms

elab "#log_axioms" : command => logAxioms

end LeanBlsSimd

#assert_standard_axioms
