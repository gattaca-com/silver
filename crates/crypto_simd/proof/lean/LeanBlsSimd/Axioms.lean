import LeanBlsSimd.Pairing.LaneFinal
import LeanBlsSimd.Pairing.LaneMiller
import LeanBlsSimd.LaneTower.Frobenius
import LeanBlsSimd.LaneTower.LineCoordinates
import LeanBlsSimd.LaneTower.CyclotomicCoordinates
import LeanBlsSimd.LaneTower.Identity
import LeanBlsSimd.Spec.PairingProduct
import LeanBlsSimd.Spec.Cyclotomic.Field
import LeanBlsSimd.Refines.FrobeniusConstants
import LeanBlsSimd.Portable.Msm.Refines
import LeanBlsSimd.Portable.Msm.Sum
import LeanBlsSimd.Portable.Msm.Initialise
import LeanBlsSimd.Portable.Msm.Input
import LeanBlsSimd.Portable.Msm.PairRounds
import LeanBlsSimd.Portable.Msm.Queue
import LeanBlsSimd.Portable.Msm.BatchRun
import LeanBlsSimd.Portable.Msm.StoreLifecycle
import LeanBlsSimd.Portable.Msm.FillReady
import LeanBlsSimd.Portable.Decode.Correct
import LeanBlsSimd.Portable.G1.PairScott
import LeanBlsSimd.Portable.G1.Scott
import LeanBlsSimd.Portable.Fp.BatchInverse
import LeanBlsSimd.Portable.Fp.Sqrt
import LeanBlsSimd.Portable.Fp.PairSqrt
import LeanBlsSimd.Portable.Fp.Correct
import LeanBlsSimd.Portable.Fp.Reduction
import LeanBlsSimd.Portable.Fp.MultiplyAdd
import LeanBlsSimd.Portable.Fp.Words
import LeanBlsSimd.Sha256.Correct
import LeanBlsSimd.Sha256.GeneratedUpdateRefines
import LeanBlsSimd.Sha256.ExtensionCompress
import LeanBlsSimd.Sha256.ExtensionLoad
import LeanBlsSimd.Sha256.ExtensionLayout
import LeanBlsSimd.Sha256.ExtensionSchedule
import LeanBlsSimd.Sha256.PortableCompress
import LeanBlsSimd.Sha256.ContractAdapter
import LeanBlsSimd.Sha256.Streaming
import LeanBlsSimd.Spec.Sha256
import LeanBlsSimd.Kzg.SetupLiterals
import LeanBlsSimd.Kzg.Fr.ByteEncode
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
import LeanBlsSimd.Refines.CheckedPoints
import LeanBlsSimd.Refines.PointOperations
import LeanBlsSimd.PairingProduct.Headline
import LeanBlsSimd.Kzg
import LeanBlsSimd.Kzg.Routes

/-!
Fails the build if any theorem under `LeanBlsSimd`, or any of `checkedDefinitions`, uses an axiom
outside `propext`, `Classical.choice`, `Quot.sound` and `acceptedAxioms`.
`controls/AxiomLog.lean` prints Lean's recorded lists for public library theorems and checked definitions.

An allow-list, because native evaluation enters a proof under a fresh name per use.
`native_decide` and `bv_decide` each add an axiom named `<theorem>._native.native_decide.ax_…` or
`<theorem>._native.bv_decide.ax_…`.

The guard walks Silver's kernel types, values and inductive constructors with a visited set.
Ownership follows the defining module, including private helpers and exposed generated code.
Foreign constants contribute Lean's exported per-declaration axiom lists.
A separate per-theorem `collectAxioms` check remains active.
Cycles entirely inside a foreign dependency remain subject to Lean's exported-list omissions.
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
  ``silver_crypto_simd.bls.g1_point.G1Point.from_blst,
  ``silver_crypto_simd.bls.g2_point.G2Point.from_blst,
  ``silver_crypto_simd.bls.g1_point.G1Point.from_trusted,
  ``silver_crypto_simd.bls.g2_point.G2Point.from_trusted,
  ``silver_crypto_simd.bls.g1_point.G1Point.as_blst,
  ``silver_crypto_simd.bls.g2_point.G2Point.as_blst,
  ``silver_crypto_simd.bls.g1_point.G1Point.into_blst,
  ``silver_crypto_simd.bls.g2_point.G2Point.into_blst,
  ``silver_crypto_simd.bls.g1_point.G1Point.negative_generator,
  ``silver_crypto_simd.bls.g1_point.G1Point.weighted_sum,
  ``silver_crypto_simd.bls.g2_point.G2Point.weighted_sum,
  ``silver_crypto_simd.bls.g2_point.G2Point.hash_to_curve,
  ``silver_crypto_simd.bls.pairing_product.PairingProduct.Insts.CoreDefaultDefault.default,
  ``silver_crypto_simd.bls.pairing_product.PairingProduct.with_capacity,
  ``silver_crypto_simd.bls.pairing_product.PairingProduct.push,
  ``silver_crypto_simd.bls.pairing_product.PairingProduct.clear,
  ``silver_crypto_simd.bls.pairing_product.PairingProduct.is_one,
  ``silver_crypto_simd.bls.pairing_product.PairingProduct.two_pairs_are_one,
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
  ``silver_crypto_simd.bls.pairing.MillerLines.pairing_check,
  ``silver_crypto_simd.kzg.verify.CurveWork.scalar,
  ``silver_crypto_simd.kzg.verify.CurveWork.pairing_check,
  ``silver_crypto_simd.kzg.blst_pairing.pairing_check,
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

/-- Fails unless every checked constant uses only the standard axioms and `accepted`. -/
def checkAxioms (accepted : List Name) : CommandElabM Unit := do
  let allowed := [``propext, ``Classical.choice, ``Quot.sound] ++ accepted
  let theorems ← libraryTheorems
  let mut union : NameSet := {}
  let mut offenders := #[]
  for c in theorems ++ checkedDefinitions do
    let axioms ← collectAxioms c
    union := axioms.foldl NameSet.insert union
    let extra := axioms.filter (!allowed.contains ·)
    unless extra.isEmpty do offenders := offenders.push m!"{c} depends on {extra.toList}"
  unless offenders.isEmpty do throwError MessageData.joinSep offenders.toList "\n"
  logInfo m!"{theorems.size} theorems and {checkedDefinitions.toList}; \
    axioms used: {union.toList}"

/-- Defining modules distinguish package constants from foreign declarations, including private names. -/
def isSilverModule (m : Name) : Bool :=
  (`LeanBlsSimd).isPrefixOf m || (`controls).isPrefixOf m ||
    (`Differential).isPrefixOf m || (`Test).isPrefixOf m

def definingModule (env : Environment) (c : Name) : Name :=
  match env.getModuleIdxFor? c with
  | some i => env.header.modules[i.toNat]!.module
  | none => env.header.mainModule

/-- Authored private theorems are roots alongside the public library theorems. -/
def guardTheorems : CommandElabM (Array Name) := do
  let env ← getEnv
  let publicTheorems ← libraryTheorems
  let roots := env.constants.fold (init := publicTheorems.foldl NameSet.insert {}) fun found c info =>
    if (`LeanBlsSimd).isPrefixOf (definingModule env c) &&
        !(privateToUserName c).isInternal && info matches .thmInfo _ then
      found.insert c
    else found
  return roots.toArray.qsort (fun a b => a.toString < b.toString)

/-- Direct kernel dependencies include the constructors of every named inductive type. -/
def silverDependencies (env : Environment) (c : Name) : CommandElabM (Array Name) := do
  match env.checked.get.find? c with
  | some (.axiomInfo v) => return v.type.getUsedConstants
  | some (.defnInfo v) => return v.type.getUsedConstants ++ v.value.getUsedConstants
  | some (.thmInfo v) => return v.type.getUsedConstants ++ v.value.getUsedConstants
  | some (.opaqueInfo v) => return v.type.getUsedConstants ++ v.value.getUsedConstants
  | some (.ctorInfo v) => return v.type.getUsedConstants
  | some (.recInfo v) => return v.type.getUsedConstants
  | some (.inductInfo v) => return v.type.getUsedConstants ++ v.ctors.toArray
  | some (.quotInfo _) => return #[]
  | none => throwError m!"missing Silver declaration {c} (module {definingModule env c})"

/-- Walk Silver bodies without per-constant axiom caches; foreign edges use Lean's recorded lists. -/
def collectSilverAxioms (roots : Array Name) : CommandElabM (NameSet × NameSet) := do
  let env ← getEnv
  let mut visited : NameSet := {}
  let mut axioms : NameSet := {}
  let mut todo := roots
  while !todo.isEmpty do
    let c := todo.back!
    todo := todo.pop
    unless visited.contains c do
      visited := visited.insert c
      if isSilverModule (definingModule env c) then
        if let some (.axiomInfo _) := env.checked.get.find? c then
          axioms := axioms.insert c
        todo := todo ++ (← silverDependencies env c)
      else
        axioms := (← collectAxioms c).foldl NameSet.insert axioms
  return (axioms, visited)

/-- Reverse complete dependency edges to name offenders without memoizing partial cycle results. -/
def silverOffenders (roots : Array Name) (visited : NameSet) (extra : Array Name) :
    CommandElabM (Array MessageData) := do
  let env ← getEnv
  let mut users : NameMap (Array Name) := {}
  for c in visited do
    let deps ← if isSilverModule (definingModule env c) then
        silverDependencies env c
      else collectAxioms c
    for d in deps do
      users := users.insert d (((users.find? d).getD #[]).push c)
  let mut offenders : NameMap (Array Name) := {}
  let rootSet := roots.foldl NameSet.insert {}
  for ax in extra do
    let mut seen : NameSet := {}
    let mut todo := #[ax]
    while !todo.isEmpty do
      let c := todo.back!
      todo := todo.pop
      unless seen.contains c do
        seen := seen.insert c
        if rootSet.contains c then
          offenders := offenders.insert c (((offenders.find? c).getD #[]).push ax)
        todo := todo ++ (users.find? c).getD #[]
  return roots.filterMap fun c =>
    (offenders.find? c).map fun axs => m!"{c} depends on {axs.toList}"

/-- Reject every disallowed axiom reachable through Silver bodies and foreign boundary lists. -/
def checkSilverAxioms (accepted : List Name) : CommandElabM Unit := do
  let start ← IO.monoMsNow
  let roots := (← guardTheorems) ++ checkedDefinitions
  let (axioms, visited) ← collectSilverAxioms roots
  let allowed := [``propext, ``Classical.choice, ``Quot.sound] ++ accepted
  let extra := (axioms.toArray.filter (!allowed.contains ·)).qsort
    (fun a b => a.toString < b.toString)
  unless extra.isEmpty do
    let offenders ← silverOffenders roots visited extra
    if offenders.isEmpty then throwError m!"reachable disallowed axioms: {extra.toList}"
    throwError MessageData.joinSep offenders.toList "\n"
  logInfo m!"Silver axiom walk: {roots.size} roots, {visited.size} visited; \
    axioms used: {axioms.toList}; elapsed {(← IO.monoMsNow) - start} ms"

/-- Both the direct Silver walk and the existing per-theorem check must accept. -/
def assertAxioms (accepted : List Name) : CommandElabM Unit := do
  checkSilverAxioms accepted
  checkAxioms accepted

def logAxioms : CommandElabM Unit := do
  for c in (← libraryTheorems) ++ checkedDefinitions do
    logInfo m!"{c}: {(← collectAxioms c).toList}"

elab "#assert_standard_axioms" : command => assertAxioms acceptedAxioms

elab "#log_axioms" : command => logAxioms

end LeanBlsSimd

#assert_standard_axioms
