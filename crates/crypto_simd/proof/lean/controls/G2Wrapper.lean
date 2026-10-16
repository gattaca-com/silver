import LeanBlsSimd.Refines.UncompressG2

/-! Routing mutations use an arbitrary scalar result to make wrong routes observable.
The valid-kernel mutation is a runtime control; the other examples are kernel-checked proofs.
These controls do not establish the universal premise for the C blst implementation. -/

namespace LeanBlsSimd.G2WrapperControls

open DecompressG2 UncompressG2

def rejected : Encoding := .replicate 96 0

def sentinel : BlstP2Affine :=
  point (.replicate 6 1) (.replicate 6 2) (.replicate 6 3) (.replicate 6 4)

def fallback (_ : Encoding) : Option BlstP2Affine := some sentinel

def uncompressWith (threshold : ℕ) (ignoreUndecided rejectValid simd : Bool)
    (blst : Encoding → Option BlstP2Affine) (inputs : List Encoding) : List (Option BlstP2Affine) :=
  (List.range inputs.length).map fun i =>
    let batch := decompress (chunkAt inputs i)
    if simd && decide (i < inputs.length ∧ threshold ≤ chunkLength inputs i) &&
        (ignoreUndecided || !batch.undecided.toNat.testBit (i % 8)) then
      if batch.valid.toNat.testBit (i % 8) && !rejectValid then some batch.points[i % 8]! else none
    else blst inputs[i]!

example : uncompressWith 3 false false = uncompress := by
  funext simd blst inputs
  simp [uncompressWith, uncompress, usesKernel]

-- A forced SIMD route changes the arbitrary scalar result on a decided rejected input.
example : (uncompress false fallback [rejected, rejected, rejected]).map Option.isSome ≠
    (uncompress true fallback [rejected, rejected, rejected]).map Option.isSome := by decide +kernel

-- Lowering or raising the threshold changes the result at the boundary.
example : (uncompress true fallback [rejected, rejected]).map Option.isSome ≠
    (uncompressWith 2 false false true fallback [rejected, rejected]).map Option.isSome := by decide +kernel

example : (uncompress true fallback [rejected, rejected, rejected]).map Option.isSome ≠
    (uncompressWith 4 false false true fallback [rejected, rejected, rejected]).map Option.isSome := by decide +kernel

example : (uncompress true fallback (List.replicate 7 rejected)).map Option.isSome ≠
    (uncompressWith 8 false false true fallback (List.replicate 7 rejected)).map Option.isSome := by decide +kernel

-- Infinity is undecided, so ignoring that mask loses the scalar verdict.
example : (uncompress true fallback (List.replicate 3 G2Spec.infinity)).map Option.isSome ≠
    (uncompressWith 3 true false true fallback (List.replicate 3 G2Spec.infinity)).map Option.isSome := by decide +kernel

example : G2Spec.verdict G2Spec.infinity = some
    (point (.replicate 6 0) (.replicate 6 0) (.replicate 6 0) (.replicate 6 0)) :=
  G2Spec.infinity_verdict

example : G2Spec.verdict (G2Spec.infinity.set 95 1) = none := by
  unfold G2Spec.verdict EthCryptographySpecs.Bls.G2.uncompress
  decide +kernel

def generator : Encoding := .ofFn fun i =>
  (EthCryptographySpecs.Bls.G2.compress EthCryptographySpecs.Bls.G2.generator).data[i.val]!

/-- info: (true, true) -/
#guard_msgs in
#eval
  let inputs := List.replicate 3 generator
  ((uncompress true (fun _ => none) inputs).all Option.isSome,
    (uncompressWith 3 false true true (fun _ => none) inputs).all Option.isNone)

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls

@[reducible] def rejecting : BlsExternals := ⟨false, fun _ => none, fun _ => none⟩

example : ¬ @BlstMatchesSpec rejecting := by
  intro h
  have hi := h (toArray toU8 G2Spec.infinity)
  change (none : Option blst.blst_p2_affine) = specVerdict _ at hi
  simp [specVerdict, ofArray_toArray, G2Spec.infinity_verdict] at hi

@[reducible] def wrongLimbs : BlsExternals := ⟨false, fun _ => none, fun _ => some (toBlstP2Affine sentinel)⟩

example : ¬ @BlstMatchesSpec wrongLimbs := by
  intro h
  have hi := h (toArray toU8 G2Spec.infinity)
  change some (toBlstP2Affine sentinel) = specVerdict _ at hi
  simp [specVerdict, ofArray_toArray, G2Spec.infinity_verdict] at hi
  have hx := congrArg (fun p => (ofBlstP2Affine p).x.fp[0].l[0]) hi
  have hbad : (1 : UInt64) = 0 := by simpa [sentinel, point] using hx
  exact (by decide : (1 : UInt64) ≠ 0) hbad

example [BlsExternals] (inputs : Slice (Array U8 96#usize))
    (out : Slice (Option blst.blst_p2_affine)) (h : out.val.length ≠ inputs.val.length) :
    silver_crypto_simd.bls.uncompress_in_g2 inputs out ≠ ok out := by
  rw [uncompress_in_g2_length_mismatch inputs out h]
  intro hbad
  cases hbad

end LeanBlsSimd.G2WrapperControls
