import LeanBlsSimd.Refines.G1Wrapper

namespace LeanBlsSimd

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.bls

set_option linter.unreachableTactic false
set_option linter.unusedSimpArgs false
set_option linter.unusedTactic false

attribute [local irreducible] UncompressG1.specVerdict

namespace G1Fallback

open DecompressG1 UncompressG1

/-! ## `decompress_g1_chunk`: the fallback lane

An undecided lane must pass its own encoding to the portable decoder. Reading `chunk[0]` instead of
`chunk[lane]` must not refine `UncompressG1.chunk`. The proof rejects the mutation.
A concrete step refutes the mutant's agreement with the original body: with all lanes
undecided and distinct scalar verdicts on inputs 0 and 1, lane 1 receives `none`
instead of `some`. This checks the loop step without evaluating decompression. -/

def chunkBodyWith (fallback : Array U8 48#usize → Result (Option blst.blst_p1_affine))
    (fallbackLane : Usize → Usize)
  (chunk : Array (Array Std.U8 48#usize) 8#usize) (batch : decompress.Batch)
  (iter : core.ops.range.Range Std.Usize)
  (out : Slice (Option blst.blst_p1_affine)) :
  Result (ControlFlow ((core.ops.range.Range Std.Usize) × (Slice (Option
    blst.blst_p1_affine))) (Slice (Option blst.blst_p1_affine)))
  := do
  let (o, iter1) ←
    core.iter.range.IteratorRange.next core.iter.range.StepUsize iter
  match o with
  | none => ok (done out)
  | some lane =>
    let bit ← 1#u8 <<< lane
    let i ← lift (batch.undecided &&& bit)
    let (iter2, o1) ←
      if i != 0#u8
      then
        do
        let a ← Array.index_usize chunk (fallbackLane lane)
        let o2 ← fallback a
        ok (iter1, o2)
      else
        do
        let i1 ← lift (batch.valid &&& bit)
        let o2 ←
          if i1 != 0#u8
          then do
               let bpa ← Array.index_usize batch.points lane
               ok (some bpa)
          else ok none
        ok (iter1, o2)
    let s ← Slice.update out lane o1
    ok (cont (iter2, s))

example [RuntimeFeatures] :
    chunkBodyWith portable.decompress.uncompress_in_g1 id = decompress_g1_chunk_loop.body := rfl

def chunkWith [RuntimeFeatures] (fallbackLane : Usize → Usize)
    (inputs : Array (Array U8 48#usize) 8#usize)
    (out : Slice (Option blst.blst_p1_affine)) : Result (Slice (Option blst.blst_p1_affine)) := do
  let batch ← decompress.decompress inputs
  loop (fun (iter, out) => chunkBodyWith portable.decompress.uncompress_in_g1 fallbackLane inputs batch iter out)
    ({ start := 0#usize, «end» := LANES }, out)

example [RuntimeFeatures] : chunkWith id = decompress_g1_chunk := rfl

private theorem mask_bit (m : UInt8) (l : Fin 8) :
    (toU8 m &&& toU8 (1 <<< l.val.toUInt8) != 0#u8) = m.toNat.testBit l := by
  rw [Bool.eq_iff_iff]
  simp only [bne_iff_ne, toU8_and]
  change (toU8 (m &&& (1 <<< l.val.toUInt8)) ≠ toU8 0 ↔ _)
  simp only [ne_eq, toU8_inj]
  exact Mmask8.and_one_shiftLeft_ne_zero m l

private def vectorSlice {α : Type} {n : ℕ} (v : Vector α n) (h : n ≤ Usize.max) : Slice α :=
  ⟨v.toList, by simpa using h⟩

private theorem slice_update_ok {α : Type} (s : Slice α) (i : Usize) (x : α)
    (h : i.val < s.val.length) : Slice.update s i x = ok (s.set i x) := by
  simp [Slice.update, h, Slice.set, Slice.setAtNat]

private theorem vectorSlice_set {α : Type} {n : ℕ} (v : Vector α n) (h : n ≤ Usize.max)
    (i : Usize) (hi : i.val < n) (x : α) :
    (vectorSlice v h).set i x = vectorSlice (v.set i.val x hi) h := by
  apply Subtype.ext
  simp [vectorSlice, Slice.set, Slice.setAtNat, Vector.toList_set]

private theorem modelBlst_roundtrip (a : Array U8 48#usize) :
    (modelBlst (ofArray ofU8 a)).map toBlstP1Affine = UncompressG1.specVerdict a := by
  simp [modelBlst, toArray_ofArray, Option.map_map, Function.comp_def]

set_option hygiene false in
/-- The proof of `UncompressG1.chunk_refines`, over `chunkWith`. -/
local macro "chunk_proof" : tactic => `(tactic| (
  intro inputs out hlen
  let b := decompress (ofArray (ofArray ofU8) inputs)
  let target := (chunk modelBlst (ofArray (ofArray ofU8) inputs)).map (Option.map toBlstP1Affine)
  have hb : 8 ≤ Usize.max := by scalar_tac
  let enc := fun v : Vector (Option blst.blst_p1_affine) 8 => vectorSlice v hb
  have ho : enc (ofSlice id out hlen) = out := by
    apply Subtype.ext
    simp [enc, vectorSlice]
  refine ⟨enc target, ?_, by simp [enc, vectorSlice, target, Vector.toList_map]⟩
  rw [chunkWith, decompress_refines]
  simp only [bind_tc_ok]
  rw [← ho]
  apply loop_range (n := 8) _ LANES (by simp [LANES]) enc
    (fun v j => v.set j (target[j])) enc (ofSlice id out hlen) (enc target)
  · intro r v he hs hn
    simp only [chunkBodyWith, id_eq, hn, bind_tc_ok, Function.uncurry_apply_pair]
  · intro r r' v j he hs he' hs' hn
    have hj : r.start.val < 8 := by omega
    simp only [chunkBodyWith, id_eq, hn, bind_tc_ok, Function.uncurry_apply_pair]
    rw [toU8_shiftLeft_one _ hj]
    simp only [lift, bind_tc_ok, toBatch]
    rw [show r.start.val = j.val from hs, mask_bit]
    have ht : target[j] =
        if b.undecided.toNat.testBit j then UncompressG1.specVerdict (inputs.val[j.val]'(by simp [inputs.property]))
        else if b.valid.toNat.testBit j then some (toBlstP1Affine b.points[j]) else none := by
      simp only [target, chunk, Fin.getElem_fin, Vector.getElem_map, Vector.getElem_ofFn, laneVerdict]
      split
      · simp only [getElem_ofArray, modelBlst_roundtrip]
      · split <;> rfl
    cases hu : b.undecided.toNat.testBit j
    · simp only [Bool.false_eq_true, ↓reduceIte]
      rw [mask_bit]
      cases hv : b.valid.toNat.testBit j
      · simp only [Bool.false_eq_true, ↓reduceIte, bind_tc_ok, Function.uncurry_apply_pair]
        rw [slice_update_ok _ _ _ (by simp [enc, vectorSlice, hs]), vectorSlice_set v hb r.start hj]
        simp only [bind_tc_ok, enc, ht, hu, hv, hs, Bool.false_eq_true, ↓reduceIte]
      · simp only [↓reduceIte]
        rw [index_usize_toArray _ _ _ _ hj]
        simp only [bind_tc_ok, Function.uncurry_apply_pair]
        rw [slice_update_ok _ _ _ (by simp [enc, vectorSlice, hs]), vectorSlice_set v hb r.start hj]
        simp only [bind_tc_ok, enc, ht, hu, hv, hs, Bool.false_eq_true, ↓reduceIte]
        rfl
    · simp only [↓reduceIte]
      rw [index_usize_eq _ _ (by first | exact hj | decide)]
      simp only [Portable.Decode.g1_decoder_correct.singleton, bind_tc_ok, Function.uncurry_apply_pair]
      rw [slice_update_ok _ _ _ (by simp [enc, vectorSlice, hs]), vectorSlice_set v hb r.start hj]
      simp only [bind_tc_ok, enc, ht, hu, hs, ↓reduceIte]
  · rw [foldl_set_ofFn]
    congr 1
    ext i hi
    simp))

example [RuntimeFeatures] : ∀ (inputs : Array (Array U8 48#usize) 8#usize)
    (out : Slice (Option blst.blst_p1_affine)), out.val.length = 8 →
    ∃ result, chunkWith id inputs out = ok result ∧
      result.val = ((chunk modelBlst (ofArray (ofArray ofU8) inputs)).toList.map
        (Option.map toBlstP1Affine)) := by
  chunk_proof

example [RuntimeFeatures] : True := by
  fail_if_success
    have : ∀ (inputs : Array (Array U8 48#usize) 8#usize)
        (out : Slice (Option blst.blst_p1_affine)), out.val.length = 8 →
        ∃ result, chunkWith (fun _ => 0#usize) inputs out = ok result ∧
          result.val = ((chunk modelBlst (ofArray (ofArray ofU8) inputs)).toList.map
            (Option.map toBlstP1Affine)) := by
      chunk_proof
  trivial

/-- Distinct scalar verdicts expose a fallback read from the wrong lane. -/
@[reducible] def distinguishingFallback (bytes : Array U8 48#usize) :
    Result (Option blst.blst_p1_affine) :=
  ok (if bytes.val[0]!.val = 0 then none else some (toBlstP1Affine default))

def distinctInputs : Array (Array U8 48#usize) 8#usize :=
  toArray (toArray toU8) (Vector.ofFn fun (lane : Fin 8) =>
    Vector.replicate 48 lane.val.toUInt8)

def undecidedBatch : decompress.Batch :=
  toBatch ⟨Vector.replicate 8 default, 0, 255⟩

def emptyOutput : Slice (Option blst.blst_p1_affine) :=
  vectorSlice (Vector.replicate 8 none) (by scalar_tac)

def laneOneVerdict (result : Result (ControlFlow
    (core.ops.range.Range Usize × Slice (Option blst.blst_p1_affine))
    (Slice (Option blst.blst_p1_affine)))) : Bool :=
  match result with
  | ok (cont (_, out)) => out.val[1]!.isSome
  | _ => false

set_option hygiene false in
local macro "lane_one_proof" : tactic => `(tactic| (
  obtain ⟨next, _, _, hn⟩ := next_lt
    { start := 1#usize, «end» := 8#usize } (by decide)
  simp only [chunkBodyWith, hn, bind_tc_ok, Function.uncurry_apply_pair]
  rw [toU8_shiftLeft_one _ (by decide)]
  rfl))

theorem original_lane_one : laneOneVerdict
    (chunkBodyWith distinguishingFallback id distinctInputs undecidedBatch
      { start := 1#usize, «end» := 8#usize } emptyOutput) = true := by
  lane_one_proof

theorem mutated_lane_one : laneOneVerdict
    (chunkBodyWith distinguishingFallback (fun _ => 0#usize) distinctInputs undecidedBatch
      { start := 1#usize, «end» := 8#usize } emptyOutput) = false := by
  lane_one_proof

example : chunkBodyWith distinguishingFallback (fun _ => 0#usize) distinctInputs undecidedBatch
    { start := 1#usize, «end» := 8#usize } emptyOutput ≠
    chunkBodyWith distinguishingFallback id distinctInputs undecidedBatch
      { start := 1#usize, «end» := 8#usize } emptyOutput := by
  intro h
  have e := congrArg laneOneVerdict h
  rw [original_lane_one, mutated_lane_one] at e
  contradiction

end G1Fallback

end LeanBlsSimd
