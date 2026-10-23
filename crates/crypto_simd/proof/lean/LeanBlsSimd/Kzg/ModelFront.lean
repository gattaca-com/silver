import LeanBlsSimd.Kzg.DedupModel
import LeanBlsSimd.Kzg.ByteSerialization
import LeanBlsSimd.Kzg.Representation

open EthLib.Cryptography Bls Kzg

namespace LeanBlsSimd.Kzg

set_option maxRecDepth 10000
set_option maxHeartbeats 4000000

namespace ModelFront

@[simp] theorem toOption_ok {ε α : Type} (a : α) :
    (Except.ok a : Except ε α).toOption = some a := rfl
@[simp] theorem toOption_error {ε α : Type} (e : ε) :
    (Except.error e : Except ε α).toOption = none := rfl
@[simp] theorem toOption_pure {ε α : Type} (a : α) :
    (pure a : Except ε α).toOption = some a := rfl

@[simp] theorem toOption_bind {ε α β : Type} (x : Except ε α) (f : α → Except ε β) :
    (x >>= f).toOption = x.toOption.bind (fun a => (f a).toOption) := by
  cases x <;> rfl

@[simp] theorem toOption_map {ε α β : Type} (f : α → β) (x : Except ε α) :
    (f <$> x).toOption = x.toOption.map f := by
  cases x <;> rfl

private theorem validated_fold {α σ ε : Type} (xs : List α) (p : α → Bool)
    (f : σ → α → σ) (err : α → ε) (init : σ) :
    (xs.foldlM (fun s x => if p x then Except.ok (f s x) else .error (err x)) init).toOption =
      if xs.all p then some (xs.foldl f init) else none := by
  induction xs generalizing init with
  | nil => rfl
  | cons x xs ih =>
    simp only [List.foldlM_cons, toOption_bind, List.all_cons, List.foldl_cons]
    cases hp : p x <;> cases ht : xs.all p <;> simp [ih, ht]

private theorem validated_map {α β ε : Type} (xs : List α) (p : α → Bool)
    (f : α → β) (err : α → ε) :
    (xs.mapM (fun x => if p x then Except.ok (f x) else .error (err x))).toOption =
      if xs.all p then some (xs.map f) else none := by
  induction xs with
  | nil => rfl
  | cons x xs ih =>
    simp only [List.mapM_cons, toOption_bind, List.all_cons, List.map_cons]
    cases hp : p x <;> cases ht : xs.all p <;> simp [ih, ht]

private theorem enumerate_array {α : Type} [Inhabited α] (xs : Array α) :
    (List.range xs.size).map (fun i => xs[i]!) = xs.toList := by
  apply List.ext_getElem (by simp)
  intro i hi hj
  simp [getElem!_pos xs i (by simpa using hj)]

private def dedupStep (state : Array Bytes48 × Array Nat) (c : Bytes48) :=
  match state.1.idxOf? c with
  | some j => (state.1, state.2.push j)
  | none => (state.1.push c, state.2.push state.1.size)

private def checkCommitmentStep (cs : Array Bytes48) (state : Array Bytes48 × Array Nat)
    (i : Nat) : Except KzgError (Array Bytes48 × Array Nat) := do
  let c := cs[i]!
  let _ ← match bytesToKzgCommitment c with
    | .ok c => pure c
    | .error _ => throw (.invalidCommitment (some i))
  match state.1.idxOf? c with
  | some j => pure (state.1, state.2.push j)
  | none => pure (state.1.push c, state.2.push state.1.size)

private theorem checkCommitmentStep_eq (cs : Array Bytes48) (s : Array Bytes48 × Array Nat)
    (i : Nat) :
    checkCommitmentStep cs s i =
      if validateKzgG1 cs[i]! then .ok (dedupStep s cs[i]!)
      else .error (.invalidCommitment (some i)) := by
  unfold checkCommitmentStep
  dsimp only
  unfold bytesToKzgCommitment
  cases hv : validateKzgG1 cs[i]! <;> cases hi : s.1.idxOf? cs[i]! <;>
    simp [dedupStep, hi]
  all_goals rfl

private theorem commitment_fold (cs : Array Bytes48) :
    ((Array.range cs.size).foldlM (checkCommitmentStep cs) (#[], #[])).toOption =
      if cs.all validateKzgG1 then some (Model.deduplicate cs) else none := by
  simp only [checkCommitmentStep_eq, ← Array.foldlM_toList, Array.toList_range]
  rw [validated_fold]
  have hall : (List.range cs.size).all (fun i => validateKzgG1 cs[i]!) = cs.all validateKzgG1 := by
    calc
      _ = ((List.range cs.size).map (fun i => cs[i]!)).all validateKzgG1 := by simp only [List.all_map, Function.comp_def]
      _ = _ := by rw [enumerate_array]; simp
  have hfold : (List.range cs.size).foldl (fun s i => dedupStep s cs[i]!) (#[], #[]) =
      Model.deduplicate cs := by
    rw [← List.foldl_map, enumerate_array, Array.foldl_toList]
    rfl
  rw [hall, hfold]

private def checkProof (ps : Array Bytes48) (i : Nat) : Except KzgError Bytes48 :=
  match bytesToKzgProof ps[i]! with
  | .ok p => pure p
  | .error _ => throw (.invalidProof (some i))

private theorem checkProof_eq (ps : Array Bytes48) (i : Nat) :
    checkProof ps i = if validateKzgG1 ps[i]! then .ok ps[i]!
      else .error (.invalidProof (some i)) := by
  unfold checkProof bytesToKzgProof
  cases validateKzgG1 ps[i]! <;> rfl

private theorem proof_map (ps : Array Bytes48) :
    ((Array.range ps.size).mapM (checkProof ps)).toOption =
      if ps.all validateKzgG1 then some ps else none := by
  rw [Array.mapM_eq_mapM_toList, toOption_map]
  have hfun : checkProof ps = fun i => if validateKzgG1 ps[i]! then .ok ps[i]!
      else .error (.invalidProof (some i)) := funext (checkProof_eq ps)
  simp only [Array.toList_range, hfun]
  rw [validated_map]
  have hall : (List.range ps.size).all (fun i => validateKzgG1 ps[i]!) = ps.all validateKzgG1 := by
    calc
      _ = ((List.range ps.size).map (fun i => ps[i]!)).all validateKzgG1 := by simp only [List.all_map, Function.comp_def]
      _ = _ := by rw [enumerate_array]; simp
  rw [hall, enumerate_array]
  cases ps.all validateKzgG1 <;> simp

theorem frontHalf_option (cs : Array Bytes48) (indices : Array Nat)
    (cells : Array Cell) (ps : Array Bytes48)
    (hlen : cells.size = cs.size ∧ ps.size = cs.size ∧ indices.size = cs.size)
    (hcs : ∀ b ∈ cs, b.size = 48) (hcell : ∀ b ∈ cells, b.size = 2048)
    (hps : ∀ b ∈ ps, b.size = 48)
    (hindices : ∀ i ∈ indices, i < 128) :
    (Model.frontHalf cs indices cells ps).toOption =
      if cs.all validateKzgG1 then
        (cells.mapM cellToCosetEvals).toOption.bind fun evals =>
          if ps.all validateKzgG1 then
            some ((Model.deduplicate cs).1, (Model.deduplicate cs).2, evals, ps)
          else none
      else none := by
  have hcsFind : cs.find? (fun b => b.size != Constants.BYTES_PER_COMMITMENT) = none := by
    apply Array.find?_eq_none.mpr
    intro b hb
    simp [hcs b hb, Constants.BYTES_PER_COMMITMENT]
  have hcellFind : cells.find? (fun b => b.size != Constants.BYTES_PER_CELL) = none := by
    apply Array.find?_eq_none.mpr
    intro b hb
    simp [hcell b hb, Constants.BYTES_PER_CELL, Constants.FIELD_ELEMENTS_PER_CELL, Constants.BYTES_PER_FIELD_ELEMENT]
  have hpsFind : ps.find? (fun b => b.size != Constants.BYTES_PER_PROOF) = none := by
    apply Array.find?_eq_none.mpr
    intro b hb
    simp [hps b hb, Constants.BYTES_PER_PROOF]
  have hiAny : indices.any (· ≥ Constants.CELLS_PER_EXT_BLOB) = false := by
    simp only [Array.any_eq_false', Constants.CELLS_PER_EXT_BLOB]
    intro i hi
    simpa using hindices i hi
  have hcl : ¬ cells.size ≠ cs.size := not_not.mpr hlen.1
  have hpl : ¬ ps.size ≠ cs.size := not_not.mpr hlen.2.1
  have hil : ¬ indices.size ≠ cs.size := not_not.mpr hlen.2.2
  unfold Model.frontHalf
  simp only [hcl, hpl, hil, if_false, hcsFind, hcellFind,
    hpsFind, hiAny, Bool.false_eq_true, pure, Except.pure, Bind.bind, Except.bind]
  change ((Array.range cs.size).foldlM (checkCommitmentStep cs) (#[], #[]) >>= fun state =>
    cells.mapM cellToCosetEvals >>= fun evals =>
    (Array.range ps.size).mapM (checkProof ps) >>= fun proofs =>
    Except.ok (state.1, state.2, evals, proofs)).toOption = _
  simp only [toOption_bind, commitment_fold, proof_map]
  cases cs.all validateKzgG1 <;> cases ps.all validateKzgG1 <;> simp


@[simp] theorem list_mapM_toOption {ε α β : Type} (f : α → Except ε β) (xs : List α) :
    (xs.mapM f).toOption = xs.mapM (fun a => (f a).toOption) := by
  induction xs with
  | nil => rfl
  | cons x xs ih =>
    simp only [List.mapM_cons, toOption_bind, ih]
    cases f x <;> rfl

private theorem option_sequence {α : Type} (xs : List (Option α)) :
    xs.mapM id = if xs.all Option.isSome then some (xs.filterMap id) else none := by
  induction xs with
  | nil => rfl
  | cons x xs ih => cases x <;> cases hs : xs.all Option.isSome <;> simp [List.mapM_cons, ih, hs]

def fieldOptions (cell : ByteArray) : List (Option Fr) :=
  (List.range 64).map fun j =>
    (bytesToBlsField (cell.extract (32*j) (32*(j+1)))).toOption

def fieldValues (cell : ByteArray) : Array Fr := (fieldOptions cell).filterMap id |>.toArray

theorem fieldOptions_length (cell : ByteArray) : (fieldOptions cell).length = 64 := by
  simp [fieldOptions]

theorem cell_decode_option (cell : ByteArray) (hs : cell.size = 2048) :
    (cellToCosetEvals cell).toOption =
      if (fieldOptions cell).all Option.isSome then some (fieldValues cell) else none := by
  unfold cellToCosetEvals
  simp only [Constants.BYTES_PER_CELL, Constants.FIELD_ELEMENTS_PER_CELL, Constants.BYTES_PER_FIELD_ELEMENT, hs, ne_self_iff_false, if_false]
  simp only [pure, Except.pure, bind, Except.bind]
  rw [Array.mapM_eq_mapM_toList, toOption_map, list_mapM_toOption]
  simp only [Array.toList_range]
  calc
    _ = ((List.range 64).mapM (fun i =>
        (bytesToBlsField (cell.extract (32*i) (32*(i+1)))).toOption)).map List.toArray := by
      congr 2
      funext i
      simp only [Nat.mul_comm i 32, Nat.mul_comm (i+1) 32]
      cases bytesToBlsField (cell.extract (32*i) (32*(i+1))) <;> rfl
    _ = _ := by
      have hseq : (List.range 64).mapM (fun i =>
          (bytesToBlsField (cell.extract (32*i) (32*(i+1)))).toOption) =
          (fieldOptions cell).mapM id := by simp only [fieldOptions, List.mapM_map, Function.comp_def, id_eq]
      rw [hseq]
      rw [option_sequence]
      cases (fieldOptions cell).all Option.isSome <;> rfl

theorem cells_decode_option (cells : List ByteArray)
    (hs : ∀ b ∈ cells, b.size = 2048) :
    (cells.mapM cellToCosetEvals).toOption =
      if (cells.flatMap fieldOptions).all Option.isSome then some (cells.map fieldValues)
      else none := by
  induction cells with
  | nil => rfl
  | cons cell cells ih =>
    simp only [List.mapM_cons, toOption_bind,
      cell_decode_option cell (hs cell (by simp)),
      ih (fun b hb => hs b (by simp [hb])), List.flatMap_cons,
      List.all_append, List.map_cons]
    cases (fieldOptions cell).all Option.isSome <;>
      cases (cells.flatMap fieldOptions).all Option.isSome <;> rfl

theorem cells_values_flatten (cells : List ByteArray) :
    (cells.map fieldValues).flatMap Array.toList = (cells.flatMap fieldOptions).filterMap id := by
  simp [List.flatMap_map, fieldValues, List.filterMap_flatMap]

private theorem option_filterMap_length {α : Type} (xs : List (Option α))
    (h : xs.all Option.isSome = true) : (xs.filterMap id).length = xs.length := by
  induction xs with
  | nil => rfl
  | cons x xs ih => cases x <;> simp_all

theorem cells_values_size (cell : ByteArray)
    (h : (fieldOptions cell).all Option.isSome = true) : (fieldValues cell).size = 64 := by
  simpa [fieldValues, fieldOptions_length] using option_filterMap_length (fieldOptions cell) h


theorem verify_of_front_none (setup : TrustedSetup) (cs : Array Bytes48) (indices : Array Nat)
    (cells : Array Cell) (ps : Array Bytes48)
    (h : (Model.frontHalf cs indices cells ps).toOption = none) :
    Model.verify setup cs indices cells ps = false := by
  cases hf : Model.frontHalf cs indices cells ps with
  | error e => simp [Model.verify, Model.verifyPure, hf, Model.rejectErrors, Bind.bind, Except.bind]
  | ok front => simp [hf] at h

theorem frontHalf_ok (cs : Array Bytes48) (indices : Array Nat)
    (cells : Array Cell) (ps : Array Bytes48) (evals : Array CosetEvals)
    (hlen : cells.size = cs.size ∧ ps.size = cs.size ∧ indices.size = cs.size)
    (hcs : ∀ b ∈ cs, b.size = 48) (hcell : ∀ b ∈ cells, b.size = 2048)
    (hps : ∀ b ∈ ps, b.size = 48) (hindices : ∀ i ∈ indices, i < 128)
    (hcvalid : cs.all validateKzgG1 = true) (hpvalid : ps.all validateKzgG1 = true)
    (hdecode : cells.mapM cellToCosetEvals = .ok evals) :
    Model.frontHalf cs indices cells ps =
      .ok ((Model.deduplicate cs).1, (Model.deduplicate cs).2, evals, ps) := by
  have h := frontHalf_option cs indices cells ps hlen hcs hcell hps hindices
  simp only [hcvalid, hpvalid, hdecode, if_true, Except.toOption, Option.bind_some] at h
  cases hf : Model.frontHalf cs indices cells ps with
  | error e => simp [hf] at h
  | ok front => simpa [hf] using h

theorem verify_of_bad_index (setup : TrustedSetup) (cs : Array Bytes48) (indices : Array Nat)
    (cells : Array Cell) (ps : Array Bytes48)
    (hlen : cells.size = cs.size ∧ ps.size = cs.size ∧ indices.size = cs.size)
    (hcs : ∀ b ∈ cs, b.size = 48) (hi : indices.any (· ≥ 128) = true) :
    Model.verify setup cs indices cells ps = false := by
  apply verify_of_front_none
  have hcsFind : cs.find? (fun b => b.size != Constants.BYTES_PER_COMMITMENT) = none := by
    apply Array.find?_eq_none.mpr
    intro b hb
    simp [hcs b hb, Constants.BYTES_PER_COMMITMENT]
  have hcl : ¬ cells.size ≠ cs.size := not_not.mpr hlen.1
  have hpl : ¬ ps.size ≠ cs.size := not_not.mpr hlen.2.1
  have hil : ¬ indices.size ≠ cs.size := not_not.mpr hlen.2.2
  simp only [Model.frontHalf, hcl, hpl, hil, if_false, hcsFind,
    show Constants.CELLS_PER_EXT_BLOB = 128 from rfl, hi, if_true,
    Bind.bind, Except.bind, pure, Except.pure, toOption_error]

end ModelFront
end LeanBlsSimd.Kzg
