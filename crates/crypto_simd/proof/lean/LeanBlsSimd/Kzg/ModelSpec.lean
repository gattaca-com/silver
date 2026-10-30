import LeanBlsSimd.Kzg.ByteSerialization
import LeanBlsSimd.Kzg.SpecBridge
import EthLib.Cryptography.Proofs.Kzg.CosetInterpolation

open EthLib.Cryptography Bls Kzg

namespace LeanBlsSimd.Kzg.ModelSpec

theorem cell_decode_size (cell : Cell) (evals : CosetEvals)
    (h : cellToCosetEvals cell = .ok evals) : evals.size = 64 := by
  unfold cellToCosetEvals at h
  split at h
  · simp [bind, Except.bind] at h
  · simp only [pure, Except.pure, bind, Except.bind] at h
    simpa [Constants.FIELD_ELEMENTS_PER_CELL] using array_mapM_ok_size _ _ _ h

theorem cells_decode_shape (cells : Array Cell) (evals : Array CosetEvals)
    (h : cells.mapM cellToCosetEvals = .ok evals) :
    evals.size = cells.size ∧ ∀ ys ∈ evals, ys.size = 64 := by
  have hs := array_mapM_ok_size _ _ _ h
  refine ⟨hs, ?_⟩
  intro ys hy
  obtain ⟨i, hi, rfl⟩ := Array.mem_iff_getElem.mp hy
  have hd := array_mapM_ok_get _ _ _ h i (by omega)
  have ht := cell_decode_size _ _ hd
  simpa [getElem!_pos evals i hi] using ht

theorem frontHalf_shape
    (cs : Array Bytes48) (indices : Array Nat) (cells : Array Cell) (ps : Array Bytes48)
    (unique : Array KZGCommitment) (ci : Array Nat) (evals : Array CosetEvals)
    (proofs : Array KZGProof)
    (h : Model.frontHalf cs indices cells ps = .ok (unique, ci, evals, proofs)) :
    indices.size = evals.size ∧ (∀ i ∈ indices, i < 128) ∧
      (∀ ys ∈ evals, ys.size = 64) := by
  unfold Model.frontHalf at h
  simp only [pure, Except.pure, bind, Except.bind, throw, throwThe, MonadExceptOf.throw] at h
  split at h
  · simp at h
  rename_i hcells
  split at h
  · simp at h
  rename_i hproofs
  split at h
  · simp at h
  rename_i hindices
  split at h
  · simp at h
  split at h
  · simp at h
  rename_i hbounded
  split at h
  · simp at h
  split at h
  · simp at h
  split at h
  · contradiction
  rename_i dedup hdedup
  split at h
  · contradiction
  rename_i decoded hdecoded
  split at h
  · contradiction
  rename_i checked hchecked
  simp only [Except.ok.injEq, Prod.mk.injEq] at h
  obtain ⟨_, _, hevals, _⟩ := h
  subst decoded
  obtain ⟨hsize, hrows⟩ := cells_decode_shape cells evals hdecoded
  refine ⟨by omega, ?_, hrows⟩
  have hb : indices.any (fun i => decide (i ≥ Constants.CELLS_PER_EXT_BLOB)) = false :=
    Bool.eq_false_iff.mpr hbounded
  simp only [Array.any_eq_false', decide_eq_true_eq, not_le] at hb
  intro i hi
  exact (show Constants.CELLS_PER_EXT_BLOB = 128 from rfl) ▸ hb i hi

theorem shiftOf_ok (c : Nat) (hc : c < 128) : Model.shiftOf c = .ok (Model.cosetShift c) := by
  have hc' : ¬c ≥ Constants.CELLS_PER_EXT_BLOB := by
    rw [show Constants.CELLS_PER_EXT_BLOB = 128 from rfl]; omega
  simp only [Model.shiftOf, hc', if_false]
  rfl

theorem mapM_shiftOf (indices : Array Nat) (h : ∀ i ∈ indices, i < 128) :
    indices.mapM Model.shiftOf = .ok (indices.map Model.cosetShift) := by
  rw [Array.mapM_eq_mapM_toList]
  have hl : ∀ xs : List Nat, (∀ i ∈ xs, i < 128) →
      xs.mapM Model.shiftOf = .ok (xs.map Model.cosetShift) := by
    intro xs hxs
    induction xs with
    | nil => rfl
    | cons x xs ih =>
      simp only [List.mapM_cons, shiftOf_ok x (hxs x (by simp)),
        ih (fun y hy => hxs y (by simp [hy])), List.map_cons]
      rfl
  rw [hl indices.toList (fun i hi => h i (Array.mem_toList_iff.mp hi))]
  change Except.ok (List.map Model.cosetShift indices.toList).toArray = _
  exact congrArg Except.ok (Array.toList_inj.mp (by simp))

private theorem list_foldlM_congr {α β ε : Type} (f g : β → α → Except ε β) (xs : List α)
    (init : β) (h : ∀ a ∈ xs, ∀ b, f b a = g b a) : xs.foldlM f init = xs.foldlM g init := by
  induction xs generalizing init with
  | nil => rfl
  | cons a xs ih =>
    simp only [List.foldlM_cons, h a (by simp)]
    congr 1
    funext b
    exact ih b (fun a' ha' => h a' (by simp [ha']))

/-- Upstream's coset interpolation agrees with Lagrange interpolation on every cell. -/
theorem specRli_eq_lagrangeRli (indices : Array Nat) (evals : Array (Array Fr)) (powers : Array Fr)
    (h : Model.RliInputs indices evals powers) :
    Model.specRli indices (indices.map Model.cosetShift) evals powers =
      Model.lagrangeRli indices evals powers := by
  obtain ⟨hsize, _, hbounds, hrows⟩ := h
  unfold Model.specRli Model.lagrangeRli
  rw [← Array.foldlM_toList, ← Array.foldlM_toList]
  apply list_foldlM_congr
  intro k hk acc
  have hk' : k < indices.size := by simpa using hk
  have hidx : indices[k]! < 128 := hbounds _ (by simp [getElem!_pos indices k hk'])
  have hev : evals[k]!.size = Constants.FIELD_ELEMENTS_PER_CELL :=
    hrows _ (by simp [getElem!_pos evals k (hsize ▸ hk')])
  obtain ⟨coset, hcoset, _, _⟩ := cosetForCell_ok_of_lt (cellIndex := indices[k]!) hidx
  obtain ⟨p, hspec, hlag, _⟩ := interpolateCosetEvals_eq_interpolatePolynomialcoeff hcoset hev
  have hshift : (indices.map Model.cosetShift)[k]! =
      (rootsOfUnityBrp Constants.FIELD_ELEMENTS_PER_EXT_BLOB)[
        Constants.FIELD_ELEMENTS_PER_CELL * indices[k]!]! := by
    rw [getElem!_pos _ k (by simpa using hk'), Array.getElem_map, ← getElem!_pos indices k hk']
    rfl
  simp only [hshift, hspec, hcoset, hlag, bind, Except.bind]

/-- The reviewed column interpolation identity, with its exact input contract. -/
abbrev ColumnIdentity : Prop :=
  ∀ indices evals powers, Model.RliInputs indices evals powers →
    Model.specRli indices (indices.map Model.cosetShift) evals powers =
      .ok (Model.columnRli indices evals powers)

theorem frontHalf_rli_inputs
    (cs : Array Bytes48) (indices : Array Nat) (cells : Array Cell) (ps : Array Bytes48)
    (unique : Array KZGCommitment) (ci : Array Nat) (evals : Array CosetEvals)
    (proofs : Array KZGProof)
    (h : Model.frontHalf cs indices cells ps = .ok (unique, ci, evals, proofs)) (r : Fr) :
    Model.RliInputs indices evals (computePowers r indices.size) := by
  obtain ⟨hsize, hbounds, hrows⟩ := frontHalf_shape cs indices cells ps unique ci evals proofs h
  exact ⟨hsize, by simp, hbounds, hrows⟩

theorem implPure_spec_eq_column (columnIdentity : ColumnIdentity) (setup : TrustedSetup)
    (unique : Array KZGCommitment) (ci indices : Array Nat) (evals : Array CosetEvals)
    (proofs : Array KZGProof)
    (h : indices.size = evals.size ∧ (∀ i ∈ indices, i < 128) ∧
      (∀ ys ∈ evals, ys.size = 64)) :
    Model.implPure setup Model.specRli unique ci indices evals proofs =
      Model.implPure setup Model.columnStep unique ci indices evals proofs := by
  have hin : Model.RliInputs indices evals
      (computePowers (computeVerifyCellKzgProofBatchChallenge unique ci indices evals proofs)
        indices.size) := ⟨h.1, by simp, h.2.1, h.2.2⟩
  have hr := columnIdentity _ _ _ hin
  have hm : indices.mapM Model.shiftOf = pure (indices.map Model.cosetShift) :=
    mapM_shiftOf indices h.2.1
  unfold Model.implPure Model.columnStep
  simp only [hm, pure_bind, hr]

theorem implWith_spec_eq_column (columnIdentity : ColumnIdentity) (getSetup : KzgM TrustedSetup)
    (unique : Array KZGCommitment) (ci indices : Array Nat) (evals : Array CosetEvals)
    (proofs : Array KZGProof)
    (h : indices.size = evals.size ∧ (∀ i ∈ indices, i < 128) ∧
      (∀ ys ∈ evals, ys.size = 64)) :
    Model.implWith getSetup Model.specRli unique ci indices evals proofs =
      Model.implWith getSetup Model.columnStep unique ci indices evals proofs := by
  have hin : Model.RliInputs indices evals
      (computePowers (computeVerifyCellKzgProofBatchChallenge unique ci indices evals proofs)
        indices.size) := ⟨h.1, by simp, h.2.1, h.2.2⟩
  have hr := columnIdentity _ _ _ hin
  have hm : (indices.mapM fun c => ExceptT.mk (pure (Model.shiftOf c)) : KzgM (Array Fr)) =
      pure (indices.map Model.cosetShift) := by
    rw [← liftE_arrayMapM, mapM_shiftOf indices h.2.1]
    rfl
  unfold Model.implWith Model.columnStep
  simp only [hm, pure_bind, hr]

theorem verifyPure_spec_eq_column (columnIdentity : ColumnIdentity) (setup : TrustedSetup)
    (cs : Array Bytes48) (indices : Array Nat) (cells : Array Cell) (ps : Array Bytes48) :
    Model.verifyPure setup Model.specRli cs indices cells ps =
      Model.verifyPure setup Model.columnStep cs indices cells ps := by
  unfold Model.verifyPure
  cases hf : Model.frontHalf cs indices cells ps with
  | error e => rfl
  | ok front =>
    rcases front with ⟨unique, ci, evals, proofs⟩
    exact implPure_spec_eq_column columnIdentity setup unique ci indices evals proofs
      (frontHalf_shape cs indices cells ps unique ci evals proofs hf)

theorem verifyWith_spec_eq_column (columnIdentity : ColumnIdentity) (getSetup : KzgM TrustedSetup)
    (cs : Array Bytes48) (indices : Array Nat) (cells : Array Cell) (ps : Array Bytes48) :
    Model.verifyWith getSetup Model.specRli cs indices cells ps =
      Model.verifyWith getSetup Model.columnStep cs indices cells ps := by
  unfold Model.verifyWith
  cases hf : Model.frontHalf cs indices cells ps with
  | error e =>
    simp only [liftM_eq_liftE, show liftE (Except.error e : Except KzgError Model.Front) =
      throw e from rfl, ExceptT.bind_throw]
  | ok front =>
    rcases front with ⟨unique, ci, evals, proofs⟩
    simp only [liftM_eq_liftE, show liftE (Except.ok (unique, ci, evals, proofs)) =
      pure (unique, ci, evals, proofs) from rfl, pure_bind]
    exact implWith_spec_eq_column columnIdentity getSetup unique ci indices evals proofs
      (frontHalf_shape cs indices cells ps unique ci evals proofs hf)

theorem upstream_spec_eq_column (columnIdentity : ColumnIdentity)
    (cs : Array Bytes48) (indices : Array Nat) (cells : Array Cell) (ps : Array Bytes48) :
    verifyCellKzgProofBatch cs indices cells ps =
      Model.verifyWith (monadLift TrustedSetup.get!) Model.columnStep cs indices cells ps := by
  rw [upstream_eq_verifyWith, verifyWith_spec_eq_column columnIdentity]

theorem rejectErrors_spec_eq_model (columnIdentity : ColumnIdentity) (setup : TrustedSetup)
    (cs : Array Bytes48) (indices : Array Nat) (cells : Array Cell) (ps : Array Bytes48) :
    Model.rejectErrors (Model.verifyPure setup Model.specRli cs indices cells ps) =
      Model.verify setup cs indices cells ps := by
  rw [verifyPure_spec_eq_column columnIdentity]
  rfl

end LeanBlsSimd.Kzg.ModelSpec
