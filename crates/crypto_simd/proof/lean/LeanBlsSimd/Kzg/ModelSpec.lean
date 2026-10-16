import LeanBlsSimd.Kzg.ByteSerialization
import LeanBlsSimd.Kzg.SpecBridge

open EthCryptographySpecs Bls Kzg

namespace LeanBlsSimd.Kzg.ModelSpec

theorem cell_decode_size (cell : Cell) (evals : CosetEvals)
    (h : cellToCosetEvals cell = .ok evals) : evals.size = 64 := by
  unfold cellToCosetEvals at h
  split at h
  · simp [bind, Except.bind] at h
  · simp only [pure, Except.pure, bind, Except.bind] at h
    simpa using array_mapM_ok_size _ _ _ h

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
  simp only [pure, Except.pure, bind, Except.bind] at h
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
  simpa only [Array.any_eq_false', decide_eq_true_eq, not_le] using hb

/-- The reviewed column interpolation identity, with its exact input contract. -/
abbrev ColumnIdentity : Prop :=
  ∀ indices evals powers, Model.RliInputs indices evals powers →
    Model.specRli indices evals powers = .ok (Model.columnRli indices evals powers)

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
  have hr := columnIdentity indices evals
    (computePowers (computeVerifyCellKzgProofBatchChallenge unique ci indices evals proofs)
      indices.size) ⟨h.1, by simp, h.2.1, h.2.2⟩
  unfold Model.implPure Model.columnStep
  dsimp only
  rw [hr]

theorem implWith_spec_eq_column (columnIdentity : ColumnIdentity) (getSetup : KzgM TrustedSetup)
    (unique : Array KZGCommitment) (ci indices : Array Nat) (evals : Array CosetEvals)
    (proofs : Array KZGProof)
    (h : indices.size = evals.size ∧ (∀ i ∈ indices, i < 128) ∧
      (∀ ys ∈ evals, ys.size = 64)) :
    Model.implWith getSetup Model.specRli unique ci indices evals proofs =
      Model.implWith getSetup Model.columnStep unique ci indices evals proofs := by
  have hr := columnIdentity indices evals
    (computePowers (computeVerifyCellKzgProofBatchChallenge unique ci indices evals proofs)
      indices.size) ⟨h.1, by simp, h.2.1, h.2.2⟩
  unfold Model.implWith Model.columnStep
  dsimp only
  rw [hr]

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
