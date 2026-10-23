import Aeneas
import LeanBlsSimd.Kzg.Model
import LeanBlsSimd.Kzg.IOLawful

open EthLib.Cryptography Bls Kzg

namespace LeanBlsSimd.Kzg

/-- `Except` lifted into `KzgM`. -/
abbrev liftE {α : Type} (x : Except KzgError α) : KzgM α := ExceptT.mk (pure x)

theorem run_liftE {α : Type} (x : Except KzgError α) : (liftE x).run = pure x := rfl

theorem liftE_bind {α β : Type} (x : Except KzgError α) (f : α → Except KzgError β) :
    liftE (x >>= f) = liftE x >>= fun a => liftE (f a) := by
  cases x <;> rfl

theorem liftM_eq_liftE {α : Type} (x : Except KzgError α) : (liftM x : KzgM α) = liftE x := rfl

theorem liftE_pure {α : Type} (a : α) : liftE (pure a : Except KzgError α) = pure a := rfl

theorem liftE_throw {α : Type} (e : KzgError) :
    liftE (throw e : Except KzgError α) = throw e := rfl

theorem liftE_mapM {α β : Type} (xs : List α) (f : α → Except KzgError β) :
    liftE (xs.mapM f) = xs.mapM (fun a => liftE (f a)) := by
  induction xs with
  | nil => rfl
  | cons a xs ih =>
    simp only [List.mapM_cons, liftE_bind, liftE_pure, ih]

theorem liftE_arrayMapM {α β : Type} (xs : Array α) (f : α → Except KzgError β) :
    liftE (xs.mapM f) = xs.mapM (fun a => liftE (f a)) := by
  rw [Array.mapM_eq_mapM_toList, Array.mapM_eq_mapM_toList]
  rw [← liftE_mapM]
  cases xs.toList.mapM f <;> simp

theorem liftE_foldlM {α β : Type} (xs : List α) (f : β → α → Except KzgError β)
    (init : β) : liftE (xs.foldlM f init) = xs.foldlM (fun b a => liftE (f b a)) init := by
  induction xs generalizing init with
  | nil => rfl
  | cons a xs ih => simp only [List.foldlM_cons, liftE_bind, ih]

theorem liftE_arrayFoldlM {α β : Type} (xs : Array α)
    (f : β → α → Except KzgError β) (init : β) :
    liftE (xs.foldlM f init) = xs.foldlM (fun b a => liftE (f b a)) init := by
  rw [← Array.foldlM_toList, ← Array.foldlM_toList, liftE_foldlM]

theorem g1Lincomb_eq (points : Array KZGCommitment) (scalars : Array Fr) :
    g1Lincomb points scalars = liftE (Model.lincomb points scalars) := by
  unfold g1Lincomb Model.lincomb
  simp only [liftE_bind, liftE_pure, liftE_throw, liftE_arrayMapM, apply_ite liftE]
  split_ifs <;> first
    | rfl
    | (congr!
       rename_i x
       cases G1.uncompress x <;> rfl)

theorem verifyWith_pure (s : TrustedSetup) (rli : Model.RliStep)
    (cs : Array Bytes48) (indices : Array Nat) (cells : Array Cell) (ps : Array Bytes48) :
    Model.verifyWith (pure s) rli cs indices cells ps =
      liftE (Model.verifyPure s rli cs indices cells ps) := by
  unfold Model.verifyWith Model.verifyPure Model.implWith Model.implPure
  simp only [g1Lincomb_eq, liftM_eq_liftE, liftE_bind, liftE_pure, liftE_throw, liftE_arrayMapM,
    apply_ite liftE]
  congr! with x

theorem front_decomposition
    (cs : Array Bytes48) (indices : Array Nat)
    (cells : Array Cell) (ps : Array Bytes48) :
    verifyCellKzgProofBatch cs indices cells ps = (do
      let (unique, ci, evals, proofs) ← Model.frontHalf cs indices cells ps
      verifyCellKzgProofBatchImpl unique ci indices evals proofs) := by
  unfold verifyCellKzgProofBatch Model.frontHalf
  repeat' first
    | rfl
    | simp only [liftM_eq_liftE, liftE_bind, liftE_pure, liftE_throw,
        liftE_arrayMapM, liftE_arrayFoldlM, apply_ite liftE, bind_assoc, pure_bind,
        ExceptT.bind_throw]
    | fail_if_no_progress congr!
    | split
  all_goals grind

theorem impl_decomposition :
    verifyCellKzgProofBatchImpl = Model.implWith (monadLift TrustedSetup.get!) Model.specRli := by
  funext cs ci indices evals ps
  unfold verifyCellKzgProofBatchImpl Model.implWith Model.specRli
  simp only [liftM_eq_liftE, liftE_bind, liftE_pure, liftE_arrayFoldlM]
  rfl

theorem upstream_eq_verifyWith
    (cs : Array Bytes48) (indices : Array Nat) (cells : Array Cell) (ps : Array Bytes48) :
    verifyCellKzgProofBatch cs indices cells ps =
      Model.verifyWith (monadLift TrustedSetup.get!) Model.specRli cs indices cells ps := by
  rw [front_decomposition, impl_decomposition]
  rfl

end LeanBlsSimd.Kzg
