import LeanBlsSimd.Kzg.Extender.Basic
import LeanBlsSimd.Kzg.Extender.Acceptance
import LeanBlsSimd.Kzg.Extender.Primitives
import LeanBlsSimd.Kzg.Extender.Spec
import LeanBlsSimd.Kzg.Extender.Refines

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender

theorem new_returns_ok [cpu : RuntimeFeatures] :
    ∃ initial, cell_extender.CellExtender.new = ok initial ∧ StateInvariant initial := by
  exact new_refinement

theorem default_eq_new [RuntimeFeatures] :
    cell_extender.CellExtender.Insts.CoreDefaultDefault.default =
      cell_extender.CellExtender.new := by
  rfl

theorem model_eq_spec (blob : ByteArray) :
    (computeCells blob).run = pure (Model.extend blob) := by
  exact model_spec blob

theorem model_accepts_iff (blob : Blob) :
    (Model.extend (arrayBytes blob)).isOk = true ↔ Canonical blob := by
  exact model_acceptance blob

theorem glue_refinement
    (v : cell_extender.CellExtender) (hv : StateInvariant v)
    (blob : Blob) (cells : Cells) :
    ∃ (verdict : Bool) (next : cell_extender.CellExtender) (out : Cells),
      cell_extender.CellExtender.compute v blob cells = ok (verdict, next, out) ∧
      StateInvariant next ∧
      (verdict, cellBytes out) = Model.compute (arrayBytes blob) (cellBytes cells) := by
  exact compute_refinement v hv blob cells

theorem compute_eq_spec [cpu : RuntimeFeatures] :
    ∃ initial, cell_extender.CellExtender.new = ok initial ∧ StateInvariant initial ∧
      ∀ (v : cell_extender.CellExtender), StateInvariant v →
      ∀ (blob : Blob) (cells : Cells),
      ∃ (verdict : Bool) (next : cell_extender.CellExtender) (out : Cells),
        cell_extender.CellExtender.compute v blob cells = ok (verdict, next, out) ∧
        StateInvariant next ∧
        (verdict = true ↔ Canonical blob) ∧
        (verdict = true →
          (computeCells (arrayBytes blob)).run = pure (.ok (cellBytes out))) ∧
        (verdict = false → ∃ err,
          (computeCells (arrayBytes blob)).run = pure (.error err)) ∧
        (verdict = false → out = cells) := by
  obtain ⟨initial, hnew, hinitial⟩ := new_returns_ok
  refine ⟨initial, hnew, hinitial, ?_⟩
  intro v hv blob cells
  obtain ⟨verdict, next, out, hcompute, hn, hmodel, hunchanged⟩ :=
    compute_refinement_with_rejection v hv blob cells
  cases hm : Model.extend (arrayBytes blob) with
  | error err =>
    have hvfalse : verdict = false := by
      simpa [Model.compute, hm] using congrArg Prod.fst hmodel
    subst verdict
    refine ⟨false, next, out, hcompute, hn, ?_, by simp, ?_, hunchanged⟩
    · have hc : ¬ Canonical blob := by
        rw [← model_accepts_iff, hm]
        simp [Except.isOk, Except.toBool]
      simp [hc]
    · intro _
      exact ⟨err, by rw [model_eq_spec, hm]⟩
  | ok result =>
    have hvtrue : verdict = true := by
      simpa [Model.compute, hm] using congrArg Prod.fst hmodel
    have hout : cellBytes out = result := by
      simpa [Model.compute, hm] using congrArg Prod.snd hmodel
    subst verdict
    refine ⟨true, next, out, hcompute, hn, ?_, ?_, by simp, hunchanged⟩
    · have hc : Canonical blob :=
        (model_accepts_iff blob).mp (by simp [hm, Except.isOk, Except.toBool])
      simp [hc]
    · intro _
      rw [model_eq_spec, hm, hout]

/-- The scalar constructor establishes the invariant. -/
theorem scalar_constructor_exists :
    ∃ initial, @cell_extender.CellExtender.new ⟨false, false, false⟩ = ok initial ∧
      StateInvariant initial := by
  exact @new_returns_ok ⟨false, false, false⟩

/-- The IFMA constructor establishes the invariant and selects its kernel. -/
theorem kernel_constructor_exists :
    ∃ initial, @cell_extender.CellExtender.new ⟨true, false, false⟩ = ok initial ∧
      StateInvariant initial ∧ initial.kernel.isSome = true := by
  exact @new_dispatch_refinement ⟨true, false, false⟩

end LeanBlsSimd.Kzg.Extender
