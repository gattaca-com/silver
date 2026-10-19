import LeanBlsSimd.Kzg.Extender.Basic
import LeanBlsSimd.Kzg.Extender.Acceptance
import LeanBlsSimd.Kzg.Extender.Primitives
import LeanBlsSimd.Kzg.Extender.Spec
import LeanBlsSimd.Kzg.Extender.Refines
import LeanBlsSimd.Kzg.SpecExternals

open Aeneas Aeneas.Std Result
open EthCryptographySpecs Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender

theorem new_returns_ok [e : KzgExternals] (hblst : BlstCorrect e) :
    ∃ initial, cell_extender.CellExtender.new = ok initial ∧ StateInvariant initial := by
  exact new_refinement hblst

theorem default_eq_new [KzgExternals] :
    cell_extender.CellExtender.Insts.CoreDefaultDefault.default =
      cell_extender.CellExtender.new := by
  rfl

theorem model_eq_spec (blob : ByteArray) :
    (computeCells blob).run = pure (Model.extend blob) := by
  exact model_spec blob

theorem model_accepts_iff (blob : Blob) :
    (Model.extend (arrayBytes blob)).isOk = true ↔ Canonical blob := by
  exact model_acceptance blob

theorem glue_refinement [e : KzgExternals] (hblst : BlstCorrect e)
    (hbytes : FrToBytesCorrect e)
    (v : cell_extender.CellExtender) (hv : StateInvariant v)
    (blob : Blob) (cells : Cells) :
    ∃ (verdict : Bool) (next : cell_extender.CellExtender) (out : Cells),
      cell_extender.CellExtender.compute v blob cells = ok (verdict, next, out) ∧
      StateInvariant next ∧
      (verdict, cellBytes out) = Model.compute (arrayBytes blob) (cellBytes cells) := by
  exact compute_refinement hblst hbytes v hv blob cells

theorem compute_eq_spec [e : KzgExternals] (hblst : BlstCorrect e)
    (hbytes : FrToBytesCorrect e) :
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
  obtain ⟨initial, hnew, hinitial⟩ := new_returns_ok hblst
  refine ⟨initial, hnew, hinitial, ?_⟩
  intro v hv blob cells
  obtain ⟨verdict, next, out, hcompute, hn, hmodel, hunchanged⟩ :=
    compute_refinement_with_rejection hblst hbytes v hv blob cells
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

theorem spec_instance_nonvacuous :
    BlstCorrect specExternals ∧ FrToBytesCorrect specExternals ∧
      ∃ initial, @cell_extender.CellExtender.new specExternals = ok initial ∧
        StateInvariant initial := by
  refine ⟨specExternals_correct.1, specExternals_fr_to_bytes_correct, ?_⟩
  exact @new_returns_ok specExternals specExternals_correct.1

@[reducible] def specSimdExternals : KzgExternals :=
  { specExternals with simdAvailable := true }

theorem spec_instance_kernel_nonvacuous :
    BlstCorrect specSimdExternals ∧ FrToBytesCorrect specSimdExternals ∧
      ∃ initial, @cell_extender.CellExtender.new specSimdExternals = ok initial ∧
        StateInvariant initial ∧ initial.kernel.isSome = true := by
  have h := specExternals_correct.1
  have hblst : BlstCorrect specSimdExternals :=
    ⟨h.g2_decode, h.fr_bytes, h.fr_u64, h.fr_add, h.fr_sub, h.fr_mul, h.fr_inverse,
      h.hash, h.g1_affine, h.g1_add, h.g1_neg, h.g2_neg, h.lincomb, h.pairing⟩
  exact ⟨hblst, specExternals_fr_to_bytes_correct,
    @new_dispatch_refinement specSimdExternals hblst⟩

end LeanBlsSimd.Kzg.Extender
