import LeanBlsSimd.Kzg.Extender.Statements
import LeanBlsSimd.Kzg.Refines
import LeanBlsSimd.Kzg.Routes

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls
open LeanBlsSimd LeanBlsSimd.Kzg

namespace silver_kzg.Kzg

theorem verify_after_construction [cpu : RuntimeFeatures]
    (input : Input) (hi : input.Representable) :
    ∃ initial verdict next, verify.CellBatchVerifier.new = ok initial ∧
      input.generated initial = ok (verdict, next) ∧ StateInvariant next ∧
      Model.rejectErrors input.embeddedSpec = verdict := by
  obtain ⟨initial, hnew, hs, hcall⟩ := verify_eq_spec
  obtain ⟨verdict, next, hrun, hn, hv⟩ := hcall initial hs input hi
  exact ⟨initial, verdict, next, hnew, hrun, hn, hv⟩

theorem extend_after_construction [cpu : RuntimeFeatures]
    (blob : Extender.Blob) (cells : Extender.Cells) :
    ∃ initial verdict next out, cell_extender.CellExtender.new = ok initial ∧
      cell_extender.CellExtender.compute initial blob cells = ok (verdict, next, out) ∧
      Extender.StateInvariant next ∧ (verdict = true ↔ Extender.Canonical blob) ∧
      (verdict = false → out = cells) := by
  obtain ⟨initial, hnew, hs, hcall⟩ := Extender.compute_eq_spec
  obtain ⟨verdict, next, out, hrun, hn, hv, _, _, hunchanged⟩ := hcall initial hs blob cells
  exact ⟨initial, verdict, next, out, hnew, hrun, hn, hv, hunchanged⟩

theorem scalar_decode_populates_evaluations
    (v : verify.CellBatchVerifier) (hscalar : v.kernel = none)
    (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (hb : cells.val.length * 2048 ≤ Isize.max.toNat) :
    ∃ next, verify.CellBatchVerifier.decode_cells v cells =
        ok ((cellElements cells.val).all Option.isSome, next) ∧
      next.evaluations.val =
        (((cellElements cells.val).takeWhile Option.isSome).filterMap id).map frEncode ∧
      next.setup = v.setup ∧ next.cosets = v.cosets := by
  obtain ⟨next, hcall, hevaluations, hsetup, hcosets⟩ :=
    decode_cells_refines v cells hb
  exact ⟨next, hcall, hevaluations hscalar, hsetup, hcosets⟩

theorem kernel_interpolates_cells [cpu : RuntimeFeatures]
    (v : verify.CellBatchVerifier) (hv : StateInvariant v)
    (kernel : interpolation_kernel.InterpolationKernel) (hkernel : v.kernel = some kernel)
    (indices : Slice U64) (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (evals : _root_.Array CosetEvals) (powers : _root_.Array Fr)
    (hs : Model.RliInputs (indices.val.map (·.val)).toArray evals powers)
    (hb : indices.val.length * 2048 ≤ Isize.max.toNat)
    (hcell : InterpolationKernel.CellsRep cells evals)
    (hp : v.r_powers.val = powers.toList.map frEncode) :
    ∃ point next, verify.CellBatchVerifier.interpolation_commitment v indices cells =
        ok (point, next) ∧ StateInvariant next ∧
      G1Rep point (G1.msm
        (rustG1Bytes.map (fun b => (specPoint b).getD G1.zero))
        (Model.columnRli (indices.val.map (·.val)).toArray evals powers)) := by
  apply interpolation_commitment_refines v hv indices cells evals powers hs hb hcell
  · simp [hkernel]
  · exact hp

theorem pairing_consumes_cells [cpu : RuntimeFeatures]
    (v : verify.CellBatchVerifier) (hv : StateInvariant v)
    (indices : Slice U64) (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (commitments proofs : _root_.Array G1) (evals : _root_.Array CosetEvals) (r : Fr)
    (hb : indices.val.length * 2048 ≤ Isize.max.toNat)
    (hs : Model.RliInputs (indices.val.map (·.val)).toArray evals
      (computePowers r indices.val.length))
    (hc : v.commitment_points.val = commitments.toList.map g1Affine)
    (hp : v.proof_points.val = proofs.toList.map g1Affine)
    (hcell : InterpolationKernel.CellsRep cells evals)
    (he : v.kernel = none →
      v.evaluations.val = (evals.toList.flatMap _root_.Array.toList).map frEncode)
    (hunique : v.commitments.unique.val.length = commitments.size)
    (hci : v.commitments.index_of_cell.val.length = indices.val.length ∧
      ∀ i ∈ v.commitments.index_of_cell.val, i.val < commitments.size)
    (hproofs : proofs.size = indices.val.length)
    (hvalid : (∀ p ∈ commitments, G1Valid p) ∧ (∀ p ∈ proofs, G1Valid p)) :
    ∃ next, verify.CellBatchVerifier.pairing_holds v (frEncode r) indices cells =
      ok (Bls.pairingCheck (Model.pairingInputs embeddedSetup commitments proofs
        (v.commitments.index_of_cell.val.map (·.val)).toArray
        (indices.val.map (·.val)).toArray evals r), next) ∧ StateInvariant next := by
  exact pairing_holds_refines v hv indices cells commitments proofs evals r hb hs
    hc hp hcell he hunique hci hproofs hvalid


theorem msm_accepts_arbitrary_aligned_lengths
    (state : msm8.Msm8) (ps : Slice blst.blst_p1_affine)
    (words : Slice (Aeneas.Std.Array U64 4#usize))
    (hlen : ps.val.length = words.val.length)
    (hp : ∀ p ∈ ps.val, G1AffineValid p)
    (hw : ∀ w ∈ words.val, limbs w.val < Fr.modulus) :
    ∃ point next, state.msm ps words = ok (point, next) ∧
      G1Rep point (G1.msm (ps.val.map g1ReadAffine).toArray
        (words.val.map (fun w => Fr.ofNat (limbs w.val))).toArray) := by
  exact LeanBlsSimd.Msm8.msm_refinement state ps words hlen hp hw

theorem kernel_lincomb_requires_no_blst_law [RuntimeFeatures]
    (scratch : verify.CurveWork) (hroute : CurveWork.isLanes scratch = true)
    (ps : Slice blst.blst_p1_affine) (fs : Slice blst.blst_fr)
    (hlen : ps.val.length = fs.val.length)
    (hp : ∀ p ∈ ps.val, G1AffineValid p) (hf : ∀ f ∈ fs.val, FrReduced f) :
    ∃ point next, scratch.sum ps fs = ok (point, next) ∧ CurveWork.isLanes next = true ∧
      G1Rep point (G1.msm (ps.val.map g1ReadAffine).toArray (fs.val.map frRead).toArray) := by
  exact verify_lincomb_raw_kernel_refinement scratch hroute ps fs hlen hp hf

theorem verifier_preserves_kernel_choices [RuntimeFeatures]
    (self next : verify.CellBatchVerifier) (commitments : Slice (Aeneas.Std.Array U8 48#usize))
    (indices : Slice U64) (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (proofs : Slice (Aeneas.Std.Array U8 48#usize)) (verdict : Bool)
    (h : self.verify commitments indices cells proofs = ok (verdict, next)) :
    next.kernel.isSome = self.kernel.isSome ∧ CurveWork.isLanes next.curve_work = CurveWork.isLanes self.curve_work := by
  exact Routes.verify_preserves_routes self next commitments indices cells proofs verdict h

end silver_kzg.Kzg
