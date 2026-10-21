import LeanBlsSimd.Kzg.Refines

open Aeneas Aeneas.Std Result
open EthCryptographySpecs Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls
open LeanBlsSimd LeanBlsSimd.Kzg

namespace silver_kzg.Kzg

theorem scalar_decode_populates_evaluations [e : KzgExternals]
    (hblst : BlstCorrect e) (hg1 : UncompressG1.BlstMatchesSpec)
    (v : verify.CellBatchVerifier) (hscalar : v.kernel = none)
    (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (hb : cells.val.length * 2048 ≤ Isize.max.toNat) :
    ∃ next, verify.CellBatchVerifier.decode_cells v cells =
        ok ((cellElements cells.val).all Option.isSome, next) ∧
      next.evaluations.val =
        (((cellElements cells.val).takeWhile Option.isSome).filterMap id).map frEncode ∧
      next.setup = v.setup ∧ next.cosets = v.cosets := by
  obtain ⟨next, hcall, hevaluations, hsetup, hcosets⟩ :=
    decode_cells_refines hblst hg1 v cells hb
  exact ⟨next, hcall, hevaluations hscalar, hsetup, hcosets⟩

theorem kernel_interpolates_cells [e : KzgExternals]
    (hblst : BlstCorrect e) (hg1 : UncompressG1.BlstMatchesSpec)
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
  apply interpolation_commitment_refines hblst hg1 v hv indices cells evals powers hs hb hcell
  · simp [hkernel]
  · exact hp

theorem pairing_consumes_cells [e : KzgExternals]
    (hblst : BlstCorrect e) (hg1 : UncompressG1.BlstMatchesSpec)
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
  exact pairing_holds_refines hblst hg1 v hv indices cells commitments proofs evals r hb hs
    hc hp hcell he hunique hci hproofs hvalid

end silver_kzg.Kzg
