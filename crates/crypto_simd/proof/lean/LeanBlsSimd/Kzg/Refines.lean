import LeanBlsSimd.Portable.Decode.Correct
import LeanBlsSimd.Kzg.Statements
import LeanBlsSimd.Kzg.Extender.Statements
import LeanBlsSimd.Kzg.Refines.Bytes
import LeanBlsSimd.Kzg.Refines.Bits
import LeanBlsSimd.Kzg.Refines.Points
import LeanBlsSimd.Kzg.Refines.Roots
import LeanBlsSimd.Kzg.Refines.Cells
import LeanBlsSimd.Kzg.Refines.Deduplicate
import LeanBlsSimd.Kzg.ByteSerialization
import LeanBlsSimd.Kzg.Refines.Challenge
import LeanBlsSimd.Kzg.Refines.Fft
import LeanBlsSimd.Kzg.Refines.InterpolationCommitment
import LeanBlsSimd.Kzg.Refines.Pairing

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg

def cellElements (cells : List (Aeneas.Std.Array U8 2048#usize)) : List (Option Fr) :=
  cells.flatMap fun cell => (List.range 64).map fun j =>
    (bytesToBlsField ((arrayBytes cell).extract (32*j) (32*(j+1)))).toOption

theorem decode_cells_refines
    (v : verify.CellBatchVerifier) (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (hb : cells.val.length * 2048 ≤ Isize.max.toNat) :
    ∃ next, verify.CellBatchVerifier.decode_cells v cells =
      ok ((cellElements cells.val).all Option.isSome, next) ∧
      (v.kernel = none → next.evaluations.val =
        (((cellElements cells.val).takeWhile Option.isSome).filterMap id).map frEncode) ∧
      next.setup = v.setup ∧ next.cosets = v.cosets := by
  obtain ⟨next, hcall, he, hs, hc, _⟩ := decode_cells_refinement v cells hb
  exact ⟨next, hcall, he, hs, hc⟩

theorem interpolation_commitment_refines [RuntimeFeatures]
    (v : verify.CellBatchVerifier) (hv : StateInvariant v) (indices : Slice U64)
    (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (evals : _root_.Array CosetEvals) (powers : _root_.Array Fr)
    (hs : Model.RliInputs (indices.val.map (·.val)).toArray evals powers)
    (hb : indices.val.length * 2048 ≤ Isize.max.toNat)
    (hcell : InterpolationKernel.CellsRep cells evals)
    (he : v.kernel = none → v.evaluations.val = (evals.toList.flatMap _root_.Array.toList).map frEncode)
    (hp : v.r_powers.val = powers.toList.map frEncode) :
    ∃ point next, verify.CellBatchVerifier.interpolation_commitment v indices cells = ok (point, next) ∧
      StateInvariant next ∧
      G1Rep point (G1.msm
        (rustG1Bytes.map (fun b => (specPoint b).getD G1.zero))
        (Model.columnRli (indices.val.map (·.val)).toArray evals powers)) := by
  exact interpolation_commitment_refinement v hv indices cells evals powers hs hb hcell he hp

theorem pairing_holds_refines [RuntimeFeatures] [KzgExternals]
    (v : verify.CellBatchVerifier) (hv : StateInvariant v)
    (hblst : BlstPairing.CorrectFor v.curve_work) (indices : Slice U64)
    (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (commitments proofs : _root_.Array G1) (evals : _root_.Array CosetEvals) (r : Fr)
    (hb : indices.val.length * 2048 ≤ Isize.max.toNat)
    (hs : Model.RliInputs (indices.val.map (·.val)).toArray evals
      (computePowers r indices.val.length))
    (hc : v.commitment_points.val = commitments.toList.map g1Affine)
    (hp : v.proof_points.val = proofs.toList.map g1Affine)
    (hcell : InterpolationKernel.CellsRep cells evals)
    (he : v.kernel = none → v.evaluations.val = (evals.toList.flatMap _root_.Array.toList).map frEncode)
    (hunique : v.commitments.unique.val.length = commitments.size)
    (hci : v.commitments.index_of_cell.val.length = indices.val.length ∧
      ∀ i ∈ v.commitments.index_of_cell.val, i.val < commitments.size)
    (hproofs : proofs.size = indices.val.length)
    (hvalid : (∀ p ∈ commitments, G1Valid p) ∧ (∀ p ∈ proofs, G1Valid p)) :
    ∃ next, verify.CellBatchVerifier.pairing_holds v (frEncode r) indices cells =
      ok (Bls.pairingCheck (Model.pairingInputs embeddedSetup commitments proofs
        (v.commitments.index_of_cell.val.map (·.val)).toArray
        (indices.val.map (·.val)).toArray evals r), next) ∧ StateInvariant next ∧
      CurveWork.isLanes next.curve_work = CurveWork.isLanes v.curve_work := by
  obtain ⟨next, hrun, hnext⟩ := pairing_holds_refinement v hv hblst indices cells
    commitments proofs evals r hb hs hc hp hcell he hunique hci hproofs hvalid
  exact ⟨next, hrun, hnext,
    congrArg Prod.snd (Routes.pairing_holds_route v next _ indices cells _ hrun)⟩

end LeanBlsSimd.Kzg
