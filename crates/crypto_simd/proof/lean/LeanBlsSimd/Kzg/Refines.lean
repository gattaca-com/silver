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

theorem same_bytes_refines (a b : Aeneas.Std.Array U8 48#usize) :
    verify.same_bytes a b = ok (arrayBytes a == arrayBytes b) := by
  exact same_bytes_refinement a b

theorem deduplicate_refines (old : verify.Deduplicated)
    (cs : Slice (Aeneas.Std.Array U8 48#usize)) :
    ∃ result, verify.Deduplicated.fill old cs = ok result ∧
      ((result.unique.val.map arrayBytes).toArray,
        (result.index_of_cell.val.map (·.val)).toArray) =
        Model.deduplicate (cs.val.map arrayBytes).toArray := by
  exact deduplicate_refinement old cs

theorem decode_points_refines [RuntimeFeatures] (hg1 : LeanBlsSimd.G1DecoderCorrect)
    (encodings : Slice (Aeneas.Std.Array U8 48#usize))
    (decoded : alloc.vec.Vec (Option blst.blst_p1_affine))
    (points : alloc.vec.Vec blst.blst_p1_affine) :
    ∃ resultDecoded resultPoints,
      verify.decode_points encodings decoded points =
        ok ((encodings.val.map specVerdict).all Option.isSome, resultDecoded, resultPoints) ∧
      resultDecoded.val = encodings.val.map specVerdict ∧
      resultPoints.val = ((encodings.val.map specVerdict).takeWhile Option.isSome).filterMap id := by
  exact decode_points_refinement hg1 encodings decoded points

def cellElements (cells : List (Aeneas.Std.Array U8 2048#usize)) : List (Option Fr) :=
  cells.flatMap fun cell => (List.range 64).map fun j =>
    (bytesToBlsField ((arrayBytes cell).extract (32*j) (32*(j+1)))).toOption

theorem decode_cells_refines (hbytes : FrBytesCorrect)
    (v : verify.CellBatchVerifier) (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (hb : cells.val.length * 2048 ≤ Isize.max.toNat) :
    ∃ next, verify.CellBatchVerifier.decode_cells v cells =
      ok ((cellElements cells.val).all Option.isSome, next) ∧
      (v.kernel = none → next.evaluations.val =
        (((cellElements cells.val).takeWhile Option.isSome).filterMap id).map frEncode) ∧
      next.setup = v.setup ∧ next.cosets = v.cosets := by
  obtain ⟨next, hcall, he, hs, hc, _⟩ := decode_cells_refinement hbytes v cells hb
  exact ⟨next, hcall, he, hs, hc⟩

theorem challenge_refines (hsha : ShaCorrect) (hbytes : FrBytesCorrect)
    (unique : Slice (Aeneas.Std.Array U8 48#usize)) (ci : Slice Usize) (indices : Slice U64)
    (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (ps : Slice (Aeneas.Std.Array U8 48#usize))
    (hlen : ci.val.length = indices.val.length ∧ cells.val.length = indices.val.length ∧
      ps.val.length = indices.val.length) :
    challenge.challenge_in_parts unique ci indices cells ps =
      ok (frEncode (Fr.hashToBlsField (Model.challengePreimage
        (unique.val.map arrayBytes).toArray (ci.val.map (·.val)).toArray
        (indices.val.map (·.val)).toArray (cells.val.map arrayBytes).toArray
        (ps.val.map arrayBytes).toArray))) := by
  exact challenge_refinement hsha hbytes unique ci indices cells ps hlen

theorem challenge_preimage_eq_spec (unique : _root_.Array Bytes48)
    (ci indices : _root_.Array Nat) (cells : _root_.Array Cell) (ps : _root_.Array Bytes48)
    (evals : _root_.Array CosetEvals)
    (hlen : ci.size = indices.size ∧ cells.size = indices.size ∧ ps.size = indices.size)
    (hdecode : cells.mapM cellToCosetEvals = .ok evals) :
    Fr.hashToBlsField (Model.challengePreimage unique ci indices cells ps) =
      computeVerifyCellKzgProofBatchChallenge unique ci indices evals ps := by
  exact challenge_preimage_spec unique ci indices cells ps evals hlen hdecode

theorem reverse_bits_refines (index : Usize) (bits : U32)
    (hb : bits.val ≤ Usize.numBits) :
    domain.reverse_bits index bits =
      ok ⟨BitVec.ofNat _ (BitReversal.reverseBitsAux index.val 0 bits.val)⟩ := by
  exact reverse_bits_refinement index bits hb

theorem roots_refines (hfr : FrCorrect) (logOrder : U32)
    (hl : logOrder.val = 6 ∨ logOrder.val = 13) :
    ∃ rs, domain.roots_of_unity logOrder = ok rs ∧
      rs.val = (Model.roots logOrder.val).toList.map frEncode := by
  exact roots_refinement hfr logOrder hl

theorem inverse_fft_refines (hfr : FrCorrect)
    (out input roots : Slice blst.blst_fr) (values : _root_.Array Fr)
    (ho : out.val.length = 64) (hv : values.size = 64)
    (hi : input.val = values.toList.map frEncode)
    (hr : roots.val = (Model.inverseRoots (Model.roots 6)).toList.map frEncode) :
    ∃ result, fft.inverse_fft out input roots (frEncode (Fr.ofNat 64).inverse) = ok result ∧
      result.val =
        (Model.inverseFft values (Model.inverseRoots (Model.roots 6)) (Fr.ofNat 64).inverse).toList.map
          frEncode := by
  exact inverse_fft_refinement hfr out input roots values ho hv hi hr

theorem interpolation_commitment_refines [RuntimeFeatures] (h : ExternalsCorrect)
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
  exact interpolation_commitment_refinement h v hv indices cells evals powers hs hb hcell he hp

theorem pairing_holds_refines [RuntimeFeatures] (h : ExternalsCorrect)
    (v : verify.CellBatchVerifier) (hv : StateInvariant v) (indices : Slice U64)
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
        (indices.val.map (·.val)).toArray evals r), next) ∧ StateInvariant next := by
  exact pairing_holds_refinement h v hv indices cells commitments proofs evals r hb hs
    hc hp hcell he hunique hci hproofs hvalid

end LeanBlsSimd.Kzg
