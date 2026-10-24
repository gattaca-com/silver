import LeanBlsSimd.Kzg.PairingInputs
import LeanBlsSimd.Kzg.Refines.PairingLoops

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg.Pairing

set_option maxHeartbeats 4000000
set_option maxRecDepth 16000

theorem pairing_holds_composition [RuntimeFeatures] (h : ComponentContracts)
    (hinterp : InterpolationCorrect)
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
  let powers := computePowers r indices.val.length
  let weights := (List.range indices.val.length).foldl
    (weightStep v.commitments.index_of_cell.val powers.toList) (List.replicate commitments.size Fr.zero)
  let shifted := (List.range indices.val.length).map (shiftedScalar indices.val powers.toList)
  let interpolation := G1.msm (rustG1Bytes.map (fun b => (specPoint b).getD G1.zero))
    (Model.columnRli (indices.val.map (·.val)).toArray evals powers)
  have hplen : powers.size = indices.val.length := size_computePowers _ _
  have hwlen : weights.length = commitments.size := by simp [weights, weights_length]
  have hslen : shifted.length = indices.val.length := by simp [shifted]
  have hzero : FR_ZERO = frEncode Fr.zero := fr_zero_eq
  have hone : FR_ONE = frEncode Fr.one := fr_one_eq
  obtain ⟨powers0, hpowers0, hpowers0v⟩ := resize_fields v.r_powers 0#usize (frEncode Fr.zero)
  have hpowers0e : powers0.val = [] := by simpa [List.resize] using hpowers0v
  obtain ⟨powersV, hpowers, hpowersv⟩ := powers_loop r Fr.one powers0
    { start := 0#usize, «end» := Slice.len indices } (by simp)
    (by simpa only [hpowers0e, List.length_nil, UScalar.ofNatCore_val_eq,
      Nat.sub_zero, Nat.zero_add] using indices.property)
  have hpowersE : powersV.val = powers.toList.map frEncode := by
    simpa only [hpowers0e, List.nil_append, UScalar.ofNatCore_val_eq, Nat.sub_zero,
      powers, computePowers, List.toList_toArray] using hpowersv
  obtain ⟨ll, scratchL, hll, hllrep⟩ := verify_lincomb_refinement h.msm v.proof_points powersV
    proofs powers hp hpowersE (by omega) hvalid.2 v.curve_work
  obtain ⟨weights0, hweights0, hweights0v⟩ := resize_fields v.scalars 0#usize (frEncode Fr.zero)
  have hweights0e : weights0.val = [] := by simpa [List.resize] using hweights0v
  obtain ⟨weights0', hweights0', hweights0'v⟩ := resize_fields weights0
    (alloc.vec.Vec.len v.commitments.unique) (frEncode Fr.zero)
  have hweights0'e : weights0'.val = (List.replicate commitments.size Fr.zero).map frEncode := by
    simpa [hweights0e, List.resize, hunique] using hweights0'v
  obtain ⟨weightsV, hweights, hweightsv⟩ := weights_loop v.commitments.index_of_cell
    powersV weights0' powers.toList (List.replicate commitments.size Fr.zero) hpowersE
    hweights0'e indices.val.length (by omega) (by simpa using hplen.ge)
    (by simpa using hci.2) { start := 0#usize, «end» := Slice.len indices } (by simp) (by simp)
  have hweightsE : weightsV.val = weights.map frEncode := by
    simpa only [UScalar.ofNatCore_val_eq, List.drop_zero, weights] using hweightsv
  obtain ⟨rlc, scratchC, hrlc, hrlcrep⟩ := verify_lincomb_refinement h.msm v.commitment_points weightsV
    commitments weights.toArray hc (by simpa using hweightsE) (by simpa using hwlen.symm)
    hvalid.1 scratchL
  let middle := { v with r_powers := powersV, scalars := weightsV, curve_work := scratchC }
  have hworkL := curveWorkInvariant_sum v.curve_work scratchL _ _ ll hll hv.2.2.2
  have hworkC := curveWorkInvariant_sum scratchL scratchC _ _ rlc hrlc hworkL
  have hmiddle : StateInvariant middle := ⟨hv.1, hv.2.1, hv.2.2.1, hworkC⟩
  obtain ⟨rli, after, hinterpolation, hafter, hrlirep⟩ :=
    hinterp middle hmiddle indices cells evals powers hs hb hcell he hpowersE
  dsimp only [middle] at hinterpolation
  have hframe := interpolation_frame middle after indices cells rli hinterpolation
  have hafterPowers : after.r_powers.val = powers.toList.map frEncode := by
    rw [hframe.1]
    exact hpowersE
  have hafterProofs : after.proof_points.val = proofs.toList.map g1Affine := by
    rw [hframe.2]
    exact hp
  obtain ⟨shifted0, hshifted0, hshifted0v⟩ := resize_fields after.scalars 0#usize (frEncode Fr.zero)
  have hshifted0e : shifted0.val = [] := by simpa [List.resize] using hshifted0v
  have hindices : ∀ i ∈ indices.val, i.val < 128 := by
    intro i hi
    exact hs.2.2.1 i.val (by simp only [List.mem_toArray]; exact List.mem_map.mpr ⟨i, hi, rfl⟩)
  obtain ⟨shiftedV, hshifted, hshiftedv⟩ := shifts_loop after.cosets hafter.2.1 after.r_powers
    shifted0 powers.toList hafterPowers indices (by simpa using hplen.ge) hindices
    { start := 0#usize, «end» := Slice.len indices } (by simp) (by simp)
    (by simpa only [hshifted0e, List.length_nil, UScalar.ofNatCore_val_eq,
      Nat.sub_zero, Nat.zero_add] using indices.property)
  have hshiftedE : shiftedV.val = shifted.map frEncode := by
    simpa only [hshifted0e, List.nil_append, UScalar.ofNatCore_val_eq, List.drop_zero,
      shifted] using hshiftedv
  obtain ⟨rlp, scratchP, hrlp, hrlprep⟩ := verify_lincomb_refinement h.msm after.proof_points shiftedV
    proofs shifted.toArray hafterProofs (by simpa using hshiftedE) (by simp [hproofs, hslen])
    hvalid.2 after.curve_work
  have hvll := g1_msm_valid_of_mem proofs powers hvalid.2
  have hvrlc := g1_msm_valid_of_mem commitments weights.toArray hvalid.1
  have hvrli : G1Valid interpolation := g1_msm_valid_of_mem _ _ setup_model_points_valid
  have hvrlp := g1_msm_valid_of_mem proofs shifted.toArray hvalid.2
  have hworkP := curveWorkInvariant_sum after.curve_work scratchP _ _ rlp hrlp hafter.2.2.2
  have hpair := curveWork_pairing_check_refinement h.pairing scratchP hworkP
    ⟨ll,rlc,rli,rlp⟩ _ _ _ _ hllrep hrlcrep hrlirep hrlprep hvll hvrlc hvrli hvrlp
  have hwmodel := weights_model v.commitments.index_of_cell.val powers commitments.size
  rw [hci.1] at hwmodel
  have hsmodel := shifted_model indices.val powers hplen.ge
  have hmodel : Model.pairingInputs embeddedSetup commitments proofs
      (v.commitments.index_of_cell.val.map (·.val)).toArray
      (indices.val.map (·.val)).toArray evals r =
      #[(G1.msm proofs powers, embeddedSetup.g2Monomial[64]!),
        (G1.add (G1.add (G1.msm commitments weights.toArray) (G1.neg interpolation))
          (G1.msm proofs shifted.toArray), G2.neg embeddedSetup.g2Monomial[0]!)] := by
    unfold Model.pairingInputs
    simp only [List.size_toArray, List.length_map]
    rw [← setup_model_points_eq, ← hwmodel, ← hsmodel]
  let next := { after with scalars := shiftedV, curve_work := scratchP }
  have hfinish := congrArg (fun result : Result Bool => do let b ← result; ok (b, next)) hpair
  simp only [bind_tc_ok, bind_assoc_eq] at hfinish
  refine ⟨next, ?_, hafter.1, hafter.2.1, hafter.2.2.1, hworkP⟩
  rw [hmodel]
  unfold verify.CellBatchVerifier.pairing_holds
  simp only [hzero, hone, hpowers0, hpowers, hll, hweights0, hweights0', hweights,
    hrlc, hinterpolation, hshifted0, hshifted, hrlp,
    bind_tc_ok, Function.uncurry_apply_pair]
  exact hfinish

end LeanBlsSimd.Kzg.Pairing

namespace LeanBlsSimd.Kzg

theorem pairing_holds_refinement [RuntimeFeatures] (h : ComponentContracts)
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
        (indices.val.map (·.val)).toArray evals r), next) ∧ StateInvariant next :=
  Pairing.pairing_holds_composition h (interpolation_commitment_refinement h)
    v hv indices cells commitments proofs evals r hb hs hc hp hcell he hunique hci hproofs hvalid

end LeanBlsSimd.Kzg
