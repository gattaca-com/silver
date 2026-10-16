import LeanBlsSimd.Kzg.ModelPairingShift
import LeanBlsSimd.Kzg.G1Compression
import LeanBlsSimd.Kzg.PairingRepresentation
import LeanBlsSimd.Kzg.InterpolationModel
import Mathlib.Data.List.Nodup

open EthCryptographySpecs Bls Kzg

namespace LeanBlsSimd.Kzg.ModelPairing

set_option maxHeartbeats 3000000
set_option maxRecDepth 16000

local instance modelPairingByteArrayLawfulBEq : LawfulBEq ByteArray where
  rfl := by
    intro a
    change (a.data == a.data) = true
    simp
  eq_of_beq := by
    intro a b h
    apply ByteArray.ext
    exact eq_of_beq h

private theorem pointValue_facts (b : Bytes48) (h : validateKzgG1 b = true) :
    G1.uncompress b = .ok ((specPoint b).getD G1.zero) ∧ G1Valid ((specPoint b).getD G1.zero) := by
  have hs : (specPoint b).isSome = true := by rw [specPoint_isSome, h]
  cases hp : specPoint b with
  | none => simp only [hp, Option.isSome_none, Bool.false_eq_true] at hs
  | some p =>
    simp only [Option.getD_some]
    exact ⟨specPoint_uncompress hp, specPoint_valid hp⟩

private theorem pointValues_valid (bs : Array Bytes48) (h : bs.all validateKzgG1 = true) :
    ∀ p ∈ bs.map (fun b => (specPoint b).getD G1.zero), G1Valid p := by
  intro p hp
  obtain ⟨b, hb, rfl⟩ := Array.mem_map.mp hp
  exact (pointValue_facts b (Array.all_eq_true_iff_forall_mem.mp h b hb)).2

private theorem lincomb_eq (bs : Array Bytes48) (scalars : Array Fr)
    (hs : bs.size = scalars.size) (hv : bs.all validateKzgG1 = true) :
    Model.lincomb bs scalars = .ok (G1.compress (G1.msm (bs.map (fun b => (specPoint b).getD G1.zero)) scalars)) := by
  have hd : bs.mapM (fun b => match G1.uncompress b with
      | .ok p => Except.ok p
      | .error _ => Except.error KzgError.invalidG1Point) =
      .ok (bs.map (fun b => (specPoint b).getD G1.zero)) := by
    apply array_mapM_ok
    intro b hb
    rw [(pointValue_facts b (Array.all_eq_true_iff_forall_mem.mp hv b hb)).1]
  unfold Model.lincomb
  simp only [← hs, ne_eq, not_true_eq_false, if_false]
  by_cases hz : bs.size = 0
  · have hm : G1.msm (bs.map (fun b => (specPoint b).getD G1.zero)) scalars = G1.zero := by
      rw [G1.msm_eq_msmModel]
      simp only [G1.msmModel, Array.size_map, hz, Nat.zero_le, if_true]
    simp only [hz, if_true, hm, Bind.bind, Except.bind, Pure.pure, Except.pure]
  · simp only [hz, if_false, Bind.bind, Except.bind, Pure.pure, Except.pure]
    change (do
      let ps ← bs.mapM (fun b => match G1.uncompress b with
        | .ok p => Except.ok p
        | .error _ => Except.error KzgError.invalidG1Point)
      Except.ok (G1.compress (G1.msm ps scalars))) = _
    rw [hd]
    rfl

private theorem lincomb_decode (bs : Array Bytes48) (scalars : Array Fr)
    (hs : bs.size = scalars.size) (hv : bs.all validateKzgG1 = true) :
    ∃ q,
      Model.lincomb bs scalars = .ok (G1.compress (G1.msm (bs.map (fun b => (specPoint b).getD G1.zero)) scalars)) ∧
      G1.uncompress (G1.compress (G1.msm (bs.map (fun b => (specPoint b).getD G1.zero)) scalars)) = .ok q ∧
      G1Valid q ∧ G1Valid (G1.msm (bs.map (fun b => (specPoint b).getD G1.zero)) scalars) ∧
      q.isInfinity = (G1.msm (bs.map (fun b => (specPoint b).getD G1.zero)) scalars).isInfinity ∧
      q.toAffine = (G1.msm (bs.map (fun b => (specPoint b).getD G1.zero)) scalars).toAffine := by
  have hp := g1_msm_valid_of_mem (bs.map (fun b => (specPoint b).getD G1.zero)) scalars (pointValues_valid bs hv)
  obtain ⟨q, hq, hvalid, hinf, haff⟩ := g1_uncompress_compress hp
  exact ⟨q, lincomb_eq bs scalars hs hv, hq, hvalid, hp, hinf, haff⟩

private theorem nodup_idxOf (bs : Array Bytes48) (hn : bs.toList.Nodup)
    (i : Nat) (hi : i < bs.size) : bs.idxOf? bs[i]! = some i := by
  cases bs with
  | mk xs =>
    simp only [List.idxOf?_toArray, List.getElem!_toArray] at *
    rw [getElem!_pos xs i hi]
    apply List.idxOf?_eq_some_iff.mpr
    refine ⟨hi, rfl, ?_⟩
    intro j hj heq
    have := hn.getElem_inj_iff.mp heq
    omega

private theorem duplicate_check (bs : Array Bytes48) (hn : bs.toList.Nodup) :
    (Array.range bs.size).any (fun i => bs.idxOf? bs[i]! ≠ some i) = false := by
  apply Array.any_eq_false.mpr
  intro j hj
  have hj' : j < bs.size := by simpa only [Array.size_range] using hj
  simpa only [Array.getElem_range, nodup_idxOf bs hn j hj', ne_eq, not_true_eq_false,
    decide_false, Bool.false_eq_true] using Bool.false_ne_true

private theorem weights_size (ci : Array Nat) (powers : Array Fr) (ks : List Nat)
    (initial : Array Fr) :
    (ks.foldl (fun weights k =>
      let i := ci[k]!
      weights.set! i (weights[i]! + powers[k]!)) initial).size = initial.size := by
  induction ks generalizing initial with
  | nil => rfl
  | cons k ks ih =>
    simp only [List.foldl_cons]
    rw [ih]
    simp

private theorem totals_length (columns : List Fr) (used : List Bool) (ks : List Nat)
    (initial : List Fr) (hi : initial.length = 64) :
    (ks.foldl (Interpolation.totalStep columns used) initial).length = 64 := by
  induction ks generalizing initial with
  | nil => exact hi
  | cons k ks ih =>
    exact ih _ (Interpolation.totalStep_length columns used initial k hi)

private theorem columnRli_size (indices : Array Nat) (evals : Array CosetEvals)
    (powers : Array Fr) (hs : Model.RliInputs indices evals powers) :
    (Model.columnRli indices evals powers).size = 64 := by
  rw [← Interpolation.aggregate_columnRli indices evals powers hs]
  simp only [List.size_toArray]
  exact totals_length _ _ _ _ (List.length_replicate ..)

private theorem setup_validated : rustG1Bytes.all validateKzgG1 = true := by
  apply Array.all_eq_true_iff_forall_mem.mpr
  intro b hb
  obtain ⟨p, hp⟩ := embedded_setup_matches.2.2.2.2.2.2 b hb
  rw [← specPoint_isSome, hp]
  rfl

private theorem setup_bytes_size : rustG1Bytes.size = 64 := by simp [rustG1Bytes]

private theorem implPure_eq
    (setup : TrustedSetup) (unique : Array Bytes48) (ci indices : Array Nat)
    (evals : Array CosetEvals) (proofs : Array Bytes48)
    (hshape : ci.size = indices.size ∧ evals.size = indices.size ∧ proofs.size = indices.size)
    (hci : ∀ i ∈ ci, i < unique.size) (hn : unique.toList.Nodup)
    (hi : ∀ i ∈ indices, i < 128) :
    let powers := computePowers
      (computeVerifyCellKzgProofBatchChallenge unique ci indices evals proofs) indices.size
    let weights := (Array.range indices.size).foldl (init := Array.replicate unique.size Fr.zero)
      fun weights k => weights.set! ci[k]! (weights[ci[k]!]! + powers[k]!)
    let coeffs := Model.columnRli indices evals powers
    let shifted := (Array.range indices.size).map
      (fun k => powers[k]! * Fr.powNat (Model.cosetShift indices[k]!) 64)
    ∀ (bL bC bI bP : ByteArray) (qL qC qI qP : G1),
    Model.lincomb proofs powers = .ok bL → G1.uncompress bL = .ok qL →
    Model.lincomb unique weights = .ok bC → G1.uncompress bC = .ok qC →
    Model.lincomb (setup.g1MonomialBytes.extract 0 64) coeffs = .ok bI →
    G1.uncompress bI = .ok qI →
    Model.lincomb proofs shifted = .ok bP → G1.uncompress bP = .ok qP →
    Model.implPure setup Model.columnStep unique ci indices evals proofs =
      .ok (Bls.pairingCheck #[(qL, setup.g2Monomial[64]!),
        (G1.add (G1.add qC (G1.neg qI)) qP, G2.neg setup.g2Monomial[0]!)]) := by
  dsimp only
  intro bL bC bI bP qL qC qI qP hL hdL hC hdC hI hdI hP hdP
  have hlen1 : ¬ indices.size ≠ ci.size := by omega
  have hlen2 : ¬ evals.size ≠ ci.size := by omega
  have hlen3 : ¬ proofs.size ≠ ci.size := by omega
  have hbounds : ci.any (· ≥ unique.size) = false := by
    apply Array.any_eq_false.mpr
    intro j hj
    have hb := hci ci[j] (Array.getElem_mem hj)
    simpa using Nat.not_le.mpr hb
  have hdups := duplicate_check unique hn
  have hshift := weighted_powers_eq indices
    (computePowers (computeVerifyCellKzgProofBatchChallenge unique ci indices evals proofs)
      indices.size) hi
  simp only [Constants.FIELD_ELEMENTS_PER_CELL, Bind.bind, Except.bind, Pure.pure,
    Except.pure] at hshift
  simp only [Model.implPure, hlen1, hlen2, hlen3, if_false, hbounds, hdups,
    Bool.false_eq_true, Constants.FIELD_ELEMENTS_PER_CELL, hL, hC, hI, hP,
    Bind.bind, Except.bind, Pure.pure, Except.pure, hdL, hdC, hdI, hdP,
    Except.toOption, Option.get!_some, Model.columnStep, hshift]

private theorem pairingInputs_eq
    (setup : TrustedSetup) (unique proofs : Array Bytes48) (ci indices : Array Nat)
    (evals : Array CosetEvals) (r : Fr) (monomial : Array G1)
    (hm : monomial = (setup.g1MonomialBytes.extract 0 64).map
      (fun b => (G1.uncompress b).toOption.getD G1.zero)) :
    Model.pairingInputs setup
      (unique.map (fun b => (specPoint b).getD G1.zero))
      (proofs.map (fun b => (specPoint b).getD G1.zero)) ci indices evals r =
    let powers := computePowers r indices.size
    let weights := (Array.range indices.size).foldl (init := Array.replicate unique.size Fr.zero)
      fun weights k => weights.set! ci[k]! (weights[ci[k]!]! + powers[k]!)
    let coeffs := Model.columnRli indices evals powers
    let shifted := (Array.range indices.size).map
      (fun k => powers[k]! * Fr.powNat (Model.cosetShift indices[k]!) 64)
    #[(G1.msm (proofs.map (fun b => (specPoint b).getD G1.zero)) powers, setup.g2Monomial[64]!),
      (G1.add (G1.add (G1.msm (unique.map (fun b => (specPoint b).getD G1.zero)) weights)
        (G1.neg (G1.msm monomial coeffs)))
        (G1.msm (proofs.map (fun b => (specPoint b).getD G1.zero)) shifted),
        G2.neg setup.g2Monomial[0]!)] := by
  simp only [Model.pairingInputs, Array.size_map, ← hm]

end LeanBlsSimd.Kzg.ModelPairing

namespace LeanBlsSimd.Kzg

open ModelPairing

set_option maxRecDepth 16000

theorem model_pairing_refinement
    (unique : Array Bytes48) (ci indices : Array Nat)
    (evals : Array CosetEvals) (proofs : Array Bytes48)
    (hshape : ci.size = indices.size ∧ evals.size = indices.size ∧ proofs.size = indices.size)
    (hci : ∀ i ∈ ci, i < unique.size) (hn : unique.toList.Nodup)
    (hi : ∀ i ∈ indices, i < 128) (he : ∀ ys ∈ evals, ys.size = 64)
    (hc : unique.all validateKzgG1 = true) (hp : proofs.all validateKzgG1 = true) :
    let r := computeVerifyCellKzgProofBatchChallenge unique ci indices evals proofs
    Model.implPure embeddedSetup Model.columnStep unique ci indices evals proofs =
      .ok (Bls.pairingCheck (Model.pairingInputs embeddedSetup
        (unique.map (fun b => (specPoint b).getD G1.zero))
        (proofs.map (fun b => (specPoint b).getD G1.zero)) ci indices evals r)) := by
  let r := computeVerifyCellKzgProofBatchChallenge unique ci indices evals proofs
  let powers := computePowers r indices.size
  let weights := (Array.range indices.size).foldl (init := Array.replicate unique.size Fr.zero)
    fun weights k =>
      let i := ci[k]!
      weights.set! i (weights[i]! + powers[k]!)
  let coeffs := Model.columnRli indices evals powers
  let shifted := (Array.range indices.size).map
    (fun k => powers[k]! * Fr.powNat (Model.cosetShift indices[k]!) 64)
  have hplen : powers.size = indices.size := size_computePowers _ _
  have hwlen : weights.size = unique.size := by
    simpa only [weights, ← Array.foldl_toList, Array.size_replicate] using
      ModelPairing.weights_size ci powers (Array.range indices.size).toList
        (Array.replicate unique.size Fr.zero)
  have hslen : shifted.size = indices.size := by simp only [shifted, Array.size_map, Array.size_range]
  have hrli : Model.RliInputs indices evals powers := ⟨hshape.2.1.symm, hplen.symm, hi, he⟩
  have hcoeff : coeffs.size = 64 := ModelPairing.columnRli_size indices evals powers hrli
  obtain ⟨ll, hll, hdll, hvll, hvL, hiL, haL⟩ :=
    ModelPairing.lincomb_decode proofs powers (by omega) hp
  obtain ⟨rlc, hrlc, hdrlc, hvrlc, hvC, hiC, haC⟩ :=
    ModelPairing.lincomb_decode unique weights hwlen.symm hc
  obtain ⟨rli, hrliCall, hdrli, hvrli, hvI, hiI, haI⟩ :=
    ModelPairing.lincomb_decode rustG1Bytes coeffs
      (by rw [ModelPairing.setup_bytes_size, hcoeff]) ModelPairing.setup_validated
  obtain ⟨rlp, hrlp, hdrlp, hvrlp, hvP, hiP, haP⟩ :=
    ModelPairing.lincomb_decode proofs shifted (by omega) hp
  have hneg := g1_neg_matches hvrli hvI hiI haI
  have hadd := g1_add_matches hvrlc (g1Valid_neg hvrli) hvC (g1Valid_neg hvI)
    hiC haC hneg.1 hneg.2
  have hright := g1_add_matches (g1Valid_add hvrlc (g1Valid_neg hvrli)) hvrlp
    (g1Valid_add hvC (g1Valid_neg hvI)) hvP hadd.1 hadd.2 hiP haP
  have hpair := pairingCheck_two_congr embeddedSetup.g2Monomial[64]!
    (G2.neg embeddedSetup.g2Monomial[0]!) hiL haL hright.1 hright.2
  have hmodel : Model.pairingInputs embeddedSetup
      (unique.map (fun b => (specPoint b).getD G1.zero))
      (proofs.map (fun b => (specPoint b).getD G1.zero)) ci indices evals r =
      #[(G1.msm (proofs.map (fun b => (specPoint b).getD G1.zero)) powers, embeddedSetup.g2Monomial[64]!),
        (G1.add (G1.add (G1.msm (unique.map (fun b => (specPoint b).getD G1.zero)) weights)
          (G1.neg (G1.msm (rustG1Bytes.map (fun b => (specPoint b).getD G1.zero)) coeffs)))
          (G1.msm (proofs.map (fun b => (specPoint b).getD G1.zero)) shifted),
          G2.neg embeddedSetup.g2Monomial[0]!)] := by
    exact ModelPairing.pairingInputs_eq embeddedSetup unique proofs ci indices evals r
      (rustG1Bytes.map (fun b => (specPoint b).getD G1.zero)) setup_model_points_eq
  have hsetupCall : Model.lincomb (embeddedSetup.g1MonomialBytes.extract 0 64) coeffs =
      .ok (G1.compress (G1.msm (rustG1Bytes.map (fun b => (specPoint b).getD G1.zero)) coeffs)) := by
    rw [embedded_g1_bytes]
    exact hrliCall
  have hcall := ModelPairing.implPure_eq embeddedSetup unique ci indices evals proofs
    hshape hci hn hi _ _ _ _ ll rlc rli rlp hll hdll hrlc hdrlc hsetupCall hdrli hrlp hdrlp
  change Model.implPure embeddedSetup Model.columnStep unique ci indices evals proofs = _
  rw [hmodel]
  exact hcall.trans (congrArg Except.ok hpair)

end LeanBlsSimd.Kzg
