import LeanBlsSimd.Kzg.ModelFront
import LeanBlsSimd.Kzg.Contracts
import LeanBlsSimd.Kzg.Setup
import LeanBlsSimd.Kzg.G1Compression
import LeanBlsSimd.Kzg.Refines.Checks
import LeanBlsSimd.Kzg.Refines.Points
import LeanBlsSimd.Kzg.Refines.Cells
import LeanBlsSimd.Kzg.Refines.Frames
import LeanBlsSimd.Kzg.Refines.Deduplicate
import LeanBlsSimd.Kzg.Refines.Challenge

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg.Verify

set_option maxRecDepth 16000
set_option maxHeartbeats 4000000

def pointValues (bs : _root_.Array ByteArray) : _root_.Array G1 :=
  bs.map fun b => (specPoint b).getD G1.zero

def cellValues (cells : List (Aeneas.Std.Array U8 2048#usize)) : _root_.Array CosetEvals :=
  (cells.map (fun c => ModelFront.fieldValues (arrayBytes c))).toArray

theorem arrayBytes_size {n : Usize} (b : Aeneas.Std.Array U8 n) :
    (arrayBytes b).size = n.val := by simp [arrayBytes, bytes, ByteArray.size, b.property]

private theorem takeWhile_all {α : Type} (xs : List α) (p : α → Bool)
    (h : xs.all p = true) : xs.takeWhile p = xs := by
  induction xs with
  | nil => rfl
  | cons x xs ih =>
    simp only [List.all_cons, Bool.and_eq_true] at h
    simp [h.1, ih h.2]

private theorem pointOptions_accepted (bs : List (Aeneas.Std.Array U8 48#usize))
    (h : (bs.map specVerdict).all Option.isSome = true) :
    (bs.map specVerdict).filterMap id =
      bs.map (fun b => g1Affine ((specPoint (arrayBytes b)).getD G1.zero)) := by
  induction bs with
  | nil => rfl
  | cons b bs ih =>
    simp only [List.map_cons, List.all_cons, Bool.and_eq_true] at h
    cases hb : specPoint (arrayBytes b) with
    | none => simp [specVerdict, hb] at h
    | some p =>
      simpa [specVerdict, hb] using congrArg (g1Affine p :: ·) (ih h.2)

theorem pointValues_size (bs : _root_.Array ByteArray) : (pointValues bs).size = bs.size := by
  simp [pointValues]

theorem decoded_points_acceptance (bs : List (Aeneas.Std.Array U8 48#usize)) :
    (bs.map specVerdict).all Option.isSome =
      ((bs.map arrayBytes).toArray).all (fun b => (specPoint b).isSome) := by
  simp [List.all_map, specVerdict, Function.comp_def]

theorem pointValues_valid (bs : _root_.Array ByteArray)
    (h : bs.all (fun b => (specPoint b).isSome) = true)
    (hvalid : ∀ b p, specPoint b = some p → G1Valid p) :
    ∀ p ∈ pointValues bs, G1Valid p := by
  intro p hp
  simp only [pointValues, _root_.Array.mem_map] at hp
  obtain ⟨b, hb, rfl⟩ := hp
  have hsome : (specPoint b).isSome = true := (_root_.Array.all_eq_true'.mp h) b hb
  cases hd : specPoint b with
  | none => simp [hd] at hsome
  | some q => simpa [hd] using hvalid b q hd

theorem decoded_points_values (bs : List (Aeneas.Std.Array U8 48#usize))
    (h : (bs.map specVerdict).all Option.isSome = true) :
    ((bs.map specVerdict).takeWhile Option.isSome).filterMap id =
      (pointValues (bs.map arrayBytes).toArray).toList.map g1Affine := by
  rw [takeWhile_all _ _ h, pointOptions_accepted bs h]
  simp [pointValues, List.map_map, Function.comp_def]

theorem decode_commitments_step [cpu : RuntimeFeatures] (h : LeanBlsSimd.G1DecoderCorrect)
    (v : verify.CellBatchVerifier) :
    ∃ decoded points,
      verify.CellBatchVerifier.decode_commitments v =
        ok ((v.commitments.unique.val.map specVerdict).all Option.isSome,
          { v with decoded := decoded, commitment_points := points }) ∧
      points.val =
        ((v.commitments.unique.val.map specVerdict).takeWhile Option.isSome).filterMap id := by
  obtain ⟨decoded, points, hcall, _, hpoints⟩ := decode_points_refinement h
    (alloc.vec.Vec.deref v.commitments.unique) v.decoded v.commitment_points
  refine ⟨decoded, points, ?_, hpoints⟩
  simp only [verify.CellBatchVerifier.decode_commitments, hcall, bind_tc_ok,
    Function.uncurry_apply_pair]
  rfl

theorem decode_proofs_step [cpu : RuntimeFeatures] (h : LeanBlsSimd.G1DecoderCorrect)
    (v : verify.CellBatchVerifier) (ps : Slice (Aeneas.Std.Array U8 48#usize)) :
    ∃ decoded points,
      verify.CellBatchVerifier.decode_proofs v ps =
        ok ((ps.val.map specVerdict).all Option.isSome,
          { v with decoded := decoded, proof_points := points }) ∧
      points.val = ((ps.val.map specVerdict).takeWhile Option.isSome).filterMap id := by
  obtain ⟨decoded, points, hcall, _, hpoints⟩ := decode_points_refinement h ps v.decoded v.proof_points
  refine ⟨decoded, points, ?_, hpoints⟩
  simp only [verify.CellBatchVerifier.decode_proofs, hcall, bind_tc_ok,
    Function.uncurry_apply_pair]

theorem cells_decode_option (cells : List (Aeneas.Std.Array U8 2048#usize)) :
    (((cells.map arrayBytes).toArray).mapM cellToCosetEvals).toOption =
      if (decodedCellElements cells).all Option.isSome then some (cellValues cells) else none := by
  rw [_root_.Array.mapM_eq_mapM_toList, ModelFront.toOption_map]
  simp only
  rw [ModelFront.cells_decode_option _ (by
    intro b hb
    obtain ⟨c, _, rfl⟩ := List.mem_map.mp hb
    simpa using arrayBytes_size c)]
  simp only [List.flatMap_map, ModelFront.fieldOptions]
  change (if (decodedCellElements cells).all Option.isSome then
    some ((cells.map arrayBytes).map ModelFront.fieldValues) else none).map List.toArray = _
  cases (decodedCellElements cells).all Option.isSome <;> simp [cellValues, List.map_map, Function.comp_def]

theorem cells_decode_facts (cells : List (Aeneas.Std.Array U8 2048#usize))
    (h : (decodedCellElements cells).all Option.isSome = true) :
    ((cells.map arrayBytes).toArray).mapM cellToCosetEvals = .ok (cellValues cells) ∧
      (cellValues cells).size = cells.length ∧
      (cellValues cells).toList.flatMap _root_.Array.toList =
        ((decodedCellElements cells).takeWhile Option.isSome).filterMap id ∧
      ∀ ys ∈ cellValues cells, ys.size = 64 := by
  have hmap := cells_decode_option cells
  simp only [h, if_true] at hmap
  refine ⟨?_, by simp [cellValues], ?_, ?_⟩
  · cases hm : ((cells.map arrayBytes).toArray).mapM cellToCosetEvals with
    | error e => simp [hm, ModelFront.toOption_error] at hmap
    | ok evals => simpa [hm, ModelFront.toOption_ok] using hmap
  · rw [takeWhile_all _ _ h]
    simpa [cellValues, decodedCellElements, ModelFront.fieldOptions, List.map_map,
      List.flatMap_map, Function.comp_def] using ModelFront.cells_values_flatten (cells.map arrayBytes)
  · intro ys hys
    simp only [cellValues, List.mem_toArray, List.mem_map] at hys
    obtain ⟨c, hc, rfl⟩ := hys
    apply ModelFront.cells_values_size
    simp only [decodedCellElements, List.all_flatMap, List.all_eq_true] at h
    simpa only [List.all_eq_true, ModelFront.fieldOptions] using h c hc


private theorem accepted_filterMap (xs : List (Option Fr))
    (h : xs.all Option.isSome = true) :
    xs.filterMap id = xs.map (fun x => x.getD 0) := by
  induction xs with
  | nil => rfl
  | cons x xs ih => cases x <;> simp_all

theorem cells_decode_rep (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (h : (decodedCellElements cells.val).all Option.isSome = true) :
    InterpolationKernel.CellsRep cells (cellValues cells.val) := by
  have hall : ∀ cell ∈ cells.val, (ModelFront.fieldOptions (arrayBytes cell)).all Option.isSome = true := by
    simpa only [decodedCellElements, List.all_flatMap, List.all_eq_true,
      ModelFront.fieldOptions] using h
  refine ⟨by simp [cellValues], ?_⟩
  intro k
  have hk := hall cells.val[k.val] (List.getElem_mem k.isLt)
  have hvalues : (cellValues cells.val)[k.val]! = ModelFront.fieldValues (arrayBytes cells.val[k.val]) := by
    simp [cellValues, getElem!_pos, k.isLt]
  rw [hvalues]
  refine ⟨ModelFront.cells_values_size _ hk, ?_⟩
  intro j
  have hj : (ModelFront.fieldOptions (arrayBytes cells.val[k.val]))[j.val]!.isSome = true := by
    apply List.all_eq_true.mp hk
    rw [getElem!_pos _ _ (by simp [ModelFront.fieldOptions_length])]
    exact List.getElem_mem (by simp [ModelFront.fieldOptions_length])
  have he : (ModelFront.fieldOptions (arrayBytes cells.val[k.val]))[j.val]! =
      (bytesToBlsField ((arrayBytes cells.val[k.val]).extract (32*j.val) (32*(j.val+1)))).toOption := by
    simp [ModelFront.fieldOptions, getElem!_pos, j.isLt]
  simp only [ModelFront.fieldValues, accepted_filterMap _ hk]
  simp only [List.getElem!_toArray]
  simp [ModelFront.fieldOptions, getElem!_pos, j.isLt]
  rw [he] at hj
  cases hv : (bytesToBlsField ((arrayBytes cells.val[k.val]).extract (32*j.val) (32*(j.val+1)))).toOption with
  | none => simp [hv] at hj
  | some value => simp


theorem verify_rejects_indices [RuntimeFeatures] (v : verify.CellBatchVerifier)
    (cs : Slice (Aeneas.Std.Array U8 48#usize)) (indices : Slice U64)
    (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (ps : Slice (Aeneas.Std.Array U8 48#usize))
    (hlen : indices.val.length = cs.val.length ∧ cells.val.length = cs.val.length ∧
      ps.val.length = cs.val.length)
    (hbad : ∃ x ∈ indices.val, 128 ≤ x.val) :
    verify.CellBatchVerifier.verify v cs indices cells ps = ok (false, v) := by
  have hi : Slice.len indices = Slice.len cs := UScalar.eq_of_val_eq hlen.1
  have hc : Slice.len cells = Slice.len cs := UScalar.eq_of_val_eq hlen.2.1
  have hp : Slice.len ps = Slice.len cs := UScalar.eq_of_val_eq hlen.2.2
  obtain ⟨k, hcall, hk⟩ := verify_indices_refinement indices
  have hstop : k < Slice.len cs := by
    rw [UScalar.lt_equiv, Slice.len_val, Slice.length, ← hlen.1, hk]
    apply List.findIdx_lt_length.mpr
    simpa using hbad
  rw [hi] at hcall
  simp only [verify.CellBatchVerifier.verify, hi, hc, hp, bne_self_eq_false,
    Bool.false_eq_true, if_false, hcall, bind_tc_ok, hstop, if_true]



theorem points_acceptance_validate (bs : List (Aeneas.Std.Array U8 48#usize)) :
    (bs.map specVerdict).all Option.isSome = ((bs.map arrayBytes).toArray).all validateKzgG1 := by
  rw [decoded_points_acceptance]
  simp only [specPoint_isSome]

def PairingContract [RuntimeFeatures] : Prop :=
  ∀ (v : verify.CellBatchVerifier), StateInvariant v → ∀ (indices : Slice U64)
    (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (commitments proofs : _root_.Array G1) (evals : _root_.Array CosetEvals) (r : Fr),
    indices.val.length * 2048 ≤ Isize.max.toNat →
    Model.RliInputs (indices.val.map (·.val)).toArray evals (computePowers r indices.val.length) →
    v.commitment_points.val = commitments.toList.map g1Affine →
    v.proof_points.val = proofs.toList.map g1Affine →
    InterpolationKernel.CellsRep cells evals →
    (v.kernel = none → v.evaluations.val = (evals.toList.flatMap _root_.Array.toList).map frEncode) →
    v.commitments.unique.val.length = commitments.size →
    (v.commitments.index_of_cell.val.length = indices.val.length ∧
      ∀ i ∈ v.commitments.index_of_cell.val, i.val < commitments.size) →
    proofs.size = indices.val.length →
    ((∀ p ∈ commitments, G1Valid p) ∧ (∀ p ∈ proofs, G1Valid p)) →
    ∃ next, verify.CellBatchVerifier.pairing_holds v (frEncode r) indices cells =
      ok (Bls.pairingCheck (Model.pairingInputs embeddedSetup commitments proofs
        (v.commitments.index_of_cell.val.map (·.val)).toArray
        (indices.val.map (·.val)).toArray evals r), next) ∧ StateInvariant next

def ModelPairingContract : Prop :=
  ∀ (unique : _root_.Array Bytes48) (ci indices : _root_.Array Nat)
    (evals : _root_.Array CosetEvals) (proofs : _root_.Array Bytes48),
    (ci.size = indices.size ∧ evals.size = indices.size ∧ proofs.size = indices.size) →
    (∀ i ∈ ci, i < unique.size) → unique.toList.Nodup →
    (∀ i ∈ indices, i < 128) → (∀ ys ∈ evals, ys.size = 64) →
    unique.all validateKzgG1 = true → proofs.all validateKzgG1 = true →
    let r := computeVerifyCellKzgProofBatchChallenge unique ci indices evals proofs
    Model.implPure embeddedSetup Model.columnStep unique ci indices evals proofs =
      .ok (Bls.pairingCheck (Model.pairingInputs embeddedSetup
        (pointValues unique) (pointValues proofs) ci indices evals r))

-- Keep the Boolean abstract here to avoid kernel evaluation of a total pairing.
private theorem rejectErrors_of_ok {result : Except KzgError Bool} {verdict : Bool}
    (h : result = .ok verdict) : Model.rejectErrors result = verdict := by
  rw [h]
  rfl

set_option maxHeartbeats 200000 in
theorem glue_of_contracts [cpu : RuntimeFeatures] (h : ComponentContracts)
    (hpairs : PairingContract) (hmodel : ModelPairingContract)
    (v : verify.CellBatchVerifier) (hv : StateInvariant v)
    (cs : Slice (Aeneas.Std.Array U8 48#usize)) (indices : Slice U64)
    (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (ps : Slice (Aeneas.Std.Array U8 48#usize))
    (hb : cells.val.length * 2048 ≤ Isize.max.toNat) :
    ∃ next, verify.CellBatchVerifier.verify v cs indices cells ps =
      ok (Model.verify embeddedSetup (cs.val.map arrayBytes).toArray
        (indices.val.map (·.val)).toArray (cells.val.map arrayBytes).toArray
        (ps.val.map arrayBytes).toArray, next) ∧ StateInvariant next := by
  let C := (cs.val.map arrayBytes).toArray
  let I := (indices.val.map (·.val)).toArray
  let B := (cells.val.map arrayBytes).toArray
  let P := (ps.val.map arrayBytes).toArray
  change ∃ next, verify.CellBatchVerifier.verify v cs indices cells ps =
    ok (Model.verify embeddedSetup C I B P, next) ∧ StateInvariant next
  by_cases hlen : indices.val.length = cs.val.length ∧ cells.val.length = cs.val.length ∧
      ps.val.length = cs.val.length
  · have hshape : B.size = C.size ∧ P.size = C.size ∧ I.size = C.size := by
      simpa [C, I, B, P] using ⟨hlen.2.1, hlen.2.2, hlen.1⟩
    have hcsize : ∀ b ∈ C, b.size = 48 := by
      intro b hb
      simp only [C, List.mem_toArray, List.mem_map] at hb
      obtain ⟨x, _, rfl⟩ := hb
      simpa using arrayBytes_size x
    have hbsize : ∀ b ∈ B, b.size = 2048 := by
      intro b hb
      simp only [B, List.mem_toArray, List.mem_map] at hb
      obtain ⟨x, _, rfl⟩ := hb
      simpa using arrayBytes_size x
    have hpsize : ∀ b ∈ P, b.size = 48 := by
      intro b hb
      simp only [P, List.mem_toArray, List.mem_map] at hb
      obtain ⟨x, _, rfl⟩ := hb
      simpa using arrayBytes_size x
    by_cases hindices : ∀ i ∈ indices.val, i.val < 128
    · have hI : ∀ i ∈ I, i < 128 := by
        intro i hi
        simp only [I, List.mem_toArray, List.mem_map] at hi
        obtain ⟨x, hx, rfl⟩ := hi
        exact hindices x hx
      have hfront := ModelFront.frontHalf_option C I B P hshape hcsize hbsize hpsize hI
      have hiLen : Slice.len indices = Slice.len cs := UScalar.eq_of_val_eq hlen.1
      have hbLen : Slice.len cells = Slice.len cs := UScalar.eq_of_val_eq hlen.2.1
      have hpLen : Slice.len ps = Slice.len cs := UScalar.eq_of_val_eq hlen.2.2
      obtain ⟨k, hcheck, hk⟩ := verify_indices_refinement indices
      have hstop : ¬ k < Slice.len cs := by
        have hfind := (List.findIdx_eq_length (p := fun x : U64 => decide (128 ≤ x.val))).mpr
          (fun x hx => by simpa using Nat.not_le.mpr (hindices x hx))
        simp only [UScalar.lt_equiv, Slice.len_val, Slice.length, hk, hfind, hlen.1, lt_self_iff_false, not_false_eq_true]
      rw [hiLen] at hcheck
      obtain ⟨d, hfill, hd⟩ := deduplicate_refinement v.commitments cs
      have hdu : (d.unique.val.map arrayBytes).toArray = (Model.deduplicate C).1 := congrArg Prod.fst hd
      have hdi : (d.index_of_cell.val.map (·.val)).toArray = (Model.deduplicate C).2 := congrArg Prod.snd hd
      obtain ⟨cd, cp, hcommit, hcp⟩ := decode_commitments_step h.g1 { v with commitments := d }
      let v1 := { v with commitments := d, decoded := cd, commitment_points := cp }
      have hv1 : StateInvariant v1 := hv
      have hcommit' : verify.CellBatchVerifier.decode_commitments { v with commitments := d } =
          ok ((d.unique.val.map specVerdict).all Option.isSome, v1) := hcommit
      have hcommitBool : (d.unique.val.map specVerdict).all Option.isSome = C.all validateKzgG1 := by
        rw [points_acceptance_validate, hdu, deduplicate_all]
      cases hc : (d.unique.val.map specVerdict).all Option.isSome with
      | false =>
        have hfalse : Model.verify embeddedSetup C I B P = false := by
          apply ModelFront.verify_of_front_none
          rw [hfront, ← hcommitBool, hc]
          rfl
        refine ⟨v1, ?_, hv1⟩
        simp only [verify.CellBatchVerifier.verify, hiLen, hbLen, hpLen, bne_self_eq_false,
          Bool.false_eq_true, if_false, hcheck, bind_tc_ok, hstop, hfill,
          hcommit', hc, Function.uncurry_apply_pair, hfalse]
      | true =>
        obtain ⟨v2, hcells, hevals, hs2, hcosets2, hkernel2⟩ := decode_cells_refinement h.bytes v1 cells hb
        have hframe := decode_cells_frame h.bytes v1 cells _ v2 hcells
        have hwork2 : v2.curve_work = v1.curve_work := by
          simpa only using congrArg verify.CellBatchVerifier.curve_work hframe
        have hv2 : StateInvariant v2 := by
          simpa only [StateInvariant, hs2, hcosets2, hkernel2, hwork2] using hv1
        have hcommitments2 : v2.commitments = d := by
          simpa only [v1] using congrArg verify.CellBatchVerifier.commitments hframe
        have hpoints2 : v2.commitment_points = cp := by
          simpa only [v1] using congrArg verify.CellBatchVerifier.commitment_points hframe
        have hcellsOption := cells_decode_option cells.val
        cases hcb : (decodedCellElements cells.val).all Option.isSome with
        | false =>
          have hfalse : Model.verify embeddedSetup C I B P = false := by
            apply ModelFront.verify_of_front_none
            rw [hfront, ← hcommitBool, hc]
            have hnone : (B.mapM cellToCosetEvals).toOption = none := by
              simpa only [hcb, if_false] using hcellsOption
            rw [hnone]
            rfl
          refine ⟨v2, ?_, hv2⟩
          simp only [verify.CellBatchVerifier.verify, hiLen, hbLen, hpLen, bne_self_eq_false,
            Bool.false_eq_true, if_false, hcheck, bind_tc_ok, hstop, hfill,
            hcommit', hc, if_true, Function.uncurry_apply_pair, hcells, hcb, hfalse]
        | true =>
          obtain ⟨hdecode, heSize, heFlat, heShapes⟩ := cells_decode_facts cells.val hcb
          obtain ⟨pd, pp, hproof, hpp⟩ := decode_proofs_step h.g1 v2 ps
          let v3 := { v2 with decoded := pd, proof_points := pp }
          have hv3 : StateInvariant v3 := hv2
          have hproof' : verify.CellBatchVerifier.decode_proofs v2 ps =
              ok ((ps.val.map specVerdict).all Option.isSome, v3) := hproof
          have hproofBool : (ps.val.map specVerdict).all Option.isSome = P.all validateKzgG1 :=
            points_acceptance_validate ps.val
          cases hp : (ps.val.map specVerdict).all Option.isSome with
          | false =>
            have hfalse : Model.verify embeddedSetup C I B P = false := by
              apply ModelFront.verify_of_front_none
              rw [hfront, ← hcommitBool, hc, ← hproofBool, hp]
              simp
            refine ⟨v3, ?_, hv3⟩
            simp only [verify.CellBatchVerifier.verify, hiLen, hbLen, hpLen, bne_self_eq_false,
              Bool.false_eq_true, if_false, hcheck, bind_tc_ok, hstop, hfill,
              hcommit', hc, if_true, Function.uncurry_apply_pair, hcells, hcb, hproof', hp, hfalse]
          | true =>
            let unique := (Model.deduplicate C).1
            let mapping := (Model.deduplicate C).2
            let evals := cellValues cells.val
            let r := computeVerifyCellKzgProofBatchChallenge unique mapping I evals P
            have hsize := deduplicate_sizes C
            have hmapSize : d.index_of_cell.val.length = indices.val.length := by
              have hh := congrArg _root_.Array.size hdi
              simp only [List.size_toArray, List.length_map] at hh
              simpa [C, hlen.1] using hh.trans hsize.2
            have huniqSize : d.unique.val.length = unique.size := by
              simpa only [List.size_toArray, List.length_map] using congrArg _root_.Array.size hdu
            have huniqLe : d.unique.val.length ≤ indices.val.length := by
              rw [huniqSize]
              simpa [unique, C, hlen.1] using hsize.1
            have hv3d : v3.commitments = d := by simp [v3, hcommitments2]
            have hpc : v3.commitment_points.val = (pointValues unique).toList.map g1Affine := by
              simp only [v3, hpoints2]
              rw [hcp, decoded_points_values _ hc, hdu]
            have hpp' : v3.proof_points.val = (pointValues P).toList.map g1Affine := by
              simpa only [v3, P] using hpp.trans (decoded_points_values _ hp)
            have hev : v3.kernel = none →
                v3.evaluations.val = (evals.toList.flatMap _root_.Array.toList).map frEncode := by
              simpa only [v3, evals, heFlat, hkernel2] using hevals
            have hcellRep : InterpolationKernel.CellsRep cells evals := cells_decode_rep cells hcb
            have hchallenge := verifier_challenge_refinement h.sha h.bytes v3 indices cells ps
              ⟨by simpa only [hv3d] using hmapSize, by omega, by omega⟩
            simp only [hv3d] at hchallenge
            have hchallengeSpec := challenge_preimage_spec unique mapping I B P evals
              ⟨by simpa [mapping, I, C, hlen.1] using hsize.2,
                by simp [B, I]; omega, by simp [P, I]; omega⟩ hdecode
            have hchallenge' : v3.challenge indices cells ps = ok (frEncode r) := by
              have hr : Fr.hashToBlsField (Model.challengePreimage
                  (d.unique.val.map arrayBytes).toArray (d.index_of_cell.val.map (·.val)).toArray
                  I B P) = r := by
                rw [hdu, hdi]
                exact hchallengeSpec
              exact hchallenge.trans (congrArg (fun x => ok (frEncode x)) hr)
            have hs : Model.RliInputs I evals (computePowers r indices.val.length) := by
              refine ⟨?_, ?_, hI, heShapes⟩
              · simp [I, evals, heSize]; omega
              · simp [I]
            have hvalid : (∀ p ∈ pointValues unique, G1Valid p) ∧ (∀ p ∈ pointValues P, G1Valid p) := by
              constructor
              · apply pointValues_valid
                · simpa only [specPoint_isSome, unique, deduplicate_all, ← hcommitBool] using hc
                · exact fun _ _ h => specPoint_valid h
              · apply pointValues_valid
                · simpa only [specPoint_isSome, ← hproofBool] using hp
                · exact fun _ _ h => specPoint_valid h
            have hci : ∀ i ∈ d.index_of_cell.val, i.val < (pointValues unique).size := by
              intro i hi
              rw [pointValues_size]
              apply deduplicate_indices C
              rw [← hdi]
              simp [hi]
            obtain ⟨next, hpair, hvnext⟩ := hpairs v3 hv3 indices cells
              (pointValues unique) (pointValues P) evals r (by omega) hs hpc hpp' hcellRep hev
              (by simpa [hv3d, pointValues_size] using huniqSize)
              ⟨by simpa [hv3d] using hmapSize, by simpa [hv3d] using hci⟩
              (by simp [pointValues_size, P]; omega) hvalid
            have hfrontOk := ModelFront.frontHalf_ok C I B P evals hshape hcsize hbsize hpsize hI
              (by simpa only [← hcommitBool] using hc) (by simpa only [← hproofBool] using hp) hdecode
            have hmodelOk := hmodel unique mapping I evals P
              ⟨by simpa [mapping, I, C, hlen.1] using hsize.2,
                by simp [evals, heSize, I]; omega, by simp [P, I]; omega⟩
              (deduplicate_indices C) (deduplicate_nodup C) hI heShapes
              (by simpa only [unique, deduplicate_all, ← hcommitBool] using hc)
              (by simpa only [← hproofBool] using hp)
            have hmodelVal : Model.verify embeddedSetup C I B P =
                Bls.pairingCheck (Model.pairingInputs embeddedSetup
                  (pointValues unique) (pointValues P) mapping I evals r) := by
              simp only [Model.verify, Model.verifyPure, hfrontOk, Bind.bind, Except.bind]
              exact rejectErrors_of_ok hmodelOk
            refine ⟨next, ?_, hvnext⟩
            simp only [verify.CellBatchVerifier.verify, hiLen, hbLen, hpLen, bne_self_eq_false,
              Bool.false_eq_true, if_false, hcheck, bind_tc_ok, hstop, hfill,
              hcommit', hc, if_true, Function.uncurry_apply_pair, hcells, hcb, hproof', hp, hv3d,
              hchallenge']
            simpa only [hv3d, hdi, hmodelVal] using hpair
    · have hbad : ∃ x ∈ indices.val, 128 ≤ x.val := by simpa only [not_forall, exists_prop, not_lt] using hindices
      have hiAny : I.any (· ≥ 128) = true := by
        rw [_root_.Array.any_eq_true']
        obtain ⟨x, hx, hxb⟩ := hbad
        exact ⟨x.val, by simp [I, hx], by simpa using hxb⟩
      have hm := ModelFront.verify_of_bad_index embeddedSetup C I B P hshape hcsize hiAny
      refine ⟨v, ?_, hv⟩
      rw [hm]
      exact verify_rejects_indices v cs indices cells ps hlen hbad
  · have hbad : indices.val.length ≠ cs.val.length ∨ cells.val.length ≠ cs.val.length ∨
        ps.val.length ≠ cs.val.length := by tauto
    have hm := model_rejects_lengths embeddedSetup C I B P (by simpa [C, I, B, P] using hbad)
    refine ⟨v, ?_, hv⟩
    rw [hm]
    exact verify_rejects_lengths v cs indices cells ps hbad

end LeanBlsSimd.Kzg.Verify
