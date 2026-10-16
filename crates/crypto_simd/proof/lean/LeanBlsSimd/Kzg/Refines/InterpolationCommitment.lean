import LeanBlsSimd.Kzg.Refines.Interpolation
import LeanBlsSimd.Kzg.SetupValidity
import LeanBlsSimd.Kzg.Refines.Cosets
import LeanBlsSimd.Kzg.Refines.Fft
import LeanBlsSimd.Kzg.InterpolationModel
import EthCryptographySpecs.Proofs.Kzg.Fft

open Aeneas Aeneas.Std Result ControlFlow
open EthCryptographySpecs Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg.Interpolation

set_option maxHeartbeats 4000000
set_option maxRecDepth 2000

private theorem setup_byte_facts (b : ByteArray) (hb : b ∈ rustG1Bytes.toList) :
    G1AffineValid (g1Affine ((specPoint b).getD G1.zero)) ∧
      g1ReadAffine (g1Affine ((specPoint b).getD G1.zero)) = (specPoint b).getD G1.zero := by
  simp only [rustG1Bytes, List.toList_toArray] at hb
  obtain ⟨raw, hraw, rfl⟩ := List.mem_map.mp hb
  obtain ⟨j, hj, rfl⟩ := List.mem_iff_getElem.mp hraw
  have hj64 : j < 64 := by simpa using hj
  have hp := g1_setup_specPoint ⟨j, hj64⟩
  rw [getElem!_pos trusted_setup.G1_MONOMIAL.val j hj] at hp
  simp only [hp, Option.getD_some]
  exact ⟨setup_g1_affine_valid ⟨j, hj64⟩, setup_g1_roundtrip ⟨j, hj64⟩⟩


private theorem setup_points_size (s : setup.Setup) (hs : SetupRep s) :
    s.g1_monomial.val.length = 64 := by
  rw [hs.1, List.length_map, _root_.Array.length_toList]
  simp only [rustG1Bytes, List.size_toArray, List.length_map]
  simp

private theorem setup_points_valid (s : setup.Setup) (hs : SetupRep s) :
    ∀ p ∈ s.g1_monomial.val, G1AffineValid p := by
  intro p hp
  rw [hs.1] at hp
  obtain ⟨b, hb, rfl⟩ := List.mem_map.mp hp
  exact (setup_byte_facts b hb).1

private theorem array_map_read {α β γ : Type} (bs : _root_.Array α)
    (encode : α → β) (read : β → γ) (spec : α → γ)
    (hread : ∀ b ∈ bs.toList, read (encode b) = spec b) :
    ((bs.toList.map encode).map read).toArray = bs.map spec := by
  have hl : (bs.toList.map encode).map read = bs.toList.map spec := by
    rw [List.map_map]
    apply List.map_congr_left
    intro b hb
    exact hread b hb
  rw [hl]
  rw [← List.map_toArray, _root_.Array.toArray_toList]

private theorem affine_points_read (bs : _root_.Array ByteArray)
    (hread : ∀ b ∈ bs.toList,
      g1ReadAffine (g1Affine ((specPoint b).getD G1.zero)) = (specPoint b).getD G1.zero) :
    ((bs.toList.map (fun b => g1Affine ((specPoint b).getD G1.zero))).map g1ReadAffine).toArray =
      bs.map (fun b => (specPoint b).getD G1.zero) :=
  array_map_read bs (fun b => g1Affine ((specPoint b).getD G1.zero)) g1ReadAffine
    (fun b => (specPoint b).getD G1.zero) hread


private theorem setup_points_read (s : setup.Setup) (hs : SetupRep s) :
    (s.g1_monomial.val.map g1ReadAffine).toArray =
      rustG1Bytes.map (fun b => (specPoint b).getD G1.zero) := by
  rw [hs.1]
  exact affine_points_read rustG1Bytes (fun b hb => (setup_byte_facts b hb).2)


private theorem encoded_scalars_read (coeffs : List Fr) (v : alloc.vec.Vec blst.blst_fr)
    (hv : v.val = coeffs.map frEncode) : (v.val.map frRead).toArray = coeffs.toArray := by
  simp only [hv, List.map_map, Function.comp_def, frRead_frEncode, List.map_id']

theorem setup_lincomb [e : KzgExternals] (h : ExternalsCorrect e)
    (s : setup.Setup) (hs : SetupRep s) (coeffs : List Fr) (hcoeffs : coeffs.length = 64)
    (v : alloc.vec.Vec blst.blst_fr) (hv : v.val = coeffs.map frEncode)
    (scratch : blst_ops.LincombScratch) :
    ∃ point scratch',
      blst_ops.g1_lincomb (alloc.vec.Vec.deref s.g1_monomial) (alloc.vec.Vec.deref v) scratch =
        ok (point, scratch') ∧
      G1Rep point (G1.msm (rustG1Bytes.map (fun b => (specPoint b).getD G1.zero)) coeffs.toArray) := by
  have hsize : (alloc.vec.Vec.deref s.g1_monomial).val.length =
      (alloc.vec.Vec.deref v).val.length := by
    simp only [alloc.vec.Vec.deref, setup_points_size s hs, hv, List.length_map, hcoeffs]
  have hscalars : ∀ x ∈ (alloc.vec.Vec.deref v).val, FrReduced x := by
    intro x hx
    simp only [alloc.vec.Vec.deref, hv] at hx
    obtain ⟨f, _, rfl⟩ := List.mem_map.mp hx
    exact frEncode_reduced f
  obtain ⟨point, scratch', hcall, hrep⟩ := h.blst.lincomb
    (alloc.vec.Vec.deref s.g1_monomial) (alloc.vec.Vec.deref v) scratch hsize
    (setup_points_valid s hs) hscalars
  refine ⟨point, scratch', hcall, ?_⟩
  simpa only [alloc.vec.Vec.deref, setup_points_read s hs, encoded_scalars_read coeffs v hv] using hrep


private theorem inverseFft_eq (values : _root_.Array Fr) (hvalues : values.size = 64) :
    Model.inverseFft values (Model.inverseRoots (Model.roots 6)) (Fr.ofNat 64).inverse =
      fftField values (computeRootsOfUnity 64) true := by
  simp only [fftField_def, if_true, hvalues, Model.inverseFft, Model.inverseRoots, Model.roots]

private theorem transform_step_length (columns total : List Fr) (used : List Bool) (c : Nat)
    (hlen : total.length = 64) : (totalStep columns used total c).length = 64 := by
  unfold totalStep
  split
  · rw [shiftAdd_length _ _ _ _ (by simp [hlen])]
    exact hlen
  · exact hlen

private theorem transform_columns_loop [e : KzgExternals] (h : ExternalsCorrect e)
    (cs : cosets.Cosets) (hcs : CosetsRep cs)
    (columns total : List Fr) (used : List Bool)
    (v : alloc.vec.Vec blst.blst_fr) (flags : alloc.vec.Vec Bool)
    (vcol vcoeff acc : alloc.vec.Vec blst.blst_fr)
    (hv : v.val = columns.map frEncode) (hf : flags.val = used)
    (ha : acc.val = total.map frEncode)
    (hcolumns : columns.length = 8192) (hused : used.length = 128)
    (htotal : total.length = 64) (hcol : vcol.val.length = 64) (hcoeff : vcoeff.val.length = 64)
    (iter : core.ops.range.Range Usize) (hi : iter.start.val ≤ 128) (hend : iter.end.val = 128) :
    ∃ col coeff result,
      verify.CellBatchVerifier.interpolation_commitment_loop1
        iter cs v flags vcol vcoeff acc = ok (cs, col, coeff, result) ∧
      col.val.length = 64 ∧ coeff.val.length = 64 ∧
      result.val = (((List.range 128).drop iter.start.val).foldl (totalStep columns used) total).map
        frEncode := by
  induction hn : 128 - iter.start.val generalizing total vcol vcoeff acc iter with
  | zero =>
    have hstart : iter.start.val = 128 := by omega
    have hnext := Refinement.next_ge iter (by omega)
    refine ⟨vcol, vcoeff, acc, ?_, hcol, hcoeff, by simpa [hstart] using ha⟩
    rw [verify.CellBatchVerifier.interpolation_commitment_loop1, loop.eq_1]
    simp only [verify.CellBatchVerifier.interpolation_commitment_loop1.body,
      hnext, bind_tc_ok, Function.uncurry_apply_pair]
  | succ n ih =>
    have hlt : iter.start.val < 128 := by omega
    obtain ⟨iter', hi', hend', hnext⟩ := Refinement.next_lt iter (by omega)
    have hflag : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice Bool) flags iter.start =
        ok used[iter.start.val]! := by
      simp [alloc.vec.Vec.index_usize, hf, getElem!_pos, hused, hlt]
    cases hb : used[iter.start.val]! with
    | false =>
      have hbody : verify.CellBatchVerifier.interpolation_commitment_loop1.body
          cs v flags iter vcol vcoeff acc = ok (cont (iter', vcol, vcoeff, acc)) := by
        simp only [verify.CellBatchVerifier.interpolation_commitment_loop1.body,
          hnext, bind_tc_ok, Function.uncurry_apply_pair, hflag, hb, Bool.false_eq_true, if_false]
      obtain ⟨col, coeff, result, hloop, hcol', hcoeff', hr⟩ := ih
        total vcol vcoeff acc ha htotal hcol hcoeff iter'
        (by omega) (by simpa only [hend'] using hend) (by omega)
      refine ⟨col, coeff, result, ?_, hcol', hcoeff', ?_⟩
      · rw [verify.CellBatchVerifier.interpolation_commitment_loop1, loop.eq_1]
        simp only [hbody]
        exact hloop
      · rw [List.drop_eq_getElem_cons (by simp [hlt])]
        simpa only [List.foldl_cons, List.getElem_range, hi', totalStep, hb,
          Bool.false_eq_true, if_false] using hr
    | true =>
      obtain ⟨copied, hcopy, hcopied⟩ := copy_column columns vcol.val v vcol hv rfl
        hcolumns hcol iter.start hlt
      let values := (reversedColumn columns iter.start.val).toArray
      have hvalues : values.size = 64 := by simp [values]
      obtain ⟨decoded, hdecode, hdecoded⟩ := inverse_fft_refinement h
        (alloc.vec.Vec.deref vcoeff) (alloc.vec.Vec.deref copied)
        (alloc.vec.Vec.deref cs.inverse_roots) values hcoeff hvalues
        (by simpa [values, alloc.vec.Vec.deref] using hcopied) hcs.1
      have hdecode' : fft.inverse_fft (alloc.vec.Vec.deref vcoeff) (alloc.vec.Vec.deref copied)
          (alloc.vec.Vec.deref cs.inverse_roots) cs.inverse_size = ok decoded := by
        simpa only [hcs.2.1] using hdecode
      let coeffValues := (fftField values (computeRootsOfUnity 64) true).toList
      have hcoeffValues : coeffValues.length = 64 := by simp [coeffValues, hvalues]
      have hdecoded' : decoded.val = coeffValues.map frEncode := by
        rw [inverseFft_eq values hvalues] at hdecoded
        exact hdecoded
      let decodedVec : alloc.vec.Vec blst.blst_fr := ⟨decoded.val, decoded.property⟩
      let shifts := (List.range 128).map (fun j => (Model.cosetShift j).inverse)
      have hshifts : cs.shift_inverse.val = shifts.map frEncode := by
        simpa only [shifts, List.map_map, Function.comp_def] using hcs.2.2.1
      have hshift : shifts[iter.start.val]! = (Model.cosetShift iter.start.val).inverse := by
        simp [shifts, getElem!_pos, hlt]
      obtain ⟨nextAcc, hshiftLoop, hnextAcc⟩ := shift_add_loop h shifts [] coeffValues [] total
        cs.shift_inverse decodedVec acc hshifts (by simpa [decodedVec] using hdecoded')
        (by simpa using ha) (by omega) rfl iter.start (by simp [shifts, hlt]) (Fr.ofNat 1)
        { start := 0#usize, «end» := FIELD_ELEMENTS_PER_CELL }
        (by simp) (by simp [FIELD_ELEMENTS_PER_CELL, hcoeffValues])
      have hnextVal : nextAcc.val = (totalStep columns used total iter.start.val).map frEncode := by
        simpa only [List.nil_append, hshift, totalStep, hb, if_true,
          coeffValues, values] using hnextAcc
      have hcopiedLen : copied.val.length = 64 := by simp [hcopied]
      have hdecodedLen : decodedVec.val.length = 64 := by simp [decodedVec, hdecoded', hcoeffValues]
      have hone : blst_ops.fr_from_u64 1#u64 = ok (frEncode (Fr.ofNat 1)) := by
        simpa only [UScalar.ofNatCore_val_eq] using h.blst.fr_u64 1#u64
      simp only [alloc.vec.Vec.deref] at hdecode'
      dsimp only [decodedVec] at hshiftLoop
      have hbody : verify.CellBatchVerifier.interpolation_commitment_loop1.body
          cs v flags iter vcol vcoeff acc = ok (cont (iter', copied, decodedVec, nextAcc)) := by
        simp only [verify.CellBatchVerifier.interpolation_commitment_loop1.body,
          hnext, bind_tc_ok, Function.uncurry_apply_pair, hflag, hb, if_true,
          hcopy, lift, alloc.vec.Vec.deref_mut, alloc.vec.Vec.deref,
          hdecode', hone, hshiftLoop, decodedVec]
      obtain ⟨col, coeff, result, hloop, hcol', hcoeff', hr⟩ := ih
        (totalStep columns used total iter.start.val) copied decodedVec nextAcc hnextVal
        (transform_step_length columns total used iter.start.val htotal) hcopiedLen hdecodedLen
        iter' (by omega) (by simpa only [hend'] using hend) (by omega)
      refine ⟨col, coeff, result, ?_, hcol', hcoeff', ?_⟩
      · rw [verify.CellBatchVerifier.interpolation_commitment_loop1, loop.eq_1]
        simp only [hbody]
        exact hloop
      · rw [List.drop_eq_getElem_cons (by simp [hlt])]
        simpa only [List.foldl_cons, List.getElem_range, hi'] using hr


private theorem resize_fields (v : alloc.vec.Vec blst.blst_fr) (n : Usize) (x : blst.blst_fr) :
    ∃ out, alloc.vec.Vec.resize blst.blst_fr.Insts.CoreCloneClone v n x = ok out ∧
      out.val = v.val.resize n.val x := by
  apply WP.spec_imp_exists
  apply alloc.vec.Vec.resize_spec
  simp [blst.blst_fr.Insts.CoreCloneClone.clone]

private theorem resize_flags (v : alloc.vec.Vec Bool) (n : Usize) :
    ∃ out, alloc.vec.Vec.resize core.clone.CloneBool v n false = ok out ∧
      out.val = v.val.resize n.val false := by
  apply WP.spec_imp_exists
  apply alloc.vec.Vec.resize_spec
  rfl

private theorem totals_length (columns : List Fr) (used : List Bool) (total : List Fr)
    (ks : List Nat) (hlen : total.length = 64) :
    (ks.foldl (totalStep columns used) total).length = 64 := by
  induction ks generalizing total with
  | nil => exact hlen
  | cons k ks ih => exact ih _ (transform_step_length columns total used k hlen)

private theorem aggregate_lengths (evaluations powers : List Fr) (indices : List Nat)
    (columns : List Fr) (used : List Bool) :
    (aggregateColumns evaluations powers indices columns used).1.length = columns.length ∧
    (aggregateColumns evaluations powers indices columns used).2.length = used.length := by
  unfold aggregateColumns
  generalize List.range indices.length = ks
  induction ks generalizing columns used with
  | nil => exact ⟨rfl, rfl⟩
  | cons k ks ih =>
    simpa only [List.foldl_cons, aggregateStep, aggregateCell_length, List.length_set] using
      (ih (aggregateCell evaluations powers k indices[k]! columns) (used.set indices[k]! true))

private theorem flat_length (rows : List (_root_.Array Fr))
    (hs : ∀ row ∈ rows, row.size = 64) :
    (rows.flatMap _root_.Array.toList).length = rows.length * 64 := by
  induction rows with
  | nil => simp
  | cons row rows ih =>
    have hrow := hs row (by simp)
    have hrows : ∀ row ∈ rows, row.size = 64 := fun row hr => hs row (by simp [hr])
    simp [List.flatMap_cons, hrow, ih hrows, Nat.add_mul, Nat.add_comm]


private theorem resize_zero {α : Type} (xs : List α) (x : α) : xs.resize 0 x = [] := by
  simp [List.resize]

private theorem resize_nil {α : Type} (n : Nat) (x : α) :
    ([] : List α).resize n x = List.replicate n x := by
  simp [List.resize]

private theorem interpolation_commitment_execution [e : KzgExternals] (h : ExternalsCorrect e)
    (v : verify.CellBatchVerifier) (hv : StateInvariant v) (indices : Slice U64)
    (evals : _root_.Array CosetEvals) (powers : _root_.Array Fr)
    (hs : Model.RliInputs (indices.val.map (·.val)).toArray evals powers)
    (he : v.evaluations.val = (evals.toList.flatMap _root_.Array.toList).map frEncode)
    (hp : v.r_powers.val = powers.toList.map frEncode) :
    let ag := aggregateColumns (evals.toList.flatMap _root_.Array.toList) powers.toList
      (indices.val.map (·.val)) (List.replicate 8192 Fr.zero) (List.replicate 128 false)
    let coefficients := (List.range 128).foldl (totalStep ag.1 ag.2) (List.replicate 64 Fr.zero)
    ∃ point next, verify.CellBatchVerifier.interpolation_commitment v indices = ok (point, next) ∧
      StateInvariant next ∧
      G1Rep point (G1.msm (rustG1Bytes.map (fun b => (specPoint b).getD G1.zero)) coefficients.toArray) := by
  dsimp only
  let evaluations := evals.toList.flatMap _root_.Array.toList
  let zero := frEncode Fr.zero
  have hzero : blst_ops.fr_from_u64 0#u64 = ok zero := by
    simpa only [zero, UScalar.ofNatCore_val_eq] using h.blst.fr_u64 0#u64
  obtain ⟨columns0, hcolumns0, hvcolumns0⟩ := resize_fields v.columns 0#usize zero
  have hvcolumns0' : columns0.val = [] := by simpa only [UScalar.ofNatCore_val_eq, resize_zero] using hvcolumns0
  obtain ⟨columns, hcolumns, hvcolumns⟩ := resize_fields columns0 8192#usize zero
  have hvcolumns' : columns.val = (List.replicate 8192 Fr.zero).map frEncode := by
    simpa only [UScalar.ofNatCore_val_eq, hvcolumns0', resize_nil, List.map_replicate, zero] using hvcolumns
  obtain ⟨flags0, hflags0, hvflags0⟩ := resize_flags v.column_used 0#usize
  have hvflags0' : flags0.val = [] := by simpa only [UScalar.ofNatCore_val_eq, resize_zero] using hvflags0
  obtain ⟨flags, hflags, hvflags⟩ := resize_flags flags0 128#usize
  have hvflags' : flags.val = List.replicate 128 false := by
    simpa only [UScalar.ofNatCore_val_eq, hvflags0', resize_nil] using hvflags
  have hrows : ∀ row ∈ evals.toList, row.size = 64 := by
    simpa only [_root_.Array.mem_toList_iff] using hs.2.2.2
  have hcount : evals.size = indices.val.length := by
    simpa only [List.size_toArray, List.length_map] using hs.1.symm
  have hpowerCount : powers.toList.length = indices.val.length := by
    simpa only [List.size_toArray, List.length_map, _root_.Array.length_toList] using hs.2.1.symm
  have hevals : evaluations.length = indices.val.length*64 := by
    simpa only [evaluations, _root_.Array.length_toList, hcount] using flat_length evals.toList hrows
  have hindices : ∀ i ∈ indices.val, i.val < 128 := by
    intro i hi
    apply hs.2.2.1 i.val
    simpa only [List.mem_toArray] using List.mem_map_of_mem (f := fun x : U64 => x.val) hi
  obtain ⟨aggregated, haggregate, haggColumns, haggFlags⟩ := aggregate_columns h
    evaluations powers.toList (List.replicate 8192 Fr.zero) (List.replicate 128 false)
    v.evaluations v.r_powers columns flags indices he hp hvcolumns' hvflags'
    (by omega) (by omega) (List.length_replicate ..) (List.length_replicate ..) hindices
  rcases aggregated with ⟨aggColumns, aggFlags⟩
  let ag := aggregateColumns evaluations powers.toList (indices.val.map (·.val))
    (List.replicate 8192 Fr.zero) (List.replicate 128 false)
  have haggColumns' : aggColumns.val = ag.1.map frEncode := haggColumns
  have haggFlags' : aggFlags.val = ag.2 := haggFlags
  have hagLen : ag.1.length = 8192 ∧ ag.2.length = 128 := by
    simpa only [ag, List.length_replicate] using aggregate_lengths evaluations powers.toList
      (indices.val.map (·.val)) (List.replicate 8192 Fr.zero) (List.replicate 128 false)
  obtain ⟨total0, htotal0, hvtotal0⟩ := resize_fields v.interpolation 0#usize zero
  have hvtotal0' : total0.val = [] := by simpa only [UScalar.ofNatCore_val_eq, resize_zero] using hvtotal0
  obtain ⟨total, htotal, hvtotal⟩ := resize_fields total0 FIELD_ELEMENTS_PER_CELL zero
  have hvtotal' : total.val = (List.replicate 64 Fr.zero).map frEncode := by
    simpa only [FIELD_ELEMENTS_PER_CELL, UScalar.ofNatCore_val_eq, hvtotal0', resize_nil,
      List.map_replicate, zero] using hvtotal
  obtain ⟨col, hcol, hvcol⟩ := resize_fields v.column FIELD_ELEMENTS_PER_CELL zero
  have hcolLen : col.val.length = 64 := by simp [hvcol, FIELD_ELEMENTS_PER_CELL]
  obtain ⟨coeff, hcoeff, hvcoeff⟩ := resize_fields v.coefficients FIELD_ELEMENTS_PER_CELL zero
  have hcoeffLen : coeff.val.length = 64 := by simp [hvcoeff, FIELD_ELEMENTS_PER_CELL]
  obtain ⟨finalCol, finalCoeff, result, htransform, _, _, hresult⟩ := transform_columns_loop h
    v.cosets hv.2 ag.1 (List.replicate 64 Fr.zero) ag.2 aggColumns aggFlags col coeff total
    haggColumns' haggFlags' hvtotal' hagLen.1 hagLen.2 (by simp) hcolLen hcoeffLen
    { start := 0#usize, «end» := 128#usize } (by simp) (by simp)
  let coefficients := (List.range 128).foldl (totalStep ag.1 ag.2) (List.replicate 64 Fr.zero)
  have hresult' : result.val = coefficients.map frEncode := by
    simpa only [UScalar.ofNatCore_val_eq, List.drop_zero, coefficients] using hresult
  have hresultLen : coefficients.length = 64 := totals_length _ _ _ _ (by simp)
  obtain ⟨point, scratch, hlincomb, hpoint⟩ := setup_lincomb h v.setup hv.1 coefficients hresultLen
    result hresult' v.lincomb
  let next := { v with
    cosets := v.cosets, columns := aggColumns, column_used := aggFlags,
    column := finalCol, coefficients := finalCoeff, interpolation := result, lincomb := scratch }
  have hmul : 128#usize * FIELD_ELEMENTS_PER_CELL = ok 8192#usize := by
    simp only [FIELD_ELEMENTS_PER_CELL]
    show UScalar.tryMk .Usize 8192 = _
    have hb : 8192 < 2^System.Platform.numBits := by
      rcases System.Platform.numBits_eq with hh | hh <;> simp [hh]
    simp [UScalar.tryMk, UScalar.tryMkOpt, Result.ofOption, hb]
  refine ⟨point, next, ?_, hv, hpoint⟩
  simp only [verify.CellBatchVerifier.interpolation_commitment, hzero, bind_tc_ok,
    Function.uncurry_apply_pair, hcolumns0, cells_per_ext_blob_eq, hmul, hcolumns,
    hflags0, hflags, haggregate, htotal0, htotal, hcol, hcoeff, htransform, hlincomb, next]

end LeanBlsSimd.Kzg.Interpolation

namespace LeanBlsSimd.Kzg

theorem interpolation_commitment_refinement [e : KzgExternals] (h : ExternalsCorrect e)
    (v : verify.CellBatchVerifier) (hv : StateInvariant v) (indices : Slice U64)
    (evals : _root_.Array CosetEvals) (powers : _root_.Array Fr)
    (hs : Model.RliInputs (indices.val.map (·.val)).toArray evals powers)
    (_hb : indices.val.length * 2048 ≤ Isize.max.toNat)
    (he : v.evaluations.val = (evals.toList.flatMap _root_.Array.toList).map frEncode)
    (hp : v.r_powers.val = powers.toList.map frEncode) :
    ∃ point next, verify.CellBatchVerifier.interpolation_commitment v indices = ok (point, next) ∧
      StateInvariant next ∧
      G1Rep point (G1.msm
        (rustG1Bytes.map (fun b => (specPoint b).getD G1.zero))
        (Model.columnRli (indices.val.map (·.val)).toArray evals powers)) := by
  obtain ⟨point, next, hcall, hnext, hrep⟩ :=
    Interpolation.interpolation_commitment_execution h v hv indices evals powers hs he hp
  refine ⟨point, next, hcall, hnext, ?_⟩
  have hmodel := Interpolation.aggregate_columnRli (indices.val.map (·.val)).toArray evals powers hs
  simpa only [hmodel] using hrep

end LeanBlsSimd.Kzg
