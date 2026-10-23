import LeanBlsSimd.Kzg.Refines.Loop
import LeanBlsSimd.Kzg.Refines.Bits
import LeanBlsSimd.Kzg.Externals
import LeanBlsSimd.Kzg.Model

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg.Interpolation

set_option maxHeartbeats 4000000

def columnStep (evaluations powers : List Fr) (k c : Nat) (columns : List Fr)
    (j : Nat) : List Fr :=
  columns.set (c*64+j) (columns[c*64+j]! + powers[k]! * evaluations[k*64+j]!)

def aggregateCell (evaluations powers : List Fr) (k c : Nat) (columns : List Fr) : List Fr :=
  (List.range 64).foldl (columnStep evaluations powers k c) columns

@[simp] theorem columnStep_length (evaluations powers : List Fr) (k c : Nat)
    (columns : List Fr) (j : Nat) :
    (columnStep evaluations powers k c columns j).length = columns.length := by
  simp [columnStep]

theorem aggregateCell_length (evaluations powers : List Fr) (k c : Nat)
    (columns : List Fr) : (aggregateCell evaluations powers k c columns).length = columns.length := by
  unfold aggregateCell
  generalize List.range 64 = js
  induction js generalizing columns with
  | nil => rfl
  | cons j js ih =>
      simpa only [List.foldl_cons, columnStep_length] using
        (ih (columnStep evaluations powers k c columns j))

private theorem index_encoded (v : alloc.vec.Vec blst.blst_fr) (xs : List Fr)
    (hv : v.val = xs.map frEncode) (i : Usize) (hi : i.val < xs.length) :
    alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice blst.blst_fr) v i =
      ok (frEncode xs[i.val]!) := by
  simp [alloc.vec.Vec.index_usize, hv, getElem!_pos, hi]

private theorem index_mut_encoded (v : alloc.vec.Vec blst.blst_fr) (xs : List Fr)
    (hv : v.val = xs.map frEncode) (i : Usize) (hi : i.val < xs.length) :
    alloc.vec.Vec.index_mut (core.slice.index.SliceIndexUsizeSlice blst.blst_fr) v i =
      ok (frEncode xs[i.val]!, alloc.vec.Vec.set v i) := by
  simp [alloc.vec.Vec.index_mut_usize, alloc.vec.Vec.index_usize, hv, getElem!_pos, hi]

private theorem set_encoded (v : alloc.vec.Vec blst.blst_fr) (xs : List Fr)
    (hv : v.val = xs.map frEncode) (i : Usize) (x : Fr) :
    (alloc.vec.Vec.set v i (frEncode x)).val = (xs.set i.val x).map frEncode := by
  simp [alloc.vec.Vec.set, hv]

theorem aggregate_column_loop [e : KzgExternals] (h : ExternalsCorrect e)
    (evaluations powers columns : List Fr)
    (v vp acc : alloc.vec.Vec blst.blst_fr)
    (he : v.val = evaluations.map frEncode) (hp : vp.val = powers.map frEncode)
    (ha : acc.val = columns.map frEncode) (k c : Usize)
    (hk : k.val < powers.length) (hke : k.val*64+64 ≤ evaluations.length)
    (hc : c.val*64+64 ≤ columns.length)
    (iter : core.ops.range.Range Usize) (hi : iter.start.val ≤ 64)
    (hend : iter.end.val = 64) :
    ∃ result,
      verify.CellBatchVerifier.interpolation_commitment_loop0_loop0 iter v vp acc k c = ok result ∧
      result.val = (((List.range 64).drop iter.start.val).foldl
        (columnStep evaluations powers k.val c.val) columns).map frEncode := by
  induction hn : 64 - iter.start.val generalizing iter acc columns with
  | zero =>
    have hs : iter.start.val = 64 := by omega
    have hnext := Refinement.next_ge iter (by omega)
    refine ⟨acc, ?_, by simpa [hs] using ha⟩
    rw [verify.CellBatchVerifier.interpolation_commitment_loop0_loop0, loop.eq_1]
    simp only [verify.CellBatchVerifier.interpolation_commitment_loop0_loop0.body,
      hnext, bind_tc_ok, Function.uncurry_apply_pair]
  | succ n ih =>
    have hj : iter.start.val < 64 := by omega
    obtain ⟨iter', hi', hend', hnext⟩ := Refinement.next_lt iter (by omega)
    have hev : evaluations.length ≤ Usize.max := by simpa [he] using v.property
    have hac : columns.length ≤ Usize.max := by simpa [ha] using acc.property
    obtain ⟨eb, heb, hebv⟩ := WP.spec_imp_exists
      (@Usize.mul_spec k FIELD_ELEMENTS_PER_CELL (by simp [FIELD_ELEMENTS_PER_CELL]; omega))
    have hebv' : eb.val = k.val*64 := by simpa [FIELD_ELEMENTS_PER_CELL] using hebv
    obtain ⟨ei, hei, heiv⟩ := WP.spec_imp_exists
      (@Usize.add_spec eb iter.start (by omega))
    have heiv' : ei.val = k.val*64 + iter.start.val := by omega
    obtain ⟨cb, hcb, hcbv⟩ := WP.spec_imp_exists
      (@Usize.mul_spec c FIELD_ELEMENTS_PER_CELL (by simp [FIELD_ELEMENTS_PER_CELL]; omega))
    have hcbv' : cb.val = c.val*64 := by simpa [FIELD_ELEMENTS_PER_CELL] using hcbv
    obtain ⟨target, hat, hatv⟩ := WP.spec_imp_exists
      (@Usize.add_spec cb iter.start (by omega))
    have hatv' : target.val = c.val*64 + iter.start.val := by omega
    have hpow := index_encoded vp powers hp k hk
    have heval := index_encoded v evaluations he ei (by omega)
    have hacc := index_encoded acc columns ha target (by omega)
    have hmut := index_mut_encoded acc columns ha target (by omega)
    let x := columns[target.val]! + powers[k.val]! * evaluations[ei.val]!
    let acc' := alloc.vec.Vec.set acc target (frEncode x)
    have ha' : acc'.val =
        (columnStep evaluations powers k.val c.val columns iter.start.val).map frEncode := by
      simpa only [acc', x, columnStep, heiv', hatv'] using set_encoded acc columns ha target x
    have hbody : verify.CellBatchVerifier.interpolation_commitment_loop0_loop0.body
        v vp k c iter acc = ok (cont (iter', acc')) := by
      simp only [verify.CellBatchVerifier.interpolation_commitment_loop0_loop0.body,
        hnext, bind_tc_ok, Function.uncurry_apply_pair, hpow, heb, hei, heval,
        blst_ops.fr_mul, h.blst.fr_mul, hcb, hat, hacc, blst_ops.fr_add,
        h.blst.fr_add, hmut, acc', x]
    obtain ⟨result, hloop, hr⟩ := ih
      (columnStep evaluations powers k.val c.val columns iter.start.val) acc' ha'
      (by simpa using hc) iter' (by omega) (by simpa only [hend'] using hend) (by omega)
    refine ⟨result, ?_, ?_⟩
    · rw [verify.CellBatchVerifier.interpolation_commitment_loop0_loop0, loop.eq_1]
      simp only [hbody]
      exact hloop
    · rw [List.drop_eq_getElem_cons (by simp [hj])]
      simpa only [List.foldl_cons, List.getElem_range, hi'] using hr

theorem aggregate_column [e : KzgExternals] (h : ExternalsCorrect e)
    (evaluations powers columns : List Fr)
    (v vp acc : alloc.vec.Vec blst.blst_fr)
    (he : v.val = evaluations.map frEncode) (hp : vp.val = powers.map frEncode)
    (ha : acc.val = columns.map frEncode) (k c : Usize)
    (hk : k.val < powers.length) (hke : k.val*64+64 ≤ evaluations.length)
    (hc : c.val*64+64 ≤ columns.length) :
    ∃ result,
      verify.CellBatchVerifier.interpolation_commitment_loop0_loop0
        { start := 0#usize, «end» := FIELD_ELEMENTS_PER_CELL } v vp acc k c = ok result ∧
      result.val = (aggregateCell evaluations powers k.val c.val columns).map frEncode := by
  simpa only [UScalar.ofNatCore_val_eq, List.drop_zero, aggregateCell] using
    aggregate_column_loop h evaluations powers columns v vp acc he hp ha k c hk hke hc
      { start := 0#usize, «end» := FIELD_ELEMENTS_PER_CELL } (by simp)
      (by simp [FIELD_ELEMENTS_PER_CELL])

def aggregateStep (evaluations powers : List Fr) (indices : List Nat)
    (state : List Fr × List Bool) (k : Nat) : List Fr × List Bool :=
  (aggregateCell evaluations powers k indices[k]! state.1, state.2.set indices[k]! true)

def aggregateColumns (evaluations powers : List Fr) (indices : List Nat)
    (columns : List Fr) (used : List Bool) : List Fr × List Bool :=
  (List.range indices.length).foldl (aggregateStep evaluations powers indices) (columns, used)

theorem aggregate_columns_loop [e : KzgExternals] (h : ExternalsCorrect e)
    (evaluations powers columns : List Fr) (used : List Bool)
    (v vp acc : alloc.vec.Vec blst.blst_fr) (flags : alloc.vec.Vec Bool)
    (indices : Slice U64)
    (he : v.val = evaluations.map frEncode) (hp : vp.val = powers.map frEncode)
    (ha : acc.val = columns.map frEncode) (hf : flags.val = used)
    (hep : indices.val.length*64 ≤ evaluations.length) (hpp : indices.val.length ≤ powers.length)
    (hc : columns.length = 8192) (hu : used.length = 128)
    (hindices : ∀ i ∈ indices.val, i.val < 128)
    (iter : core.ops.range.Range Usize) (hi : iter.start.val ≤ indices.val.length)
    (hend : iter.end.val = indices.val.length) :
    ∃ result,
      verify.CellBatchVerifier.interpolation_commitment_loop0 iter v vp acc flags indices = ok result ∧
      let expected := ((List.range indices.val.length).drop iter.start.val).foldl
        (aggregateStep evaluations powers (indices.val.map (·.val))) (columns, used)
      result.1.val = expected.1.map frEncode ∧ result.2.val = expected.2 := by
  induction hn : indices.val.length - iter.start.val generalizing iter acc flags columns used with
  | zero =>
    have hs : iter.start.val = indices.val.length := by omega
    have hnext := Refinement.next_ge iter (by omega)
    refine ⟨(acc, flags), ?_, by simpa [hs] using And.intro ha hf⟩
    rw [verify.CellBatchVerifier.interpolation_commitment_loop0, loop.eq_1]
    simp only [verify.CellBatchVerifier.interpolation_commitment_loop0.body,
      hnext, bind_tc_ok, Function.uncurry_apply_pair]
  | succ n ih =>
    have hk : iter.start.val < indices.val.length := by omega
    obtain ⟨iter', hi', hend', hnext⟩ := Refinement.next_lt iter (by omega)
    let raw := indices.val[iter.start.val]'hk
    have hraw : raw.val < 128 := hindices raw (List.getElem_mem hk)
    let c : Usize := UScalar.cast .Usize raw
    have hcv : c.val = raw.val := by
      rw [UScalar.cast_val_eq]
      apply Nat.mod_eq_of_lt
      scalar_tac
    have hindex : Slice.index_usize indices iter.start = ok raw := by
      simp [Slice.index_usize, hk, raw]
    have hused : alloc.vec.Vec.index_mut (core.slice.index.SliceIndexUsizeSlice Bool) flags c =
        ok (used[c.val]!, alloc.vec.Vec.set flags c) := by
      simp [alloc.vec.Vec.index_mut_usize, alloc.vec.Vec.index_usize, hf, getElem!_pos,
        show c.val < used.length by omega]
    let flags' := alloc.vec.Vec.set flags c true
    have hf' : flags'.val = used.set c.val true := by simp [flags', alloc.vec.Vec.set, hf]
    obtain ⟨acc', hcell, ha'⟩ := aggregate_column h evaluations powers columns v vp acc
      he hp ha iter.start c (by omega) (by omega) (by omega)
    have hbody : verify.CellBatchVerifier.interpolation_commitment_loop0.body
        v vp indices iter acc flags = ok (cont (iter', acc', flags')) := by
      simp only [verify.CellBatchVerifier.interpolation_commitment_loop0.body, hnext,
        bind_tc_ok, Function.uncurry_apply_pair, hindex, lift, hused, hcell, flags', c]
    obtain ⟨result, hloop, hr⟩ := ih
      (aggregateCell evaluations powers iter.start.val c.val columns) (used.set c.val true)
      acc' flags' ha' hf' (by simpa [aggregateCell_length] using hc) (by simpa using hu)
      iter' (by omega) (by simpa only [hend'] using hend) (by omega)
    refine ⟨result, ?_, ?_⟩
    · rw [verify.CellBatchVerifier.interpolation_commitment_loop0, loop.eq_1]
      simp only [hbody]
      exact hloop
    · have hget : (indices.val.map (·.val))[iter.start.val]! = c.val := by
        simp [getElem!_pos, hk, hcv, raw]
      rw [List.drop_eq_getElem_cons (by simp [hk])]
      simpa only [List.foldl_cons, List.getElem_range, hi', aggregateStep, hget] using hr

theorem aggregate_columns [e : KzgExternals] (h : ExternalsCorrect e)
    (evaluations powers columns : List Fr) (used : List Bool)
    (v vp acc : alloc.vec.Vec blst.blst_fr) (flags : alloc.vec.Vec Bool)
    (indices : Slice U64)
    (he : v.val = evaluations.map frEncode) (hp : vp.val = powers.map frEncode)
    (ha : acc.val = columns.map frEncode) (hf : flags.val = used)
    (hep : indices.val.length*64 ≤ evaluations.length) (hpp : indices.val.length ≤ powers.length)
    (hc : columns.length = 8192) (hu : used.length = 128)
    (hindices : ∀ i ∈ indices.val, i.val < 128) :
    ∃ result,
      verify.CellBatchVerifier.interpolation_commitment_loop0
        { start := 0#usize, «end» := Slice.len indices } v vp acc flags indices = ok result ∧
      let expected := aggregateColumns evaluations powers (indices.val.map (·.val)) columns used
      result.1.val = expected.1.map frEncode ∧ result.2.val = expected.2 := by
  simpa only [aggregateColumns, UScalar.ofNatCore_val_eq, List.drop_zero, List.length_map] using
    aggregate_columns_loop h evaluations powers columns used v vp acc flags indices
      he hp ha hf hep hpp hc hu hindices
      { start := 0#usize, «end» := Slice.len indices } (by simp) (by simp)

def shiftAdd (shift factor : Fr) : List Fr → List Fr → List Fr
  | a :: rest, b :: bs => (b + a*factor) :: shiftAdd shift (factor*shift) rest bs
  | _, _ => []

theorem shiftAdd_length (shift factor : Fr) (coeffs old : List Fr)
    (hlen : coeffs.length = old.length) : (shiftAdd shift factor coeffs old).length = old.length := by
  induction coeffs generalizing old factor with
  | nil =>
    have : old = [] := List.eq_nil_of_length_eq_zero (by simpa using hlen.symm)
    subst old
    rfl
  | cons a coeffs ih =>
    cases old with
    | nil => simp at hlen
    | cons b old => simp only [shiftAdd, List.length_cons, ih _ _ (by simpa using hlen)]

theorem shift_add_loop [e : KzgExternals] (h : ExternalsCorrect e)
    (shifts coeffPrefix remaining doneValues oldValues : List Fr)
    (vs vc acc : alloc.vec.Vec blst.blst_fr)
    (hs : vs.val = shifts.map frEncode)
    (hc : vc.val = (coeffPrefix ++ remaining).map frEncode)
    (ha : acc.val = (doneValues ++ oldValues).map frEncode)
    (hlen : oldValues.length = remaining.length)
    (hprefix : coeffPrefix.length = doneValues.length)
    (c : Usize) (hci : c.val < shifts.length) (factor : Fr)
    (iter : core.ops.range.Range Usize) (hi : iter.start.val = doneValues.length)
    (hend : iter.end.val = doneValues.length + remaining.length) :
    ∃ result,
      verify.CellBatchVerifier.interpolation_commitment_loop1_loop1
        iter vs vc acc c (frEncode factor) = ok result ∧
      result.val = (doneValues ++ shiftAdd shifts[c.val]! factor remaining oldValues).map frEncode := by
  induction remaining generalizing coeffPrefix doneValues oldValues acc iter factor with
  | nil =>
    have he : oldValues = [] := List.eq_nil_of_length_eq_zero (by simpa using hlen)
    subst oldValues
    have hnext := Refinement.next_ge iter (by simp_all)
    refine ⟨acc, ?_, by simpa [shiftAdd] using ha⟩
    rw [verify.CellBatchVerifier.interpolation_commitment_loop1_loop1, loop.eq_1]
    simp only [verify.CellBatchVerifier.interpolation_commitment_loop1_loop1.body,
      hnext, bind_tc_ok, Function.uncurry_apply_pair]
  | cons a remaining ih =>
    cases oldValues with
    | nil => simp at hlen
    | cons b oldValues =>
      obtain ⟨iter', hi', hend', hnext⟩ := Refinement.next_lt iter (by simp_all)
      have hcoeff : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice blst.blst_fr)
          vc iter.start = ok (frEncode a) := by
        simp [alloc.vec.Vec.index_usize, hc, hi, ← hprefix, List.getElem_append_right]
      have hacc : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice blst.blst_fr)
          acc iter.start = ok (frEncode b) := by
        simp [alloc.vec.Vec.index_usize, ha, hi, List.getElem_append_right]
      have hmut : alloc.vec.Vec.index_mut (core.slice.index.SliceIndexUsizeSlice blst.blst_fr)
          acc iter.start = ok (frEncode b, alloc.vec.Vec.set acc iter.start) := by
        have hacc' : alloc.vec.Vec.index_usize acc iter.start = ok (frEncode b) := by
          simpa only [alloc.vec.Vec.index_slice_index] using hacc
        simp only [alloc.vec.Vec.index_mut_slice_index, alloc.vec.Vec.index_mut_usize, hacc']
      have hshift := index_encoded vs shifts hs c hci
      let acc' := alloc.vec.Vec.set acc iter.start (frEncode (b + a*factor))
      have ha' : acc'.val = ((doneValues ++ [b + a*factor]) ++ oldValues).map frEncode := by
        simp [acc', alloc.vec.Vec.set, ha, hi, List.set_append_right]
      have hbody : verify.CellBatchVerifier.interpolation_commitment_loop1_loop1.body
          vs vc c iter acc (frEncode factor) =
          ok (cont (iter', acc', frEncode (factor*shifts[c.val]!))) := by
        simp only [verify.CellBatchVerifier.interpolation_commitment_loop1_loop1.body,
          hnext, bind_tc_ok, Function.uncurry_apply_pair, hcoeff, blst_ops.fr_mul,
          h.blst.fr_mul, hacc, blst_ops.fr_add, h.blst.fr_add, hmut, hshift, acc']
      obtain ⟨result, hloop, hr⟩ := ih (coeffPrefix ++ [a])
        (doneValues ++ [b+a*factor]) oldValues acc'
        (by simpa [List.append_assoc] using hc) ha'
        (by simpa using hlen) (by simp [hprefix]) (factor*shifts[c.val]!)
        iter' (by simp [hi', hi]) (by simp [hend', hend]; omega)
      refine ⟨result, ?_, ?_⟩
      · rw [verify.CellBatchVerifier.interpolation_commitment_loop1_loop1, loop.eq_1]
        simp only [hbody]
        exact hloop
      · simpa only [shiftAdd, List.append_assoc, List.singleton_append] using hr

private theorem reverse6_bound (j : Nat) (hj : j < 64) :
    BitReversal.reverseBitsAux j 0 6 < 64 := by
  interval_cases j <;> decide

def reversedColumn (columns : List Fr) (c : Nat) : List Fr :=
  List.ofFn (fun j : Fin 64 => columns[c*64 + BitReversal.reverseBitsAux j.val 0 6]!)

@[simp] theorem reversedColumn_length (columns : List Fr) (c : Nat) :
    (reversedColumn columns c).length = 64 := by simp [reversedColumn]

private theorem copy_column_loop
    (columns before remaining : List Fr) (oldValues : List blst.blst_fr)
    (v acc : alloc.vec.Vec blst.blst_fr)
    (hv : v.val = columns.map frEncode)
    (ha : acc.val = before.map frEncode ++ oldValues)
    (hcolumns : columns.length = 8192)
    (hlen : before.length + remaining.length = 64)
    (hold : oldValues.length = remaining.length)
    (c : Usize) (hc : c.val < 128)
    (hsource : ∀ j < 64,
      columns[c.val*64 + BitReversal.reverseBitsAux j 0 6]! = (before ++ remaining)[j]!)
    (iter : core.ops.range.Range Usize) (hi : iter.start.val = before.length)
    (hend : iter.end.val = 64) :
    ∃ result,
      verify.CellBatchVerifier.interpolation_commitment_loop1_loop0 iter v acc c = ok result ∧
      result.val = (before ++ remaining).map frEncode := by
  induction remaining generalizing before oldValues acc iter with
  | nil =>
    have he : oldValues = [] := List.eq_nil_of_length_eq_zero (by simpa using hold)
    subst oldValues
    have hnext := Refinement.next_ge iter (by simp_all)
    refine ⟨acc, ?_, by simpa using ha⟩
    rw [verify.CellBatchVerifier.interpolation_commitment_loop1_loop0, loop.eq_1]
    simp only [verify.CellBatchVerifier.interpolation_commitment_loop1_loop0.body,
      hnext, bind_tc_ok, Function.uncurry_apply_pair]
  | cons a remaining ih =>
    cases oldValues with
    | nil => simp at hold
    | cons b oldValues =>
      have hj : iter.start.val < 64 := by simp only [List.length_cons] at hlen; omega
      obtain ⟨iter', hi', hend', hnext⟩ := Refinement.next_lt iter (by omega)
      have hrevbound := reverse6_bound iter.start.val hj
      let rev : Usize := ⟨BitVec.ofNat _ (BitReversal.reverseBitsAux iter.start.val 0 6)⟩
      have hrevval : rev.val = BitReversal.reverseBitsAux iter.start.val 0 6 := by
        simp only [rev, UScalar.val, BitVec.toNat_ofNat]
        apply Nat.mod_eq_of_lt
        scalar_tac
      have hrev : domain.reverse_bits iter.start verify.LOG_CELL = ok rev := by
        simpa only [verify.LOG_CELL, UScalar.ofNatCore_val_eq, rev] using
          reverse_bits_refinement iter.start verify.LOG_CELL (by
            simp only [verify.LOG_CELL, UScalar.ofNatCore_val_eq]
            rcases System.Platform.numBits_eq with hh | hh <;> simp [Usize.numBits, hh])
      obtain ⟨base, hbase, hbaseval⟩ := WP.spec_imp_exists
        (@Usize.mul_spec c FIELD_ELEMENTS_PER_CELL (by
          simp only [FIELD_ELEMENTS_PER_CELL, UScalar.ofNatCore_val_eq]
          scalar_tac))
      have hbaseval' : base.val = c.val*64 := by
        simpa only [FIELD_ELEMENTS_PER_CELL, UScalar.ofNatCore_val_eq] using hbaseval
      obtain ⟨source, hsum, hsourceval⟩ := WP.spec_imp_exists
        (@Usize.add_spec base rev (by scalar_tac))
      have hsourceval' : source.val = c.val*64 + BitReversal.reverseBitsAux iter.start.val 0 6 := by
        omega
      have hread := index_encoded v columns hv source (by omega)
      have hvalue : columns[source.val]! = a := by
        rw [hsourceval', hsource iter.start.val hj]
        simp [hi, List.getElem_append_right]
      rw [hvalue] at hread
      have hmut : alloc.vec.Vec.index_mut (core.slice.index.SliceIndexUsizeSlice blst.blst_fr)
          acc iter.start = ok (b, alloc.vec.Vec.set acc iter.start) := by
        simp [alloc.vec.Vec.index_mut_usize, alloc.vec.Vec.index_usize,
          ha, hi, List.getElem_append_right]
      let acc' := alloc.vec.Vec.set acc iter.start (frEncode a)
      have ha' : acc'.val = (before ++ [a]).map frEncode ++ oldValues := by
        simp [acc', alloc.vec.Vec.set, ha, hi, List.set_append_right]
      have hbody : verify.CellBatchVerifier.interpolation_commitment_loop1_loop0.body
          v c iter acc = ok (cont (iter', acc')) := by
        simp only [verify.CellBatchVerifier.interpolation_commitment_loop1_loop0.body,
          hnext, bind_tc_ok, Function.uncurry_apply_pair, hbase, hrev, hsum, hread, hmut, acc']
      obtain ⟨result, hloop, hr⟩ := ih (before ++ [a]) oldValues acc' ha'
        (by simp at hlen ⊢; omega) (by simpa using hold)
        (by simpa only [List.append_assoc, List.singleton_append] using hsource)
        iter' (by simp [hi', hi]) (by simpa only [hend'] using hend)
      refine ⟨result, ?_, ?_⟩
      · rw [verify.CellBatchVerifier.interpolation_commitment_loop1_loop0, loop.eq_1]
        simp only [hbody]
        exact hloop
      · simpa only [List.append_assoc, List.singleton_append] using hr

theorem copy_column (columns : List Fr) (scratch : List blst.blst_fr)
    (v acc : alloc.vec.Vec blst.blst_fr)
    (hv : v.val = columns.map frEncode) (ha : acc.val = scratch)
    (hcolumns : columns.length = 8192) (hscratch : scratch.length = 64)
    (c : Usize) (hc : c.val < 128) :
    ∃ result,
      verify.CellBatchVerifier.interpolation_commitment_loop1_loop0
        { start := 0#usize, «end» := FIELD_ELEMENTS_PER_CELL } v acc c = ok result ∧
      result.val = (reversedColumn columns c.val).map frEncode := by
  apply copy_column_loop columns [] (reversedColumn columns c.val) scratch v acc hv
    (by simpa using ha) hcolumns (by simp [reversedColumn]) (by simp [reversedColumn, hscratch])
    c hc
    (by
      intro j hj
      rw [List.nil_append, getElem!_pos (reversedColumn columns c.val) j (by simpa using hj)]
      simp only [reversedColumn, List.getElem_ofFn])
    { start := 0#usize, «end» := FIELD_ELEMENTS_PER_CELL }
    (by simp) (by simp [FIELD_ELEMENTS_PER_CELL])

def totalStep (columns : List Fr) (used : List Bool) (total : List Fr) (c : Nat) : List Fr :=
  if used[c]! then
    shiftAdd (Model.cosetShift c).inverse (Fr.ofNat 1)
      (fftField (reversedColumn columns c).toArray (computeRootsOfUnity 64) true).toList total
  else total

end LeanBlsSimd.Kzg.Interpolation
