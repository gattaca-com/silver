import LeanBlsSimd.Kzg.Refines.Interpolation
import EthLib.Cryptography.Proofs.Kzg.Fft
import EthLib.Cryptography.Proofs.Kzg.Polynomials

open EthLib.Cryptography Bls Kzg

namespace LeanBlsSimd.Kzg.Interpolation

set_option maxHeartbeats 2000000
set_option maxRecDepth 16000

theorem aggregateColumns_lengths (evaluations powers : List Fr) (indices : List Nat)
    (columns : List Fr) (used : List Bool) :
    (aggregateColumns evaluations powers indices columns used).1.length = columns.length ∧
    (aggregateColumns evaluations powers indices columns used).2.length = used.length := by
  unfold aggregateColumns
  generalize List.range indices.length = ks
  induction ks generalizing columns used with
  | nil => exact ⟨rfl, rfl⟩
  | cons k ks ih =>
    simpa only [List.foldl_cons, aggregateStep, aggregateCell_length, List.length_set]
      using ih (aggregateCell evaluations powers k indices[k]! columns)
        (used.set indices[k]! true)

def columnView (columns : List Fr) (c : Nat) : Array Fr :=
  Array.ofFn (fun j : Fin 64 => columns[c*64+j.val]!)

@[simp] theorem columnView_size (columns : List Fr) (c : Nat) :
    (columnView columns c).size = 64 := by simp [columnView]

private theorem column_fold_length (evaluations powers : List Fr) (k c : Nat)
    (columns : List Fr) (js : List Nat) :
    (js.foldl (columnStep evaluations powers k c) columns).length = columns.length := by
  induction js generalizing columns with
  | nil => rfl
  | cons j js ih =>
    simpa only [List.foldl_cons, columnStep_length] using
      ih (columnStep evaluations powers k c columns j)

private theorem column_fold_get (evaluations powers columns : List Fr) (k c d j n : Nat)
    (hlen : columns.length = 8192) (hc : c < 128) (hd : d < 128) (hj : j < 64)
    (hn : n ≤ 64) :
    ((List.range n).foldl (columnStep evaluations powers k c) columns)[d*64+j]! =
      if d = c ∧ j < n then columns[d*64+j]! + powers[k]! * evaluations[k*64+j]!
      else columns[d*64+j]! := by
  induction n with
  | zero => simp
  | succ n ih =>
    have hnb : n < 64 := by omega
    have hold := ih (by omega)
    have hlen' : ((List.range n).foldl (columnStep evaluations powers k c) columns).length =
        8192 := (column_fold_length _ _ _ _ _ _).trans hlen
    have hjb : d*64+j < 8192 := by omega
    have hnb' : c*64+n < 8192 := by omega
    rw [List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil, columnStep]
    rw [getElem!_pos _ _ (by simpa only [List.length_set, hlen'] using hjb),
      List.getElem_set]
    by_cases hsame : c*64+n = d*64+j
    · have hdc : d = c := by omega
      have hjn : j = n := by omega
      subst d
      subst j
      simp only [if_true]
      rw [ih (by omega)]
      simp
    · have hne : ¬(d = c ∧ j = n) := by omega
      simp only [hsame, if_false]
      rw [← getElem!_pos _ _ (by simpa only [hlen'] using hjb), hold]
      by_cases hdc : d = c
      · simp only [hdc, true_and]
        have : (j < n + 1) = (j < n) := propext (by omega)
        simp only [this]
      · simp [hdc]

theorem columnView_aggregateCell (evaluations powers columns : List Fr) (k c d : Nat)
    (hlen : columns.length = 8192) (hc : c < 128) (hd : d < 128) :
    columnView (aggregateCell evaluations powers k c columns) d =
      if d = c then Array.ofFn (fun j : Fin 64 =>
        (columnView columns d)[j.val]! + powers[k]! * evaluations[k*64+j.val]!)
      else columnView columns d := by
  apply Array.ext
  · simp only [columnView_size]
    split <;> simp [columnView]
  · intro j hj hj'
    have hj64 : j < 64 := by simpa only [columnView_size] using hj
    simp only [columnView, Array.getElem_ofFn, aggregateCell]
    rw [column_fold_get evaluations powers columns k c d j 64 hlen hc hd hj64 (by omega)]
    by_cases hdc : d = c <;> simp [hdc, hj64, getElem!_pos]

theorem flat_evals_length (rows : List (Array Fr))
    (hs : ∀ row ∈ rows, row.size = 64) :
    (rows.flatMap Array.toList).length = rows.length * 64 := by
  induction rows with
  | nil => simp
  | cons row rows ih =>
    have hrow := hs row (by simp)
    have hrows : ∀ row ∈ rows, row.size = 64 := fun row hr => hs row (by simp [hr])
    simp [List.flatMap_cons, hrow, ih hrows, Nat.add_mul, Nat.add_comm]

theorem flat_evals_get (rows : List (Array Fr))
    (hs : ∀ row ∈ rows, row.size = 64) (k j : Nat) (hk : k < rows.length) (hj : j < 64) :
    (rows.flatMap Array.toList)[k*64+j]! = (rows[k]!)[j]! := by
  induction rows generalizing k with
  | nil => simp at hk
  | cons row rows ih =>
    have hrow := hs row (by simp)
    have hrows : ∀ row ∈ rows, row.size = 64 := fun row hr => hs row (by simp [hr])
    have hlength := flat_evals_length rows hrows
    cases k with
    | zero =>
      simp only [Nat.zero_mul, Nat.zero_add, List.getElem!_cons_zero, List.flatMap_cons]
      rw [getElem!_pos _ _ (by simp only [List.length_append, Array.length_toList, hrow]; omega),
        List.getElem_append_left (by simpa only [Array.length_toList, hrow] using hj)]
      simp [getElem!_pos, hrow, hj]
    | succ k =>
      have hk' : k < rows.length := by simpa using hk
      simp only [List.flatMap_cons, List.getElem!_cons_succ]
      have hbound : (k+1)*64+j < (row.toList ++ rows.flatMap Array.toList).length := by
        simp only [List.length_append, Array.length_toList, hrow, hlength]
        omega
      rw [getElem!_pos (row.toList ++ rows.flatMap Array.toList) _ hbound,
        List.getElem_append_right (by simp only [Array.length_toList, hrow]; omega)]
      have hidx : (k+1)*64+j-row.toList.length = k*64+j := by
        simp only [Array.length_toList, hrow]
        omega
      simp only [hidx]
      rw [← getElem!_pos (rows.flatMap Array.toList) (k*64+j) (by rw [hlength]; omega)]
      exact ih hrows k hk'

theorem totalStep_length (columns : List Fr) (used : List Bool) (total : List Fr)
    (c : Nat) (ht : total.length = 64) : (totalStep columns used total c).length = 64 := by
  unfold totalStep
  split
  · rw [shiftAdd_length]
    · exact ht
    · simp [ht]
  · exact ht

private theorem aggregate_fold_lengths (evaluations powers : List Fr) (indices ks : List Nat)
    (columns : List Fr) (used : List Bool) :
    (ks.foldl (aggregateStep evaluations powers indices) (columns, used)).1.length = columns.length ∧
    (ks.foldl (aggregateStep evaluations powers indices) (columns, used)).2.length = used.length := by
  induction ks generalizing columns used with
  | nil => exact ⟨rfl, rfl⟩
  | cons k ks ih =>
    simpa only [List.foldl_cons, aggregateStep, aggregateCell_length, List.length_set]
      using ih (aggregateCell evaluations powers k indices[k]! columns)
        (used.set indices[k]! true)

def modelColumnStep (indices : Array Nat) (evals : Array (Array Fr)) (powers : Array Fr)
    (c : Nat) (acc : Array Fr) (k : Nat) : Array Fr :=
  if indices[k]! = c then
    Array.ofFn (fun j : Fin 64 => acc[j.val]! + powers[k]! * (evals[k]!)[j.val]!)
  else acc

theorem columnView_zero (c : Nat) (hc : c < 128) :
    columnView (List.replicate 8192 Fr.zero) c = Array.replicate 64 Fr.zero := by
  apply Array.ext
  · simp only [columnView_size, Array.size_replicate]
  · intro j hj hj'
    have h : c*64+j < 8192 := by simp only [columnView_size] at hj; omega
    simp only [columnView, Array.getElem_ofFn, Array.getElem_replicate,
      getElem!_pos (List.replicate 8192 Fr.zero) (c*64+j)
        (by simpa only [List.length_replicate] using h),
      List.getElem_replicate]

private theorem aggregate_projection_prefix
    (indices : Array Nat) (evals : Array (Array Fr)) (powers : Array Fr)
    (hi : Model.RliInputs indices evals powers) (c n : Nat) (hc : c < 128)
    (hn : n ≤ indices.size) :
    columnView ((List.range n).foldl
      (aggregateStep (evals.toList.flatMap Array.toList) powers.toList indices.toList)
      (List.replicate 8192 Fr.zero, List.replicate 128 false)).1 c =
    (List.range n).foldl (modelColumnStep indices evals powers c) (Array.replicate 64 Fr.zero) := by
  induction n with
  | zero => simpa only [List.range_zero, List.foldl_nil] using columnView_zero c hc
  | succ n ih =>
    have hn' : n < indices.size := by omega
    have hidx : indices[n]! < 128 := by
      rw [getElem!_pos indices n hn']
      exact hi.2.2.1 _ (Array.getElem_mem hn')
    simp only [List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil]
    dsimp only [aggregateStep]
    rw [columnView_aggregateCell _ _ _ _ _ _
      (by simpa only [List.length_replicate] using (aggregate_fold_lengths (evals.toList.flatMap Array.toList) powers.toList
        indices.toList (List.range n) (List.replicate 8192 Fr.zero)
        (List.replicate 128 false)).1)
      (by simpa only [Array.getElem!_toList] using hidx) hc]
    rw [ih (by omega)]
    unfold modelColumnStep
    simp only [Array.getElem!_toList]
    by_cases heq : indices[n]! = c
    · simp only [heq, if_true]
      congr 1
      funext j
      rw [flat_evals_get evals.toList (by simpa using hi.2.2.2) n j.val
        (by simp only [Array.length_toList]; rw [← hi.1]; exact hn') j.isLt]
      simp only [Array.getElem!_toList]
    · simp [heq, Ne.symm heq]

theorem aggregate_projection
    (indices : Array Nat) (evals : Array (Array Fr)) (powers : Array Fr)
    (hi : Model.RliInputs indices evals powers) (c : Nat) (hc : c < 128) :
    columnView (aggregateColumns (evals.toList.flatMap Array.toList) powers.toList indices.toList
      (List.replicate 8192 Fr.zero) (List.replicate 128 false)).1 c =
    (Array.range indices.size).foldl (modelColumnStep indices evals powers c)
      (Array.replicate 64 Fr.zero) := by
  simpa only [aggregateColumns, Array.length_toList, ← Array.foldl_toList,
    Array.toList_range] using aggregate_projection_prefix indices evals powers hi c indices.size hc le_rfl

private theorem getElem!_zero (n j : Nat) :
    (Array.replicate n (0 : Fr))[j]! = 0 := by
  by_cases hj : j < n
  · simp [getElem!_pos, hj]
  · rw [getElem!_neg _ _ (by simpa using hj)]
    rfl

private theorem fftHalve_zero (n start : Nat) :
    fftHalve (Array.replicate n Fr.zero) start = Array.replicate (n/2) Fr.zero := by
  apply Array.ext
  · simp
  · intro j hj hj'
    simp only [fftHalve, Array.getElem_ofFn, show Fr.zero = (0 : Fr) from rfl,
      getElem!_zero, Array.getElem_replicate]

theorem fftFieldAux_zero (n : Nat) (roots : Array Fr) :
    fftFieldAux (Array.replicate n Fr.zero) roots = Array.replicate n Fr.zero := by
  induction n using Nat.strong_induction_on generalizing roots with
  | h n ih =>
    rw [fftFieldAux]
    simp only [Array.size_replicate]
    split
    · rfl
    · rename_i hn
      have hh : n / 2 < n := by omega
      rw [fftHalve_zero, fftHalve_zero, ih (n/2) hh]
      apply Array.ext
      · simp
      · intro j hj hj'
        simp only [Array.getElem_ofFn, Array.getElem_replicate,
          show Fr.zero = (0 : Fr) from rfl, getElem!_zero, Fin.zero_mul, Fin.zero_add, Fin.sub_self]
        split <;> rfl

theorem fftField_zero (n : Nat) (roots : Array Fr) (inv : Bool) :
    fftField (Array.replicate n Fr.zero) roots inv = Array.replicate n Fr.zero := by
  rw [fftField_def]
  cases inv
  · simp only [Bool.false_eq_true, if_false, fftFieldAux_zero]
  · simp only [if_true, fftFieldAux_zero]
    apply Array.ext
    · simp
    · intro j hj hj'
      simp only [Array.getElem_map, Array.getElem_replicate,
        show Fr.zero = (0 : Fr) from rfl, Fin.zero_mul]

private theorem aggregate_unused_fold (evaluations powers : List Fr) (indices ks : List Nat)
    (columns : List Fr) (used : List Bool) (c : Nat) (hc : c < 128)
    (hlen : columns.length = 8192) (hu : used.length = 128)
    (hks : ∀ k ∈ ks, indices[k]! < 128)
    (hz : used[c]! = false → columnView columns c = Array.replicate 64 Fr.zero) :
    let a := ks.foldl (aggregateStep evaluations powers indices) (columns, used)
    a.2[c]! = false → columnView a.1 c = Array.replicate 64 Fr.zero := by
  induction ks generalizing columns used with
  | nil => exact hz
  | cons k ks ih =>
    dsimp only [List.foldl_cons, aggregateStep]
    apply ih (aggregateCell evaluations powers k indices[k]! columns)
      (used.set indices[k]! true) (by rw [aggregateCell_length]; exact hlen)
      (by simpa using hu) (fun k hk => hks k (by simp [hk]))
    intro hfalse
    have hne : indices[k]! ≠ c := by
      intro heq
      simp [heq, getElem!_pos, hu, hc] at hfalse
    rw [columnView_aggregateCell evaluations powers columns k indices[k]! c
      hlen (hks k (by simp)) hc, if_neg (Ne.symm hne)]
    apply hz
    simpa only [getElem!_pos (used.set indices[k]! true) c
      (by simpa only [List.length_set, hu] using hc),
      List.getElem_set, hne, if_false,
      getElem!_pos used c (by simpa only [hu] using hc)]
      using hfalse

theorem aggregate_unused (evaluations powers : List Fr) (indices : List Nat)
    (hi : ∀ i ∈ indices, i < 128) (c : Nat) (hc : c < 128) :
    let a := aggregateColumns evaluations powers indices
      (List.replicate 8192 Fr.zero) (List.replicate 128 false)
    a.2[c]! = false → columnView a.1 c = Array.replicate 64 Fr.zero := by
  apply aggregate_unused_fold evaluations powers indices (List.range indices.length)
    (List.replicate 8192 Fr.zero) (List.replicate 128 false) c hc
    (List.length_replicate ..) (List.length_replicate ..)
  · intro k hk
    have hk' : k < indices.length := List.mem_range.mp hk
    rw [getElem!_pos indices k hk']
    exact hi _ (List.getElem_mem hk')
  · intro _
    exact columnView_zero c hc

theorem reversedColumn_eq (columns : List Fr) (c : Nat) :
    (reversedColumn columns c).toArray = BitReversal.bitReversalPermutation (columnView columns c) := by
  apply Array.ext
  · simp only [List.size_toArray, reversedColumn_length, BitReversal.bitReversalPermutation,
      Array.size_ofFn, columnView_size]
  · intro j hj hj'
    have hj64 : j < 64 := by simpa only [List.size_toArray, reversedColumn_length] using hj
    have hrev : BitReversal.reverseBitsAux j 0 6 < 64 := by interval_cases j <;> decide
    simp only [reversedColumn, List.getElem_toArray, List.getElem_ofFn,
      BitReversal.bitReversalPermutation, Array.getElem_ofFn, columnView_size,
      BitReversal.reverseBits, show Nat.log2 64 = 6 from rfl]
    exact (Array.getElem!_ofFn (fun i : Fin 64 => columns[c*64+i.val]!) _ hrev).symm

private theorem shiftAdd_get (shift factor : Fr) (coeffs old : List Fr)
    (hlen : coeffs.length = old.length) (j : Nat) (hj : j < old.length) :
    (shiftAdd shift factor coeffs old)[j]! =
      old[j]! + (shiftValsAux shift factor coeffs)[j]! := by
  induction coeffs generalizing old factor j with
  | nil =>
    have : old.length = 0 := by simpa only [List.length_nil] using hlen.symm
    omega
  | cons a coeffs ih =>
    cases old with
    | nil => simp at hj
    | cons b old =>
      cases j with
      | zero => simp only [shiftAdd, shiftValsAux, List.getElem!_cons_zero]
      | succ j =>
        simp only [shiftAdd, shiftValsAux, List.getElem!_cons_succ]
        exact ih (factor*shift) old (by simpa using hlen) j (by simpa using hj)

theorem shiftAdd_eq (shift : Fr) (coeffs old : List Fr)
    (hlen : coeffs.length = old.length) :
    (shiftAdd shift (Fr.ofNat 1) coeffs old).toArray =
      addPolynomialcoeff old.toArray (shiftVals coeffs.toArray shift) := by
  have hs : (shiftVals coeffs.toArray shift).size = old.toArray.size := by simp [hlen]
  unfold addPolynomialcoeff
  rw [if_pos (Nat.le_of_eq hs)]
  apply Array.ext
  · simp only [List.size_toArray, Array.size_ofFn, shiftAdd_length _ _ _ _ hlen]
  · intro j hj hj'
    have hjold : j < old.length := by simpa only [Array.size_ofFn, List.size_toArray] using hj'
    have hjcoef : j < coeffs.length := by omega
    simp only [Array.getElem_ofFn, hs, List.size_toArray, hjold, if_true]
    rw [← getElem!_pos (shiftAdd shift (Fr.ofNat 1) coeffs old).toArray j hj]
    simp only [shiftVals, Array.getElem!_eq_toList_getElem!]
    exact shiftAdd_get shift Fr.one coeffs old hlen j hjold

private theorem shiftVals_zero (n : Nat) (factor : Fr) :
    shiftVals (Array.replicate n Fr.zero) factor = Array.replicate n Fr.zero := by
  apply Array.ext
  · simp
  · intro j hj hj'
    rw [getElem_shiftVals]
    simp only [Array.getElem_replicate, show Fr.zero = (0 : Fr) from rfl, Fin.zero_mul]

private theorem addPolynomialcoeff_zero (total : Array Fr) :
    addPolynomialcoeff total (Array.replicate total.size Fr.zero) = total := by
  unfold addPolynomialcoeff
  simp only [Array.size_replicate, le_refl, if_true]
  apply Array.ext
  · simp
  · intro j hj hj'
    simp only [Array.getElem_ofFn, hj', if_true,
      getElem!_pos total j hj', show Fr.zero = (0 : Fr) from rfl, getElem!_zero, Fin.add_zero]

private theorem bitReversal_zero (n : Nat) :
    BitReversal.bitReversalPermutation (Array.replicate n Fr.zero) =
      Array.replicate n Fr.zero := by
  apply Array.ext
  · simp only [BitReversal.bitReversalPermutation, Array.size_ofFn]
  · intro j hj hj'
    simp only [BitReversal.bitReversalPermutation, Array.getElem_ofFn,
      show Fr.zero = (0 : Fr) from rfl, getElem!_zero, Array.getElem_replicate]

private def modelTotalStep (indices : Array Nat) (evals : Array (Array Fr))
    (powers : Array Fr) (total : Array Fr) (c : Nat) : Array Fr :=
  let column := (Array.range indices.size).foldl (modelColumnStep indices evals powers c)
    (Array.replicate 64 Fr.zero)
  let coeffs := fftField (BitReversal.bitReversalPermutation column) (computeRootsOfUnity 64) true
  addPolynomialcoeff total (shiftVals coeffs (Model.cosetShift c).inverse)

private theorem totalStep_eq_model (indices : Array Nat) (evals : Array (Array Fr))
    (powers : Array Fr) (hi : Model.RliInputs indices evals powers)
    (total : List Fr) (ht : total.length = 64) (c : Nat) (hc : c < 128) :
    let a := aggregateColumns (evals.toList.flatMap Array.toList) powers.toList indices.toList
      (List.replicate 8192 Fr.zero) (List.replicate 128 false)
    (totalStep a.1 a.2 total c).toArray = modelTotalStep indices evals powers total.toArray c := by
  let a := aggregateColumns (evals.toList.flatMap Array.toList) powers.toList indices.toList
    (List.replicate 8192 Fr.zero) (List.replicate 128 false)
  change (totalStep a.1 a.2 total c).toArray = _
  unfold modelTotalStep
  rw [← aggregate_projection indices evals powers hi c hc]
  change (totalStep a.1 a.2 total c).toArray =
    addPolynomialcoeff total.toArray (shiftVals
      (fftField (BitReversal.bitReversalPermutation (columnView a.1 c)) (computeRootsOfUnity 64) true)
      (Model.cosetShift c).inverse)
  cases hflag : a.2[c]! with
  | false =>
    have hzero : columnView a.1 c = Array.replicate 64 Fr.zero :=
      aggregate_unused _ _ indices.toList (by simpa only [Array.mem_toList_iff] using hi.2.2.1) c hc hflag
    rw [hzero, bitReversal_zero, fftField_zero, shiftVals_zero]
    have hts : total.toArray.size = 64 := by simpa only [List.size_toArray] using ht
    rw [← hts, addPolynomialcoeff_zero]
    simp only [totalStep, hflag, Bool.false_eq_true, if_false]
  | true =>
    simp only [totalStep, hflag, if_true]
    rw [shiftAdd_eq _ _ _ (by simp only [Array.length_toList, size_fftField,
      List.size_toArray, reversedColumn_length, ht])]
    simp only [Array.toArray_toList, reversedColumn_eq]

private theorem fold_totalStep (columns : List Fr) (used : List Bool)
    (step : Array Fr → Nat → Array Fr)
    (hstep : ∀ total : List Fr, total.length = 64 → ∀ c, c < 128 →
      (totalStep columns used total c).toArray = step total.toArray c)
    (cs : List Nat) (hcs : ∀ c ∈ cs, c < 128) (total : List Fr) (ht : total.length = 64) :
    (cs.foldl (totalStep columns used) total).toArray = cs.foldl step total.toArray := by
  induction cs generalizing total with
  | nil => rfl
  | cons c cs ih =>
    simp only [List.foldl_cons]
    rw [ih (fun c hc => hcs c (by simp [hc])) _ (totalStep_length _ _ _ _ ht)]
    rw [hstep total ht c (hcs c (by simp))]

private theorem columnRli_fold (indices : Array Nat) (evals : Array (Array Fr))
    (powers : Array Fr) :
    Model.columnRli indices evals powers =
      (List.range 128).foldl (modelTotalStep indices evals powers) (Array.replicate 64 Fr.zero) := by
  unfold Model.columnRli
  rw [← Array.foldl_toList, Array.toList_range]
  rfl

theorem aggregate_columnRli (indices : Array Nat) (evals : Array (Array Fr))
    (powers : Array Fr) (hi : Model.RliInputs indices evals powers) :
    let a := aggregateColumns (evals.toList.flatMap Array.toList) powers.toList indices.toList
      (List.replicate 8192 Fr.zero) (List.replicate 128 false)
    ((List.range 128).foldl (totalStep a.1 a.2) (List.replicate 64 Fr.zero)).toArray =
      Model.columnRli indices evals powers := by
  dsimp only
  rw [columnRli_fold]
  apply fold_totalStep _ _ (modelTotalStep indices evals powers)
    (fun total ht c hc => totalStep_eq_model indices evals powers hi total ht c hc)
    (List.range 128) (fun c hc => List.mem_range.mp hc) (List.replicate 64 Fr.zero)
    (List.length_replicate ..)

end LeanBlsSimd.Kzg.Interpolation
