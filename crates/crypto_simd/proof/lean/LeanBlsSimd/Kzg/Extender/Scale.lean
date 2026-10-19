import LeanBlsSimd.Kzg.Extender.Basic
import LeanBlsSimd.Kzg.Refines.Loop
import EthCryptographySpecs.Proofs.Kzg.Polynomials

open Aeneas Aeneas.Std Result ControlFlow
open EthCryptographySpecs Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg.Extender

private theorem shift_loop [e : KzgExternals] (h : BlstCorrect e)
    (remaining : List (Fr × Fr)) (doneValues shiftPrefix : List Fr)
    (out shifts : alloc.vec.Vec blst.blst_fr)
    (ho : out.val = (doneValues ++ remaining.map Prod.fst).map frEncode)
    (hs : shifts.val = (shiftPrefix ++ remaining.map Prod.snd).map frEncode)
    (hp : shiftPrefix.length = doneValues.length)
    (iter : core.ops.range.Range Usize) (hi : iter.start.val = doneValues.length)
    (he : iter.end.val = doneValues.length + remaining.length) :
    ∃ result, cell_extender.CellExtender.compute_loop iter shifts out = ok result ∧
      result.val = (doneValues ++ remaining.map (fun p => p.1 * p.2)).map frEncode := by
  induction remaining generalizing doneValues shiftPrefix out iter with
  | nil =>
    have hn := Refinement.next_ge iter (by simp_all)
    refine ⟨out, ?_, by simpa using ho⟩
    rw [cell_extender.CellExtender.compute_loop, loop.eq_1]
    simp only [cell_extender.CellExtender.compute_loop.body, hn, bind_tc_ok,
      Function.uncurry_apply_pair]
  | cons p remaining ih =>
    rcases p with ⟨a, w⟩
    obtain ⟨iter', hi', he', hn⟩ := Refinement.next_lt iter (by simp_all)
    have hindex : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice blst.blst_fr)
        out iter.start = ok (frEncode a) := by
      simp [alloc.vec.Vec.index_usize, ho, hi, List.getElem_append_right]
    have hshift : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice blst.blst_fr)
        shifts iter.start = ok (frEncode w) := by
      simp [alloc.vec.Vec.index_usize, hs, hi, ← hp, List.getElem_append_right]
    have hmut : alloc.vec.Vec.index_mut (core.slice.index.SliceIndexUsizeSlice blst.blst_fr)
        out iter.start = ok (frEncode a, alloc.vec.Vec.set out iter.start) := by
      have hindex' : alloc.vec.Vec.index_usize out iter.start = ok (frEncode a) := by
        simpa only [alloc.vec.Vec.index_slice_index] using hindex
      simp only [alloc.vec.Vec.index_mut_slice_index, alloc.vec.Vec.index_mut_usize, hindex']
    let out' := alloc.vec.Vec.set out iter.start (frEncode (a * w))
    have hout' : out'.val = ((doneValues ++ [a * w]) ++ remaining.map Prod.fst).map frEncode := by
      simp [out', alloc.vec.Vec.set, ho, hi, List.set_append_right]
    have hs' : shifts.val = ((shiftPrefix ++ [w]) ++ remaining.map Prod.snd).map frEncode := by
      simpa only [List.map_cons, List.append_assoc, List.singleton_append] using hs
    have hbody : cell_extender.CellExtender.compute_loop.body shifts iter out =
        ok (cont (iter', out')) := by
      simp only [cell_extender.CellExtender.compute_loop.body, hn, bind_tc_ok,
        Function.uncurry_apply_pair, hindex, hshift, blst_ops.fr_mul, h.fr_mul, hmut, out']
    obtain ⟨result, hloop, hr⟩ := ih (doneValues ++ [a * w]) (shiftPrefix ++ [w]) out'
      hout' hs' (by simpa using hp) iter' (by simp [hi', hi])
      (by simp [he', he, Nat.add_comm, Nat.add_left_comm])
    refine ⟨result, ?_, ?_⟩
    · rw [cell_extender.CellExtender.compute_loop, loop.eq_1]
      simp only [hbody]
      exact hloop
    · simpa [List.append_assoc] using hr

private theorem shift_arrays [e : KzgExternals] (h : BlstCorrect e)
    (n : Nat) (count : Usize) (hn : count.val = n) (coefficients shifts : alloc.vec.Vec blst.blst_fr)
    (values factors : _root_.Array Fr)
    (hv : values.size = n) (hf : factors.size = n)
    (hc : coefficients.val = values.toList.map frEncode)
    (hs : shifts.val = factors.toList.map frEncode) :
    ∃ out, cell_extender.CellExtender.compute_loop
        { start := 0#usize, «end» := count } shifts coefficients = ok out ∧
      out.val = (_root_.Array.ofFn (n := n) fun i =>
        values[i.val]! * factors[i.val]!).toList.map frEncode := by
  let pairs := List.ofFn fun i : Fin n => (values[i.val]!, factors[i.val]!)
  have hlen : pairs.length = n := List.length_ofFn
  have hleft : pairs.map Prod.fst = values.toList := by
    apply List.ext_getElem (by simp only [List.length_map, hlen, _root_.Array.length_toList, hv])
    intro j hj hvj
    have hjv : j < values.size := by omega
    simp only [pairs, List.getElem_map, List.getElem_ofFn, _root_.Array.getElem_toList,
      getElem!_pos values j hjv]
  have hright : pairs.map Prod.snd = factors.toList := by
    apply List.ext_getElem (by simp only [List.length_map, hlen, _root_.Array.length_toList, hf])
    intro j hj hfj
    have hjf : j < factors.size := by omega
    simp only [pairs, List.getElem_map, List.getElem_ofFn, _root_.Array.getElem_toList,
      getElem!_pos factors j hjf]
  obtain ⟨out, hout, hval⟩ := shift_loop h pairs [] [] coefficients shifts
    (by simpa only [List.nil_append, hleft] using hc)
    (by simpa only [List.nil_append, hright] using hs) rfl
    { start := 0#usize, «end» := count } (by simp) (by simp [hlen, hn])
  refine ⟨out, hout, ?_⟩
  simpa only [List.nil_append, pairs, List.map_ofFn, _root_.Array.toList_ofFn] using hval

private theorem shift_extract [e : KzgExternals] (h : BlstCorrect e)
    (n : Nat) (count : Usize) (hn : count.val = n) (coefficients shifts : alloc.vec.Vec blst.blst_fr)
    (values factors : _root_.Array Fr)
    (hv : values.size = n) (hf : n ≤ factors.size)
    (hc : coefficients.val = values.toList.map frEncode)
    (hs : shifts.val = (factors.extract 0 n).toList.map frEncode) :
    ∃ out, cell_extender.CellExtender.compute_loop
        { start := 0#usize, «end» := count } shifts coefficients = ok out ∧
      out.val = (_root_.Array.ofFn (n := n) fun i =>
        values[i.val]! * factors[i.val]!).toList.map frEncode := by
  have hlen : (factors.extract 0 n).size = n := by simp [Nat.min_eq_left hf]
  obtain ⟨out, hout, hval⟩ := shift_arrays h n count hn coefficients shifts
    values (factors.extract 0 n) hv hlen hc hs
  have hfunctions :
      (fun i : Fin n => values[i.val]! * (factors.extract 0 n)[i.val]!) =
      (fun i : Fin n => values[i.val]! * factors[i.val]!) := by
    funext i
    have hi : i.val < (factors.extract 0 n).size := by simpa only [hlen] using i.isLt
    rw [getElem!_pos (factors.extract 0 n) i.val hi, _root_.Array.getElem_extract]
    rw [getElem!_pos factors i.val (by omega)]
    simp only [Nat.zero_add]
  refine ⟨out, hout, ?_⟩
  rw [hfunctions] at hval
  exact hval

theorem shift_refinement [e : KzgExternals] (h : BlstCorrect e)
    (coefficients shifts : alloc.vec.Vec blst.blst_fr) (values : _root_.Array Fr)
    (hv : values.size = 4096)
    (hc : coefficients.val = values.toList.map frEncode)
    (hs : shifts.val = ((Kzg.Model.roots 13).extract 0 4096).toList.map frEncode) :
    ∃ out, cell_extender.CellExtender.compute_loop
        { start := 0#usize, «end» := FIELD_ELEMENTS_PER_BLOB } shifts coefficients = ok out ∧
      out.val = (_root_.Array.ofFn (n := 4096) fun i =>
        values[i.val]! * (Kzg.Model.roots 13)[i.val]!).toList.map frEncode :=
  shift_extract h 4096 FIELD_ELEMENTS_PER_BLOB (by simp [FIELD_ELEMENTS_PER_BLOB])
    coefficients shifts values (Kzg.Model.roots 13) hv (by simp [Kzg.Model.roots]) hc hs

end LeanBlsSimd.Kzg.Extender
