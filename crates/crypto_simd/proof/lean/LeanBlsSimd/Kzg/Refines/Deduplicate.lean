import LeanBlsSimd.Kzg.Refines.Bytes
import LeanBlsSimd.Kzg.Refines.Loop
import LeanBlsSimd.Kzg.Model

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg

private abbrev Commitment := Aeneas.Std.Array U8 48#usize

private theorem usize_succ (i : Usize) (stop : Usize) (h : i.val < stop.val) :
    ∃ j : Usize, i + 1#usize = ok j ∧ j.val = i.val + 1 := by
  have hb : i.val + 1 < 2 ^ UScalarTy.Usize.numBits := by
    have := stop.hBounds
    omega
  let j : Usize := UScalar.ofNatCore (i.val + 1) hb
  refine ⟨j, ?_, UScalar.ofNatCore_val_eq _⟩
  show UScalar.tryMk .Usize (i.val + (1#usize).val) = ok j
  have hb' : i.val + 1 < 2 ^ System.Platform.numBits := hb
  simp [UScalar.tryMk, UScalar.tryMkOpt, hb', Result.ofOption, j]

private theorem search_suffix
    (v : alloc.vec.Vec Commitment) (cs : Slice Commitment) (k : Usize)
    (hk : k.val < cs.val.length) (target : Commitment)
    (ht : cs.val[k.val] = target) (remaining prior : List Commitment)
    (hv : v.val = prior ++ remaining) (i : Usize) (hi : i.val = prior.length) :
    ∃ j, verify.Deduplicated.fill_loop0_loop0 v cs k (alloc.vec.Vec.len v) i = ok j ∧
      j.val = i.val + remaining.findIdx (fun a => arrayBytes a == arrayBytes target) := by
  induction remaining generalizing prior i with
  | nil =>
    have hend : i.val = v.val.length := by simp [hv, hi]
    refine ⟨alloc.vec.Vec.len v, ?_, ?_⟩
    · rw [verify.Deduplicated.fill_loop0_loop0, loop.eq_1]
      simp [verify.Deduplicated.fill_loop0_loop0.body, hend]
    · simp [hend]
  | cons a remaining ih =>
    have hlt : i.val < v.val.length := by simp [hv, hi]
    have htest : i < alloc.vec.Vec.len v := by simpa using hlt
    have hindex : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice Commitment)
        v i = ok a := by
      simp [alloc.vec.Vec.index_usize, hv, hi, List.getElem_append_right]
    have htarget : Slice.index_usize cs k = ok target := by
      simp [Slice.index_usize, hk, ht]
    cases hb : (arrayBytes a == arrayBytes target) with
    | true =>
      refine ⟨i, ?_, ?_⟩
      · rw [verify.Deduplicated.fill_loop0_loop0, loop.eq_1]
        simp only [verify.Deduplicated.fill_loop0_loop0.body, htest, if_true,
          hindex, htarget, bind_tc_ok, same_bytes_refinement, hb]
      · simp [List.findIdx_cons, hb]
    | false =>
      obtain ⟨i', hadd, hi'⟩ := usize_succ i (alloc.vec.Vec.len v) (by simpa using hlt)
      obtain ⟨j, hloop, hj⟩ := ih (prior ++ [a]) (by simpa [List.append_assoc] using hv)
        i' (by simp [hi', hi])
      refine ⟨j, ?_, ?_⟩
      · have hbody : verify.Deduplicated.fill_loop0_loop0.body v cs k
            (alloc.vec.Vec.len v) i = ok (cont i') := by
          simp only [verify.Deduplicated.fill_loop0_loop0.body, htest, if_true,
            hindex, htarget, bind_tc_ok, same_bytes_refinement, hb, Bool.false_eq_true,
            if_false, hadd]
        rw [verify.Deduplicated.fill_loop0_loop0, loop.eq_1, hbody]
        exact hloop
      · simp only [List.findIdx_cons, hb, cond_false]
        omega

private def dedupStep (state : _root_.Array ByteArray × _root_.Array Nat) (c : ByteArray) :=
  match state.1.idxOf? c with
  | some i => (state.1, state.2.push i)
  | none => (state.1.push c, state.2.push state.1.size)

private def dedupState (v : alloc.vec.Vec Commitment) (indices : alloc.vec.Vec Usize) :=
  ((v.val.map arrayBytes).toArray, (indices.val.map (·.val)).toArray)

private theorem step_eq (v : alloc.vec.Vec Commitment) (indices : alloc.vec.Vec Usize)
    (c : Commitment) (j : Usize)
    (hj : j.val = v.val.findIdx (fun a => arrayBytes a == arrayBytes c)) :
    dedupStep (dedupState v indices) (arrayBytes c) =
      (if j = alloc.vec.Vec.len v then
        ((v.val.map arrayBytes).toArray.push (arrayBytes c),
          (indices.val.map (·.val)).toArray.push j.val)
       else ((v.val.map arrayBytes).toArray,
          (indices.val.map (·.val)).toArray.push j.val)) := by
  have hfind : (v.val.map arrayBytes).findIdx (· == arrayBytes c) = j.val := by
    simpa only [List.findIdx_map, Function.comp_def] using hj.symm
  unfold dedupStep dedupState
  rw [List.idxOf?_toArray]
  cases hopt : (v.val.map arrayBytes).idxOf? (arrayBytes c) with
  | none =>
    have hlen : j.val = v.val.length := by
      rw [List.idxOf?] at hopt
      have hd := List.findIdx_eq_getD_findIdx? (xs := v.val.map arrayBytes)
        (p := (· == arrayBytes c))
      simpa [hfind, hopt] using hd
    have heq : j = alloc.vec.Vec.len v := by
      apply UScalar.eq_of_val_eq
      simpa using hlen
    simp [heq]
  | some n =>
    have hn := List.findIdx?_eq_some_iff_findIdx_eq.mp hopt
    have hval : j.val = n := by simpa [hfind] using hn.2
    have hne : j ≠ alloc.vec.Vec.len v := by
      intro heq
      have he := congrArg UScalar.val heq
      simp only [alloc.vec.Vec.len_val, alloc.vec.Vec.length] at he
      simp only [List.length_map] at hn
      omega
    simp [hne, hval]

private theorem fill_suffix (cs : Slice Commitment) (remaining prior : List Commitment)
    (hcs : cs.val = prior ++ remaining) (iter : core.ops.range.Range Usize)
    (hend : iter.end = Slice.len cs) (hi : iter.start.val = prior.length)
    (v : alloc.vec.Vec Commitment) (indices : alloc.vec.Vec Usize)
    (hv : v.val.length ≤ prior.length) (hindices : indices.val.length = prior.length) :
    ∃ out outIndices,
      verify.Deduplicated.fill_loop0 iter v indices cs = ok (out, outIndices) ∧
      dedupState out outIndices =
        (remaining.map arrayBytes).foldl dedupStep (dedupState v indices) := by
  induction remaining generalizing prior iter v indices with
  | nil =>
    have hnext := Refinement.next_ge iter (by simp [hend, hcs, hi])
    refine ⟨v, indices, ?_, by simp⟩
    rw [verify.Deduplicated.fill_loop0, loop.eq_1]
    simp only [verify.Deduplicated.fill_loop0.body, hnext, bind_tc_ok,
      Function.uncurry_apply_pair]
  | cons c remaining ih =>
    have hk : iter.start.val < cs.val.length := by simp [hcs, hi]
    have htarget : cs.val[iter.start.val] = c := by
      simp [hcs, hi, List.getElem_append_right]
    obtain ⟨iter', hi', he', hnext⟩ := Refinement.next_lt iter (by simpa [hend] using hk)
    obtain ⟨j, hsearch, hj⟩ := search_suffix v cs iter.start hk c htarget v.val [] rfl
      0#usize (by decide)
    simp only [UScalar.ofNatCore_val_eq, Nat.zero_add] at hj
    have hcap : prior.length + 1 ≤ Usize.max := by
      have := cs.property
      simp only [hcs, List.length_append, List.length_cons] at this
      omega
    have hvCap : v.val.length + 1 ≤ Usize.max := by omega
    have hiCap : indices.val.length + 1 ≤ Usize.max := by omega
    let pushed : alloc.vec.Vec Commitment := ⟨v.val ++ [c], by simpa using hvCap⟩
    let nextV := if j = alloc.vec.Vec.len v then pushed else v
    let nextIndices : alloc.vec.Vec Usize := ⟨indices.val ++ [j], by simpa using hiCap⟩
    have hpush : alloc.vec.Vec.push v c = ok pushed := by
      simp [alloc.vec.Vec.push, hvCap, pushed]
    have hpushIndices : alloc.vec.Vec.push indices j = ok nextIndices := by
      simp [alloc.vec.Vec.push, hiCap, nextIndices]
    have hunique : (if j = alloc.vec.Vec.len v then do
        let a ← Slice.index_usize cs iter.start
        alloc.vec.Vec.push v a
      else ok v) = ok nextV := by
      have hindex : Slice.index_usize cs iter.start = ok c := by
        simp [Slice.index_usize, hk, htarget]
      simp only [hindex, bind_tc_ok, hpush, nextV]
      split <;> rfl
    have hstep : dedupState nextV nextIndices =
        dedupStep (dedupState v indices) (arrayBytes c) := by
      rw [step_eq v indices c j hj]
      by_cases h : j = alloc.vec.Vec.len v <;>
        simp [nextV, h, pushed, nextIndices, dedupState]
    have hv' : nextV.val.length ≤ (prior ++ [c]).length := by
      dsimp only [nextV]
      split <;> simp [pushed] <;> omega
    have hindices' : nextIndices.val.length = (prior ++ [c]).length := by
      simp [nextIndices, hindices]
    obtain ⟨out, outIndices, hloop, hval⟩ := ih (prior ++ [c])
      (by simpa [List.append_assoc] using hcs) iter' (he'.trans hend)
      (by simp [hi', hi]) nextV nextIndices hv' hindices'
    refine ⟨out, outIndices, ?_, ?_⟩
    · have hbody : verify.Deduplicated.fill_loop0.body cs iter v indices =
          ok (cont (iter', nextV, nextIndices)) := by
        simp only [verify.Deduplicated.fill_loop0.body, hnext, bind_tc_ok,
          Function.uncurry_apply_pair, hsearch, hunique, hpushIndices]
      rw [verify.Deduplicated.fill_loop0, loop.eq_1]
      simp only [hbody]
      exact hloop
    · simpa only [List.map_cons, List.foldl_cons, hstep] using hval

theorem deduplicate_refinement (old : verify.Deduplicated) (cs : Slice Commitment) :
    ∃ result, verify.Deduplicated.fill old cs = ok result ∧
      ((result.unique.val.map arrayBytes).toArray,
        (result.index_of_cell.val.map (·.val)).toArray) =
        Model.deduplicate (cs.val.map arrayBytes).toArray := by
  let emptyV := alloc.vec.Vec.new Commitment
  let emptyIndices := alloc.vec.Vec.new Usize
  have hclone : core.array.CloneArray.clone core.clone.CloneU8
      (Array.repeat 48#usize 0#u8) = ok (Array.repeat 48#usize 0#u8) := by
    obtain ⟨a, ha, he⟩ := WP.spec_imp_exists (core.array.CloneArray.clone_spec
      core.clone.CloneU8 (Array.repeat 48#usize 0#u8) (by intro x hx; rfl))
    simpa only [← he] using ha
  have hclear : alloc.vec.Vec.resize (core.clone.CloneArray 48#usize core.clone.CloneU8)
      old.unique 0#usize (Array.repeat 48#usize 0#u8) = ok emptyV := by
    simp [alloc.vec.Vec.resize, List.resize, emptyV, alloc.vec.Vec.new, hclone]
  have hclearIndices : alloc.vec.Vec.resize core.clone.CloneUsize old.index_of_cell
      0#usize 0#usize = ok emptyIndices := by
    simp [alloc.vec.Vec.resize, List.resize, emptyIndices, alloc.vec.Vec.new]
  obtain ⟨out, outIndices, hloop, hval⟩ := fill_suffix cs cs.val [] rfl
    { start := 0#usize, «end» := Slice.len cs } rfl (by rfl) emptyV emptyIndices
    (by simp [emptyV]) (by simp [emptyIndices])
  refine ⟨⟨out, outIndices⟩, ?_, ?_⟩
  · unfold verify.Deduplicated.fill
    simp only [hclear, hclearIndices, bind_tc_ok, hloop, Function.uncurry_apply_pair]
  · change dedupState out outIndices = _
    rw [hval]
    simp only [Model.deduplicate, ← _root_.Array.foldl_toList]
    rfl

end LeanBlsSimd.Kzg
