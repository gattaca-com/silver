import LeanBlsSimd.Kzg.Extender.Kernel.FftWide

open Aeneas Aeneas.Std Result ControlFlow
open EthCryptographySpecs Bls Kzg
open scoped EthCryptographySpecs.Bls.Fr
open silver_crypto_simd silver_crypto_simd.kzg
attribute [-instance] Lean.Grind.Fin.instHPowFinNatOfNeZero
attribute [-instance] Lean.Grind.Fin.instPowFinNatOfNeZero

namespace LeanBlsSimd.Kzg.Extender.Kernel

def TransposedRep (t : Aeneas.Std.Array fr8.Fr8 8#usize)
    (values : _root_.Array Fr) (offset : Nat) : Prop :=
  ∀ row : Fin 8, Represents t.val[row.val]!
    (fun lane => values[8 * (offset + lane.val) + row.val]!)

private def ShortPrefix (t : Aeneas.Std.Array fr8.Fr8 8#usize)
    (values output : _root_.Array Fr) (offset h group count : Nat) : Prop :=
  ∀ row : Fin 8, Represents t.val[row.val]!
    (fun lane =>
      if row.val < group + count ∨ group + h ≤ row.val ∧ row.val < group + h + count
      then output[8 * (offset + lane.val) + row.val]!
      else values[8 * (offset + lane.val) + row.val]!)

private theorem short_pair_values (dit : Bool) (values roots : _root_.Array Fr)
    (offset h group j : Nat) (hh : h = 1 ∨ h = 2 ∨ h = 4)
    (hj : j < h) (hg : group % (2*h) = 0) (hb : group + 2*h ≤ 8)
    (hsize : values.size = roots.size) (hbound : 8*(offset+8) ≤ values.size)
    (lane : Fin 8) :
    (butterflyStage dit values roots h)[8*(offset+lane.val)+group+j]! =
      (if dit then values[8*(offset+lane.val)+group+j]! +
          values[8*(offset+lane.val)+group+j+h]! * roots[j*(roots.size/(2*h))]!
       else values[8*(offset+lane.val)+group+j]! + values[8*(offset+lane.val)+group+j+h]!) ∧
    (butterflyStage dit values roots h)[8*(offset+lane.val)+group+j+h]! =
      (if dit then values[8*(offset+lane.val)+group+j]! -
          values[8*(offset+lane.val)+group+j+h]! * roots[j*(roots.size/(2*h))]!
       else (values[8*(offset+lane.val)+group+j]! - values[8*(offset+lane.val)+group+j+h]!) *
          roots[j*(roots.size/(2*h))]!) := by
  have hpos : 0 < h := by rcases hh with rfl | rfl | rfl <;> omega
  have hmod : (8*(offset+lane.val)+group) % (2*h) = 0 := by
    rcases hh with rfl | rfl | rfl <;> omega
  have hwithin : 8*(offset+lane.val)+group+2*h ≤ values.size := by
    have := lane.isLt
    omega
  simpa only [hsize] using
    butterfly_pair_get dit values roots h (8*(offset+lane.val)+group) j hpos hj hmod hwithin

private def shortPairRun (dit : Bool) (j : Usize) (a b w : fr8.Fr8) :
    Result (fr8.Fr8 × fr8.Fr8) :=
  if j = 0#usize then do
    let first ← fr8.Fr8.add a b
    let second ← fr8.Fr8.sub a b
    ok (first, second)
  else widePairRun dit a b w

private theorem short_pair_representation (dit : Bool) (j : Usize) (a b w : fr8.Fr8)
    (av bv factors : Fin 8 → Fr) (ha : Represents a av) (hb : Represents b bv)
    (hw : MultiplierRep w factors) (hunit : j = 0#usize → ∀ lane, factors lane = 1) :
    ∃ first second, shortPairRun dit j a b w = ok (first,second) ∧
      Represents first (fun lane => if dit then av lane+bv lane*factors lane else av lane+bv lane) ∧
      Represents second (fun lane => if dit then av lane-bv lane*factors lane else (av lane-bv lane)*factors lane) := by
  by_cases hj : j = 0#usize
  · obtain ⟨first,hf,hrf⟩ := add_representation a b av bv ha hb
    obtain ⟨second,hs,hrs⟩ := sub_representation a b av bv ha hb
    refine ⟨first,second,by simp [shortPairRun,hj,hf,hs],?_,?_⟩
    · simpa only [hunit hj,Fin.mul_one,ite_self] using hrf
    · simpa only [hunit hj,Fin.mul_one,ite_self] using hrs
  · simpa only [shortPairRun,hj,if_false] using
      wide_pair_representation dit a b w av bv factors ha hb hw

private theorem short_prefix_set (t : Aeneas.Std.Array fr8.Fr8 8#usize)
    (values output : _root_.Array Fr) (offset h group count : Nat) (i i1 : Usize)
    (hi : i.val = group+count) (hi1 : i1.val = group+count+h)
    (hh : 0 < h) (hj : count < h) (hg : group+2*h ≤ 8)
    (first second : fr8.Fr8)
    (hfirst : Represents first (fun lane => output[8*(offset+lane.val)+i.val]!))
    (hsecond : Represents second (fun lane => output[8*(offset+lane.val)+i1.val]!))
    (hp : ShortPrefix t values output offset h group count) :
    ShortPrefix ((t.set i first).set i1 second) values output offset h group (count+1) := by
  intro row
  have hib : i.val < t.val.length := by have := t.property; simp only [UScalar.ofNatCore_val_eq] at this; omega
  have hi1b : i1.val < t.val.length := by have := t.property; simp only [UScalar.ofNatCore_val_eq] at this; omega
  by_cases hv : row.val=i.val
  · have hdone : row.val < group+(count+1) ∨ group+h ≤ row.val ∧ row.val < group+h+(count+1) := by omega
    simp only [hdone,if_true,Array.set_val_eq]
    rw [hv,List.getElem!_set_ne _ i1.val i.val second (by omega),
      List.getElem!_set _ i.val first hib]
    exact hfirst
  · by_cases hv1 : row.val=i1.val
    · have hdone : row.val < group+(count+1) ∨ group+h ≤ row.val ∧ row.val < group+h+(count+1) := by omega
      simp only [hdone,if_true,Array.set_val_eq]
      rw [hv1,List.getElem!_set _ i1.val second (by simpa using hi1b)]
      exact hsecond
    · have he :
          (row.val < group+(count+1) ∨ group+h ≤ row.val ∧ row.val < group+h+(count+1)) =
          (row.val < group+count ∨ group+h ≤ row.val ∧ row.val < group+h+count) :=
        propext (by omega)
      simpa only [Array.set_val_eq,
        List.getElem!_set_ne (t.val.set i.val first) i1.val row.val second (by omega),
        List.getElem!_set_ne t.val i.val row.val first (by omega),he] using hp row

private theorem short_add (a b c : Usize) (hc : c.val = a.val+b.val) :
    a+b = ok c := by
  rw [scalar_add_ok a b (by rw [←hc]; exact c.hmax)]
  congr 1
  apply UScalar.eq_of_val_eq
  simpa using hc.symm

private theorem short_usize_bound : 8 < 2^UScalarTy.Usize.numBits := by scalar_tac

private def shortBody (dit : Bool) (h group : Usize)
    (table : fft8.Fft8) (t : Aeneas.Std.Array fr8.Fr8 8#usize) (j : Usize) :=
  if dit then fft8.Fft8.dit_short_loop0_loop0.body h group table t j
  else fft8.Fft8.dif_short_loop0_loop0.body h group table t j

private theorem short_body_pair (dit : Bool) (table : fft8.Fft8)
    (t : Aeneas.Std.Array fr8.Fr8 8#usize) (h group j i i1 wi j1 : Usize)
    (hj : j.val < h.val) (hi : i.val=group.val+j.val) (hi1 : i1.val=i.val+h.val)
    (hwi : wi.val=h.val-1+j.val) (hj1 : j1.val=j.val+1)
    (hdata : i1.val < 8) (hshort : wi.val < table.short.val.length) :
    shortBody dit h group table t j = (do
      let (first,second) ← shortPairRun dit j t.val[i.val]! t.val[i1.val]! table.short.val[wi.val]!
      ok (cont (table,(t.set i first).set i1 second,j1))) := by
  have hhalf : 0 < h.val := by omega
  have hi0 : i.val < t.val.length := by
    have := t.property
    simp only [UScalar.ofNatCore_val_eq] at this
    omega
  have hi1b : i1.val < t.val.length := by simpa only [t.property,UScalar.ofNatCore_val_eq] using hdata
  have hadd := short_add group j i hi
  have hadd1 := short_add i h i1 hi1
  have haddj := short_add j 1#usize j1 (by simpa using hj1)
  let prev : Usize := UScalar.ofNatCore (h.val-1) (Nat.lt_of_le_of_lt (Nat.sub_le _ _) h.hmax)
  have hprev : prev.val=h.val-1 := UScalar.ofNatCore_val_eq _
  have hsub : h-1#usize = ok prev := by
    obtain ⟨out,hout,hv⟩ := WP.spec_imp_exists
      (UScalar.sub_spec (x:=h) (y:=1#usize) (by simpa using hhalf))
    rw [hout]
    congr 1
    apply UScalar.eq_of_val_eq
    exact hv.1.trans (by simpa using hprev.symm)
  have haddw := short_add prev j wi (by simpa [hprev] using hwi)
  have ha : Array.index_usize t i = ok t.val[i.val]! := by
    simp [Array.index_usize,List.getElem?_eq_getElem hi0]
  have hb : Array.index_usize t i1 = ok t.val[i1.val]! := by
    simp [Array.index_usize,List.getElem?_eq_getElem hi1b]
  have hw : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice fr8.Fr8)
      table.short wi = ok table.short.val[wi.val]! := by
    simp [alloc.vec.Vec.index_usize,List.getElem?_eq_getElem hshort]
  have hu (x : fr8.Fr8) : Array.update t i x = ok (t.set i x) := by
    simp [Array.update,Aeneas.Std.Array.set,List.getElem?_eq_getElem hi0]
  have hu1 (x y : fr8.Fr8) : Array.update (t.set i x) i1 y = ok ((t.set i x).set i1 y) := by
    simp [Array.update,Aeneas.Std.Array.set,
      List.getElem?_eq_getElem (show i1.val < (t.val.set i.val x).length by simpa using hi1b)]
  cases dit <;>
    simp only [shortBody,Bool.false_eq_true,if_false,if_true,
      fft8.Fft8.dit_short_loop0_loop0.body,fft8.Fft8.dif_short_loop0_loop0.body,
      UScalar.lt_equiv,hj,hadd,hadd1,haddj,hsub,haddw,ha,hb,hw,hu,hu1,
      bind_tc_ok]
  all_goals by_cases hz : j = 0#usize <;>
    simp only [shortPairRun,widePairRun,hz,
      bind_tc_ok,bind_assoc_eq,Function.uncurry_apply_pair,Bool.false_eq_true,
      if_true,if_false]

private theorem short_inner_loop (dit : Bool) (table : fft8.Fft8)
    (roots values : _root_.Array Fr) (offset : Nat)
    (htable : FftInvariant table roots) (hsize : values.size=roots.size)
    (hbound : 8*(offset+8) ≤ values.size) (hunit : roots[0]! = 1)
    (h group : Usize) (hh : h.val=1 ∨ h.val=2 ∨ h.val=4)
    (hgmod : group.val%(2*h.val)=0) (hg : group.val+2*h.val ≤ 8)
    (remaining : Nat) :
    ∀ (t : Aeneas.Std.Array fr8.Fr8 8#usize) (j : Usize), h.val=j.val+remaining →
      ShortPrefix t values (butterflyStage dit values roots h.val) offset h.val group.val j.val →
      ∃ out, loop (fun (self,t,k) => shortBody dit h group self t k) (table,t,j) =
          ok (table,out) ∧
        ShortPrefix out values (butterflyStage dit values roots h.val) offset h.val group.val h.val := by
  have hpos : 0 < h.val := by rcases hh with hh | hh | hh <;> omega
  have hsmall : h.val ≤ 4 := by rcases hh with hh | hh | hh <;> omega
  induction remaining with
  | zero =>
    intro t j hj hp
    have he : j.val=h.val := by omega
    refine ⟨t,?_,by simpa only [he] using hp⟩
    rw [loop.eq_1]
    cases dit <;> simp [shortBody,fft8.Fft8.dit_short_loop0_loop0.body,
      fft8.Fft8.dif_short_loop0_loop0.body,UScalar.lt_equiv,he]
  | succ remaining ih =>
    intro t j hj hp
    have hjlt : j.val < h.val := by omega
    let i : Usize := UScalar.ofNatCore (group.val+j.val) (by scalar_tac)
    let i1 : Usize := UScalar.ofNatCore (group.val+j.val+h.val) (by scalar_tac)
    let wi : Usize := UScalar.ofNatCore (h.val-1+j.val) (by scalar_tac)
    let j1 : Usize := UScalar.ofNatCore (j.val+1) (by scalar_tac)
    have hi : i.val=group.val+j.val := UScalar.ofNatCore_val_eq _
    have hi1 : i1.val=group.val+j.val+h.val := UScalar.ofNatCore_val_eq _
    have hwi : wi.val=h.val-1+j.val := UScalar.ofNatCore_val_eq _
    have hj1 : j1.val=j.val+1 := UScalar.ofNatCore_val_eq _
    have hi0 : i.val < 8 := by omega
    have hi1b : i1.val < 8 := by omega
    have hwib : wi.val < table.short.val.length := by rw [htable.2.2.2.2.1]; omega
    have ha : Represents t.val[i.val]! (fun lane => values[8*(offset+lane.val)+i.val]!) := by
      have hf : ¬(i.val < group.val+j.val ∨ group.val+h.val ≤ i.val ∧ i.val < group.val+h.val+j.val) := by omega
      simpa only [hf,if_false] using hp ⟨i.val,hi0⟩
    have hb : Represents t.val[i1.val]! (fun lane => values[8*(offset+lane.val)+i1.val]!) := by
      have hf : ¬(i1.val < group.val+j.val ∨ group.val+h.val ≤ i1.val ∧ i1.val < group.val+h.val+j.val) := by omega
      simpa only [hf,if_false] using hp ⟨i1.val,hi1b⟩
    have hw : MultiplierRep table.short.val[wi.val]!
        (fun _ => roots[j.val*(roots.size/(2*h.val))]!) := by
      rw [hwi]
      exact htable.2.2.2.2.2 h.val hh ⟨j.val,hjlt⟩
    obtain ⟨first,second,hrun,hfirst,hsecond⟩ := short_pair_representation dit j _ _ _ _ _ _ ha hb hw
      (by intro hz lane; simp [hz,hunit])
    have hsem (lane : Fin 8) := short_pair_values dit values roots offset h.val group.val j.val
      hh hjlt hgmod hg hsize hbound lane
    have he0 : (fun (lane : Fin 8) => if dit then values[8*(offset+lane.val)+i.val]! +
        values[8*(offset+lane.val)+i1.val]!*roots[j.val*(roots.size/(2*h.val))]!
        else values[8*(offset+lane.val)+i.val]!+values[8*(offset+lane.val)+i1.val]!) =
        (fun (lane : Fin 8) => (butterflyStage dit values roots h.val)[8*(offset+lane.val)+i.val]!) := by
      funext lane
      simpa only [hi,hi1,Nat.add_assoc] using (hsem lane).1.symm
    have he1 : (fun (lane : Fin 8) => if dit then values[8*(offset+lane.val)+i.val]! -
        values[8*(offset+lane.val)+i1.val]!*roots[j.val*(roots.size/(2*h.val))]!
        else (values[8*(offset+lane.val)+i.val]!-values[8*(offset+lane.val)+i1.val]!)*
          roots[j.val*(roots.size/(2*h.val))]!) =
        (fun (lane : Fin 8) => (butterflyStage dit values roots h.val)[8*(offset+lane.val)+i1.val]!) := by
      funext lane
      simpa only [hi,hi1,Nat.add_assoc] using (hsem lane).2.symm
    rw [he0] at hfirst
    rw [he1] at hsecond
    let next := (t.set i first).set i1 second
    have hnext : ShortPrefix next values (butterflyStage dit values roots h.val)
        offset h.val group.val j1.val := by
      rw [hj1]
      exact short_prefix_set t values _ offset h.val group.val j.val i i1 hi hi1
        hpos hjlt hg first second hfirst hsecond hp
    obtain ⟨out,hout,ho⟩ := ih next j1 (by omega) hnext
    refine ⟨out,?_,ho⟩
    rw [loop.eq_1]
    dsimp only
    rw [short_body_pair dit table t h group j i i1 wi j1 hjlt hi (by omega) hwi hj1 hi1b hwib,hrun]
    exact hout

private def shortOuterBody (dit : Bool) (h : Usize) (table : fft8.Fft8)
    (t : Aeneas.Std.Array fr8.Fr8 8#usize) (group : Usize) :=
  if dit then fft8.Fft8.dit_short_loop0.body h table t group
  else fft8.Fft8.dif_short_loop0.body h table t group

private theorem short_outer_body (dit : Bool) (h : Usize) (table : fft8.Fft8)
    (t : Aeneas.Std.Array fr8.Fr8 8#usize) (group : Usize) :
    shortOuterBody dit h table t group =
      if group < fr8.LANES then do
        let (self,t1) ← loop
          (fun (s : fft8.Fft8 × Aeneas.Std.Array fr8.Fr8 8#usize × Usize) =>
            shortBody dit h group s.1 s.2.1 s.2.2) (table,t,0#usize)
        let step ← 2#usize * h
        let next ← group + step
        ok (cont (self,t1,next))
      else ok (done t) := by
  cases dit <;> rfl

private theorem short_outer_loop (dit : Bool) (table : fft8.Fft8)
    (roots values : _root_.Array Fr) (offset : Nat)
    (htable : FftInvariant table roots) (hsize : values.size=roots.size)
    (hbound : 8*(offset+8) ≤ values.size) (hunit : roots[0]! = 1)
    (h : Usize) (hh : h.val=1 ∨ h.val=2 ∨ h.val=4) (remaining : Nat) :
    ∀ (t : Aeneas.Std.Array fr8.Fr8 8#usize) (group : Usize),
      8 = group.val+2*h.val*remaining → group.val%(2*h.val)=0 →
      ShortPrefix t values (butterflyStage dit values roots h.val) offset h.val group.val 0 →
      ∃ out, loop (fun (self,t,g) => shortOuterBody dit h self t g) (table,t,group) = ok out ∧
        TransposedRep out (butterflyStage dit values roots h.val) offset := by
  have hpos : 0 < h.val := by rcases hh with hh | hh | hh <;> omega
  have hsmall : h.val ≤ 4 := by rcases hh with hh | hh | hh <;> omega
  induction remaining with
  | zero =>
    intro t group hn hg hp
    have he : group.val=8 := by omega
    refine ⟨t,?_,?_⟩
    · rw [loop.eq_1]
      dsimp only
      rw [short_outer_body,if_neg (by simp [UScalar.lt_equiv,fr8.LANES,he])]
    · intro row
      have hv := row.isLt
      simpa only [he,Nat.add_zero,hv,true_or,if_true] using hp row
  | succ remaining ih =>
    intro t group hn hg hp
    have hgroup : group.val < 8 := by nlinarith
    have hwithin : group.val+2*h.val ≤ 8 := by nlinarith
    obtain ⟨middle,hm,hmd⟩ := short_inner_loop dit table roots values offset htable hsize
      hbound hunit h group hh hg hwithin h.val t 0#usize (by simp) hp
    let step : Usize := UScalar.ofNatCore (2*h.val)
      (Nat.lt_of_le_of_lt (by omega) short_usize_bound)
    let next : Usize := UScalar.ofNatCore (group.val+2*h.val)
      (Nat.lt_of_le_of_lt hwithin short_usize_bound)
    have hs : step.val=2*h.val := UScalar.ofNatCore_val_eq _
    have hnext : next.val=group.val+2*h.val := UScalar.ofNatCore_val_eq _
    have hmstep : 2#usize * h = ok step := by
      rw [mul_ok _ _ (by change 2*h.val < _; rw [←hs]; exact step.hmax)]
      congr 1
    have hanext : group+step = ok next := short_add group step next (by omega)
    have hprefix : ShortPrefix middle values (butterflyStage dit values roots h.val)
        offset h.val next.val 0 := by
      intro row
      have he :
          (row.val < next.val+0 ∨ next.val+h.val ≤ row.val ∧ row.val < next.val+h.val+0) =
          (row.val < group.val+h.val ∨ group.val+h.val ≤ row.val ∧ row.val < group.val+h.val+h.val) :=
        propext (by omega)
      simpa only [he] using hmd row
    have hgnext : next.val%(2*h.val)=0 := by rw [hnext,Nat.add_mod,hg]; simp
    have hnnext : 8=next.val+2*h.val*remaining := by rw [hnext]; nlinarith
    obtain ⟨out,hout,ho⟩ := ih middle next hnnext hgnext hprefix
    refine ⟨out,?_,ho⟩
    rw [loop.eq_1]
    dsimp only
    rw [short_outer_body,if_pos (by simpa only [UScalar.lt_equiv,fr8.LANES] using hgroup),hm]
    simp only [bind_tc_ok,hmstep,hanext]
    exact hout

theorem short_refinement (dit : Bool) (table : fft8.Fft8)
    (t : Aeneas.Std.Array fr8.Fr8 8#usize) (values roots : _root_.Array Fr) (offset : Nat)
    (h : Usize) (hh : h.val=1 ∨ h.val=2 ∨ h.val=4)
    (htable : FftInvariant table roots) (hsize : values.size=roots.size)
    (hbound : 8*(offset+8) ≤ values.size) (hunit : roots[0]! = 1)
    (ht : TransposedRep t values offset) :
    ∃ out, (if dit then fft8.Fft8.dit_short table t h else fft8.Fft8.dif_short table t h) = ok out ∧
      TransposedRep out (butterflyStage dit values roots h.val) offset := by
  have hp : ShortPrefix t values (butterflyStage dit values roots h.val) offset h.val 0 0 := by
    intro row
    have hf : ¬ (row.val < 0+0 ∨ 0+h.val ≤ row.val ∧ row.val < 0+h.val+0) := by omega
    simpa only [hf,if_false] using ht row
  obtain ⟨out,hout,ho⟩ := short_outer_loop dit table roots values offset htable hsize hbound hunit h hh
    (8/(2*h.val)) t 0#usize
    (by rcases hh with hh | hh | hh <;> simp [hh]) (by simp) hp
  refine ⟨out,?_,ho⟩
  cases dit <;> exact hout

end LeanBlsSimd.Kzg.Extender.Kernel
