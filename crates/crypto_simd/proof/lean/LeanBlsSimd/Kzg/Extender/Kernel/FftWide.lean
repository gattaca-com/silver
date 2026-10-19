import LeanBlsSimd.Kzg.Extender.Kernel.FftOperations
import LeanBlsSimd.Kzg.Extender.Kernel.FftMath
open Aeneas Aeneas.Std Result ControlFlow
open EthCryptographySpecs Bls Kzg
open scoped EthCryptographySpecs.Bls.Fr
open silver_crypto_simd silver_crypto_simd.kzg
attribute [-instance] Lean.Grind.Fin.instHPowFinNatOfNeZero
attribute [-instance] Lean.Grind.Fin.instPowFinNatOfNeZero
namespace LeanBlsSimd.Kzg.Extender.Kernel
set_option maxRecDepth 10000
set_option maxHeartbeats 4000000

theorem butterfly_pair_get (dit : Bool) (values roots : _root_.Array Fr)
    (h block j : Nat) (hh : 0 < h) (hj : j < h) (hblock : block % (2*h)=0)
    (hsize : block+2*h  ≤  values.size) :
    (butterflyStage dit values roots h)[block+j]! =
      (if dit then values[block+j]! + values[block+j+h]! * roots[j*(values.size/(2*h))]!
       else values[block+j]! + values[block+j+h]!) ∧
    (butterflyStage dit values roots h)[block+j+h]! =
      (if dit then values[block+j]! - values[block+j+h]! * roots[j*(values.size/(2*h))]!
       else (values[block+j]! - values[block+j+h]!) * roots[j*(values.size/(2*h))]!) := by
  have hblock' : block / (2*h) * (2*h) = block := Nat.div_mul_cancel (Nat.dvd_of_mod_eq_zero hblock)
  have hbmod : block % h = 0 := by
    have hd : h ∣ block := (dvd_mul_left h 2).trans (Nat.dvd_of_mod_eq_zero hblock)
    exact Nat.mod_eq_zero_of_dvd hd
  have hj2 : j  <  2*h := by omega
  have hjh2 : j+h  <  2*h := by omega
  have hi0 : block+j  <  values.size := by omega
  have hi1 : block+j+h  <  values.size := by omega
  have hmod0 : (block+j) % h = j := by simp [Nat.add_mod, hbmod, Nat.mod_eq_of_lt hj]
  have hmod1 : (block+j+h) % h = j := by simpa [Nat.add_mod] using hmod0
  have hmod20 : (block+j) % (2*h) = j := by simp [Nat.add_mod, hblock, Nat.mod_eq_of_lt hj2]
  have hmod21 : (block+j+h) % (2*h) = j+h := by
    rw [Nat.add_assoc]
    simp [Nat.add_mod, hblock, Nat.mod_eq_of_lt hjh2]
  have hdiv0 : (block+j)/(2*h) = block/(2*h) := by
    rw [Nat.add_div_of_dvd_right (Nat.dvd_of_mod_eq_zero hblock), Nat.div_eq_of_lt hj2, Nat.add_zero]
  have hdiv1 : (block+j+h)/(2*h) = block/(2*h) := by
    rw [Nat.add_assoc, Nat.add_div_of_dvd_right (Nat.dvd_of_mod_eq_zero hblock), Nat.div_eq_of_lt hjh2, Nat.add_zero]
  have he (i : Nat) (hi : i  <  values.size) :
      (butterflyStage dit values roots h)[i]! =
        (let a := values[i/(2*h)*(2*h)+i%h]!
         let b := values[i/(2*h)*(2*h)+i%h+h]!
         let w := roots[(i%h)*(values.size/(2*h))]!
         if dit then (if i%(2*h) < h then a+b*w else a-b*w)
         else (if i%(2*h) < h then a+b else (a-b)*w)) := by
    rw [getElem!_pos _ i (by simpa [butterflyStage] using hi)]
    simp only [butterflyStage, _root_.Array.getElem_ofFn]
  rw [he _ hi0, he _ hi1]
  simp [hmod0,hmod1,hmod20,hmod21,hdiv0,hdiv1,hblock',hj,show ¬j+h < h by omega]

theorem wide_pair_values (dit : Bool) (values roots : _root_.Array Fr)
    (half block j : Nat) (hh : 0 < half) (hj : j < half) (hb : block % (2*half)=0)
    (hn : block+2*half  ≤  values.size/8) (hn8 : values.size % 8 = 0)
    (hsize : values.size=roots.size) (lane : Fin 8) :
    (butterflyStage dit values roots (8*half))[8*(block+j)+lane.val]! =
      (if dit then values[8*(block+j)+lane.val]! +
          values[8*(block+j+half)+lane.val]! * roots[(8*j+lane.val)*(roots.size/(2*(8*half)))]!
       else values[8*(block+j)+lane.val]! + values[8*(block+j+half)+lane.val]!) ∧
    (butterflyStage dit values roots (8*half))[8*(block+j+half)+lane.val]! =
      (if dit then values[8*(block+j)+lane.val]! -
          values[8*(block+j+half)+lane.val]! * roots[(8*j+lane.val)*(roots.size/(2*(8*half)))]!
       else (values[8*(block+j)+lane.val]! - values[8*(block+j+half)+lane.val]!) *
          roots[(8*j+lane.val)*(roots.size/(2*(8*half)))]!) := by
  have hb' : (8*block) % (2*(8*half))=0 := by
    apply Nat.mod_eq_zero_of_dvd
    obtain ⟨q,hq⟩ := Nat.dvd_of_mod_eq_zero hb
    refine ⟨q, ?_⟩
    rw [hq]
    ring
  have hsz : 8*block+2*(8*half)  ≤  values.size := by
    have hmul := Nat.div_mul_cancel (Nat.dvd_of_mod_eq_zero hn8)
    omega
  have ht := butterfly_pair_get dit values roots (8*half) (8*block) (8*j+lane.val)
    (by omega) (by have := lane.isLt; omega) hb' hsz
  have h0 : 8*block+(8*j+lane.val) = 8*(block+j)+lane.val := by omega
  have h1 : 8*block+(8*j+lane.val)+8*half = 8*(block+j+half)+lane.val := by omega
  have h1' : 8*(block+j)+lane.val+8*half = 8*(block+j+half)+lane.val := by omega
  simpa only [h0,h1',hsize] using ht


private theorem small_add (a b c : Usize) (hc : c.val = a.val+b.val) : a+b = ok c := by
  have hbound : a.val+b.val  <  2^UScalarTy.Usize.numBits := by rw [←hc]; exact c.hmax
  rw [scalar_add_ok a b hbound]
  congr 1
  apply UScalar.eq_of_val_eq
  simpa using hc.symm

private theorem small_sub (a b c : Usize) (hc : c.val = a.val-b.val) (hle : b.val ≤ a.val) : a-b = ok c := by
  obtain ⟨out,hout,hv⟩ := WP.spec_imp_exists (UScalar.sub_spec (x:=a) (y:=b) hle)
  rw [hout]
  congr 1
  apply UScalar.eq_of_val_eq
  exact hv.1.trans hc.symm

private theorem wide_table_bounds (table : fft8.Fft8) (roots : _root_.Array Fr)
    (htable : FftInvariant table roots) :
    roots.size = 8*table.vectors.val ∧ table.vectors.val  ≤  512 ∧
      ∃ k : Nat, table.vectors.val = 2^k := by
  obtain ⟨k,hk4,hk12,hk⟩ := htable.1
  have hpow : roots.size = 8*2^(k-3) := by
    rw [hk]
    conv_lhs => rw [show k=(k-3)+3 by omega, Nat.pow_add]
    ring
  have hv : table.vectors.val = 2^(k-3) := by rw [htable.2.1,hpow]; simp
  refine ⟨by rw [hpow,hv], ?_, ⟨k-3,hv⟩⟩
  rw [hv]
  exact (show 2^(k-3) ≤ 2^9 from Nat.pow_le_pow_right (by decide) (by omega))

private theorem wide_multiplier (table : fft8.Fft8) (roots : _root_.Array Fr)
    (htable : FftInvariant table roots) (half stage j : Nat)
    (hhalf : half = 2^stage) (hbound : half < table.vectors.val) (hj : j < half) :
    MultiplierRep table.wide.val[half-1+j]!
      (fun lane => roots[(8*j+lane.val)*(roots.size/(2*(8*half)))]!) := by
  have hsz := (wide_table_bounds table roots htable).1
  have hp : 2^(stage+3) = 8*half := by rw [hhalf,Nat.pow_add]; ring
  have ht := htable.2.2.2.1 (stage+3) (by omega) (by rw [hp,hsz]; omega)
    ⟨j,by simpa only [hp,Nat.mul_div_cancel_left _ (by decide : 0 < 8)] using hj⟩
  simpa only [hp,Nat.mul_div_cancel_left _ (by decide : 0 < 8)] using ht

def widePairRun (dit : Bool) (a b w : fr8.Fr8) : Result (fr8.Fr8 × fr8.Fr8) :=
  if dit then do
    let t ← fr8.Fr8.mul b w
    let first ← fr8.Fr8.add a t
    let second ← fr8.Fr8.sub a t
    ok (first,second)
  else do
    let first ← fr8.Fr8.add a b
    let d ← fr8.Fr8.sub a b
    let second ← fr8.Fr8.mul d w
    ok (first,second)

theorem wide_pair_representation (dit : Bool) (a b w : fr8.Fr8)
    (av bv factors : Fin 8 → Fr) (ha : Represents a av) (hb : Represents b bv)
    (hw : MultiplierRep w factors) :
    ∃ first second, widePairRun dit a b w = ok (first,second) ∧
      Represents first (fun lane => if dit then av lane+bv lane*factors lane else av lane+bv lane) ∧
      Represents second (fun lane => if dit then av lane-bv lane*factors lane else (av lane-bv lane)*factors lane) := by
  cases dit with
  | true =>
    obtain ⟨t,ht,hrt⟩ := mul_multiplier_refinement b w bv factors hb hw
    obtain ⟨first,hf,hrf⟩ := add_representation a t av _ ha hrt
    obtain ⟨second,hs,hrs⟩ := sub_representation a t av _ ha hrt
    exact ⟨first,second,by simp [widePairRun,ht,hf,hs],hrf,hrs⟩
  | false =>
    obtain ⟨first,hf,hrf⟩ := add_representation a b av bv ha hb
    obtain ⟨d,hd,hrd⟩ := sub_representation a b av bv ha hb
    obtain ⟨second,hs,hrs⟩ := mul_multiplier_refinement d w _ factors hrd hw
    exact ⟨first,second,by simp [widePairRun,hf,hd,hs],hrf,hrs⟩

private def WidePrefix (data : Slice fr8.Fr8) (values output : _root_.Array Fr)
    (n half block count : Nat) : Prop :=
  data.val.length = n ∧ ∀ v : Fin n, Represents data.val[v.val]!
    (fun lane => if v.val  <  block+count ∨ block+half  ≤  v.val ∧ v.val  <  block+half+count
      then output[8*v.val+lane.val]! else values[8*v.val+lane.val]!)

private theorem wide_prefix_set (data : Slice fr8.Fr8) (values output : _root_.Array Fr)
    (n half block count : Nat) (i i1 : Usize) (hi : i.val=block+count)
    (hi1 : i1.val=block+count+half) (hh : 0 < half) (hj : count < half) (hb : block+2*half  ≤  n)
    (first second : fr8.Fr8)
    (hfirst : Represents first (fun lane => output[8*i.val+lane.val]!))
    (hsecond : Represents second (fun lane => output[8*i1.val+lane.val]!))
    (hprefix : WidePrefix data values output n half block count) :
    WidePrefix ((data.set i first).set i1 second) values output n half block (count+1) := by
  have hlen := hprefix.1
  refine ⟨by simpa [Slice.set,Slice.setAtNat] using hlen, ?_⟩
  intro v
  have hib : i.val < data.val.length := by omega
  have hi1b : i1.val < data.val.length := by omega
  by_cases hv : v.val=i.val
  · have hdone : v.val < block+(count+1) ∨ block+half ≤ v.val ∧ v.val < block+half+(count+1) := by omega
    simp only [hdone,if_true,Slice.set,Slice.setAtNat]
    rw [hv,List.getElem!_set_ne _ i1.val i.val second (by omega),List.getElem!_set _ i.val first hib]
    exact hfirst
  · by_cases hv1 : v.val=i1.val
    · have hdone : v.val < block+(count+1) ∨ block+half ≤ v.val ∧ v.val < block+half+(count+1) := by omega
      simp only [hdone,if_true,Slice.set,Slice.setAtNat]
      rw [hv1,List.getElem!_set _ i1.val second (by simpa using hi1b)]
      exact hsecond
    · have hiff :
        (v.val < block+(count+1) ∨ block+half ≤ v.val ∧ v.val < block+half+(count+1)) =
        (v.val < block+count ∨ block+half ≤ v.val ∧ v.val < block+half+count) := propext (by omega)
      simpa only [Slice.set,Slice.setAtNat,
        List.getElem!_set_ne (data.val.set i.val first) i1.val v.val second (by omega),
        List.getElem!_set_ne data.val i.val v.val first (by omega), hiff]
        using hprefix.2 v

def wideBody (dit : Bool) (wide : alloc.vec.Vec fr8.Fr8) (half block : Usize)
    (data : Slice fr8.Fr8) (j : Usize) : Result (ControlFlow (Slice fr8.Fr8 × Usize) (Slice fr8.Fr8)) :=
  if dit then fft8.Fft8.dit_wide_loop0_loop0.body wide half block data j
  else fft8.Fft8.dif_wide_loop0_loop0.body wide half block data j

private theorem wide_body_pair (dit : Bool) (wide : alloc.vec.Vec fr8.Fr8)
    (data : Slice fr8.Fr8) (half block j i i1 wi j1 : Usize)
    (hj : j.val < half.val) (hi : i.val=block.val+j.val) (hi1 : i1.val=i.val+half.val)
    (hwi : wi.val=half.val-1+j.val) (hj1 : j1.val=j.val+1)
    (hdata : i1.val < data.val.length) (hwide : wi.val < wide.val.length) :
    wideBody dit wide half block data j = (do
      let (first,second) ← widePairRun dit data.val[i.val]! data.val[i1.val]! wide.val[wi.val]!
      ok (cont ((data.set i first).set i1 second,j1))) := by
  have hhalf : 0 < half.val := by omega
  have hi0 : i.val < data.val.length := by omega
  have hadd := small_add block j i hi
  have hadd1 := small_add i half i1 hi1
  have haddj := small_add j 1#usize j1 (by simpa using hj1)
  let prev : Usize := UScalar.ofNatCore (half.val-1) (Nat.lt_of_le_of_lt (Nat.sub_le _ _) half.hmax)
  have hprev : prev.val=half.val-1 := UScalar.ofNatCore_val_eq _
  have hsub := small_sub half 1#usize prev (by simpa using hprev) (by simpa using hhalf)
  have haddw := small_add prev j wi (by simpa [hprev] using hwi)
  have ha : Slice.index_usize data i = ok data.val[i.val]! := by
    simp [Slice.index_usize,List.getElem?_eq_getElem hi0]
  have hb : Slice.index_usize data i1 = ok data.val[i1.val]! := by
    simp [Slice.index_usize,List.getElem?_eq_getElem hdata]
  have hw : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice fr8.Fr8) wide wi = ok wide.val[wi.val]! := by
    simp [alloc.vec.Vec.index_usize,List.getElem?_eq_getElem hwide]
  have hu (x : fr8.Fr8) : Slice.update data i x = ok (data.set i x) := by
    simp [Slice.update,Slice.set,Slice.setAtNat,List.getElem?_eq_getElem hi0]
  have hu1 (x y : fr8.Fr8) : Slice.update (data.set i x) i1 y = ok ((data.set i x).set i1 y) := by
    simp [Slice.update,Slice.set,Slice.setAtNat,
      List.getElem?_eq_getElem (show i1.val < (data.val.set i.val x).length by simpa using hdata)]
  cases dit <;> simp only [wideBody,Bool.false_eq_true,if_false,if_true,
    fft8.Fft8.dit_wide_loop0_loop0.body,fft8.Fft8.dif_wide_loop0_loop0.body,
    UScalar.lt_equiv,hj,hadd,hadd1,haddj,hsub,haddw,ha,hb,hw,hu,hu1,
    widePairRun,bind_tc_ok,bind_assoc_eq,Function.uncurry_apply_pair]

private theorem wide_inner_loop (dit : Bool) (table : fft8.Fft8) (roots values : _root_.Array Fr)
    (htable : FftInvariant table roots) (hsize : values.size=roots.size)
    (half block : Usize) (stage : Nat) (hhalf : half.val=2^stage)
    (hbound : half.val < table.vectors.val) (hbmod : block.val%(2*half.val)=0)
    (hb : block.val+2*half.val ≤ table.vectors.val) (remaining : Nat) :
    ∀ (data : Slice fr8.Fr8) (j : Usize), half.val=j.val+remaining →
      WidePrefix data values (butterflyStage dit values roots (8*half.val))
        table.vectors.val half.val block.val j.val →
      ∃ out, loop (fun (d,k) => wideBody dit table.wide half block d k) (data,j) = ok out ∧
        WidePrefix out values (butterflyStage dit values roots (8*half.val))
          table.vectors.val half.val block.val half.val := by
  have htb := wide_table_bounds table roots htable
  have hhp : 0 < half.val := by rw [hhalf]; positivity
  induction remaining with
  | zero =>
    intro data j hj hd
    have he : j.val=half.val := by omega
    refine ⟨data,?_,by simpa only [he] using hd⟩
    rw [loop.eq_1]
    cases dit <;> simp [wideBody,fft8.Fft8.dit_wide_loop0_loop0.body,
      fft8.Fft8.dif_wide_loop0_loop0.body,UScalar.lt_equiv,he]
  | succ remaining ih =>
    intro data j hj hd
    have hjlt : j.val < half.val := by omega
    have hlen := hd.1
    let i : Usize := UScalar.ofNatCore (block.val+j.val) (by scalar_tac)
    let i1 : Usize := UScalar.ofNatCore (block.val+j.val+half.val) (by scalar_tac)
    let wi : Usize := UScalar.ofNatCore (half.val-1+j.val) (by scalar_tac)
    let j1 : Usize := UScalar.ofNatCore (j.val+1) (by scalar_tac)
    have hi : i.val=block.val+j.val := UScalar.ofNatCore_val_eq _
    have hi1 : i1.val=block.val+j.val+half.val := UScalar.ofNatCore_val_eq _
    have hwi : wi.val=half.val-1+j.val := UScalar.ofNatCore_val_eq _
    have hj1 : j1.val=j.val+1 := UScalar.ofNatCore_val_eq _
    have hi0 : i.val < table.vectors.val := by omega
    have hi1b : i1.val < table.vectors.val := by omega
    have hwib : wi.val < table.wide.val.length := by rw [htable.2.2.1,←htable.2.1]; omega
    have ha : Represents data.val[i.val]! (fun lane => values[8*i.val+lane.val]!) := by
      have hf : ¬(i.val < block.val+j.val ∨ block.val+half.val ≤ i.val ∧ i.val < block.val+half.val+j.val) := by omega
      simpa only [hf,if_false] using hd.2 ⟨i.val,hi0⟩
    have ha1 : Represents data.val[i1.val]! (fun lane => values[8*i1.val+lane.val]!) := by
      have hf : ¬(i1.val < block.val+j.val ∨ block.val+half.val ≤ i1.val ∧ i1.val < block.val+half.val+j.val) := by omega
      simpa only [hf,if_false] using hd.2 ⟨i1.val,hi1b⟩
    have hw : MultiplierRep table.wide.val[wi.val]!
        (fun lane => roots[(8*j.val+lane.val)*(roots.size/(2*(8*half.val)))]!) := by
      rw [hwi]
      exact wide_multiplier table roots htable half.val stage j.val hhalf hbound hjlt
    obtain ⟨first,second,hrun,hfirst,hsecond⟩ := wide_pair_representation dit _ _ _ _ _ _ ha ha1 hw
    have hsem (lane : Fin 8) := wide_pair_values dit values roots half.val block.val j.val
      hhp hjlt hbmod (by rw [hsize,htb.1]; simpa using hb)
      (by rw [hsize,htb.1]; omega) hsize lane
    have he0 : (fun (lane : Fin 8) => if dit then values[8*i.val+lane.val]! +
        values[8*i1.val+lane.val]!*roots[(8*j.val+lane.val)*(roots.size/(2*(8*half.val)))]!
        else values[8*i.val+lane.val]!+values[8*i1.val+lane.val]!) =
        (fun (lane : Fin 8) => (butterflyStage dit values roots (8*half.val))[8*i.val+lane.val]!) := by
      funext lane
      simpa only [hi,hi1] using (hsem lane).1.symm
    have he1 : (fun (lane : Fin 8) => if dit then values[8*i.val+lane.val]! -
        values[8*i1.val+lane.val]!*roots[(8*j.val+lane.val)*(roots.size/(2*(8*half.val)))]!
        else (values[8*i.val+lane.val]!-values[8*i1.val+lane.val]!)*
          roots[(8*j.val+lane.val)*(roots.size/(2*(8*half.val)))]!) =
        (fun (lane : Fin 8) => (butterflyStage dit values roots (8*half.val))[8*i1.val+lane.val]!) := by
      funext lane
      simpa only [hi,hi1] using (hsem lane).2.symm
    rw [he0] at hfirst
    rw [he1] at hsecond
    let next := (data.set i first).set i1 second
    have hnext : WidePrefix next values (butterflyStage dit values roots (8*half.val))
        table.vectors.val half.val block.val j1.val := by
      rw [hj1]
      exact wide_prefix_set data values _ _ _ _ _ i i1 hi hi1 hhp hjlt hb first second hfirst hsecond hd
    obtain ⟨out,hout,ho⟩ := ih next j1 (by omega) hnext
    refine ⟨out,?_,ho⟩
    rw [loop.eq_1]
    dsimp only
    rw [wide_body_pair dit table.wide data half block j i i1 wi j1 hjlt hi
      (by omega) hwi hj1 (by omega) hwib,hrun]
    exact hout

def wideOuterBody (dit : Bool) (table : fft8.Fft8) (half : Usize)
    (data : Slice fr8.Fr8) (block : Usize) :
    Result (ControlFlow (Slice fr8.Fr8 × Usize) (Slice fr8.Fr8)) :=
  if dit then fft8.Fft8.dit_wide_loop0.body table half data block
  else fft8.Fft8.dif_wide_loop0.body table half data block

private theorem wide_outer_body (dit : Bool) (table : fft8.Fft8) (half : Usize)
    (data : Slice fr8.Fr8) (block : Usize) :
    wideOuterBody dit table half data block =
      if block  <  table.vectors then do
        let data1 ← loop (fun (d,k) => wideBody dit table.wide half block d k) (data,0#usize)
        let step ← 2#usize * half
        let next ← block + step
        ok (cont (data1,next))
      else ok (done data) := by
  cases dit <;> rfl

private theorem wide_outer_loop (dit : Bool) (table : fft8.Fft8) (roots values : _root_.Array Fr)
    (htable : FftInvariant table roots) (hsize : values.size=roots.size)
    (half : Usize) (stage : Nat) (hhalf : half.val=2^stage)
    (hbound : half.val < table.vectors.val) (remaining : Nat) :
    ∀ (data : Slice fr8.Fr8) (block : Usize),
      table.vectors.val = block.val + 2*half.val*remaining →
      block.val%(2*half.val)=0 →
      WidePrefix data values (butterflyStage dit values roots (8*half.val))
        table.vectors.val half.val block.val 0 →
      ∃ out, loop (fun (d,b) => wideOuterBody dit table half d b) (data,block) = ok out ∧
        DataRep out (butterflyStage dit values roots (8*half.val)) := by
  have htb := wide_table_bounds table roots htable
  have hhp : 0 < half.val := by rw [hhalf]; positivity
  induction remaining with
  | zero =>
    intro data block hn hb hd
    have he : block.val=table.vectors.val := by omega
    refine ⟨data, ?_, ?_⟩
    · rw [loop.eq_1]
      dsimp only
      rw [wide_outer_body, if_neg (by rw [UScalar.lt_equiv,he]; omega)]
    · refine ⟨?_, ?_⟩
      · rw [FftMath.size_stage, hsize, htb.1, hd.1]
      · intro v
        have hv : v.val < table.vectors.val := by simpa only [hd.1] using v.isLt
        have h := hd.2 ⟨v.val,hv⟩
        have hvd : v.val < data.val.length := v.isLt
        simpa only [he,Nat.add_zero,hv,true_or,if_true,getElem!_pos data.val v.val hvd] using h
  | succ remaining ih =>
    intro data block hn hb hd
    have hblock : block.val < table.vectors.val := by nlinarith
    have hwithin : block.val+2*half.val ≤ table.vectors.val := by nlinarith
    obtain ⟨middle,hm,hmd⟩ := wide_inner_loop dit table roots values htable hsize half block stage
      hhalf hbound hb hwithin half.val data 0#usize (by simp) hd
    let step : Usize := UScalar.ofNatCore (2*half.val) (by scalar_tac)
    let next : Usize := UScalar.ofNatCore (block.val+2*half.val) (by scalar_tac)
    have hs : step.val=2*half.val := UScalar.ofNatCore_val_eq _
    have hnext : next.val=block.val+2*half.val := UScalar.ofNatCore_val_eq _
    have hmstep : 2#usize * half = ok step := by
      rw [mul_ok _ _ (by change 2*half.val  <  _; rw [←hs]; exact step.hmax)]
      congr 1
    have hanext : block+step = ok next := small_add block step next (by omega)
    have hprefix : WidePrefix middle values (butterflyStage dit values roots (8*half.val))
        table.vectors.val half.val next.val 0 := by
      refine ⟨hmd.1, ?_⟩
      intro v
      have he : (v.val < next.val+0 ∨ next.val+half.val ≤ v.val ∧ v.val < next.val+half.val+0) =
          (v.val < block.val+half.val ∨ block.val+half.val ≤ v.val ∧ v.val < block.val+half.val+half.val) :=
        propext (by omega)
      simpa only [he] using hmd.2 v
    have hbnext : next.val%(2*half.val)=0 := by rw [hnext,Nat.add_mod,hb]; simp
    have hnnext : table.vectors.val=next.val+2*half.val*remaining := by rw [hnext]; nlinarith
    obtain ⟨out,hout,ho⟩ := ih middle next hnnext hbnext hprefix
    refine ⟨out, ?_, ho⟩
    rw [loop.eq_1]
    dsimp only
    rw [wide_outer_body, if_pos (by simpa only [UScalar.lt_equiv] using hblock), hm]
    simp only [bind_tc_ok,hmstep,hanext]
    exact hout

theorem wide_refinement (dit : Bool) (table : fft8.Fft8) (data : Slice fr8.Fr8) (half : Usize)
    (values roots : _root_.Array Fr) (htable : FftInvariant table roots)
    (hsize : values.size=roots.size) (hdata : DataRep data values)
    (hhalf : ∃ stage : Nat, half.val=2^stage) (hbound : half.val < table.vectors.val) :
    ∃ out, (if dit then fft8.Fft8.dit_wide table data half else fft8.Fft8.dif_wide table data half) = ok out ∧
      DataRep out (butterflyStage dit values roots (8*half.val)) := by
  obtain ⟨stage,hhalf⟩ := hhalf
  obtain ⟨hn,hnle,k,hk⟩ := wide_table_bounds table roots htable
  have hslt : stage < k := by
    have hp : 2^stage < 2^k := by rw [←hhalf,←hk]; exact hbound
    exact (Nat.pow_lt_pow_iff_right (by decide)).mp hp
  have hd : 2*half.val ∣ table.vectors.val := by
    rw [hhalf,hk,←pow_succ']
    exact Nat.pow_dvd_pow 2 (Nat.succ_le_of_lt hslt)
  have hlen : data.val.length=table.vectors.val := by
    have h := hdata.1
    rw [hsize,hn] at h
    omega
  have hprefix : WidePrefix data values (butterflyStage dit values roots (8*half.val))
      table.vectors.val half.val 0 0 := by
    refine ⟨hlen, ?_⟩
    intro v
    have hvd : v.val < data.val.length := by omega
    have hf : ¬(v.val < 0+0 ∨ 0+half.val ≤ v.val ∧ v.val < 0+half.val+0) := by omega
    simpa only [hf,if_false,getElem!_pos data.val v.val hvd] using hdata.2 ⟨v.val,hvd⟩
  obtain ⟨out,hout,ho⟩ := wide_outer_loop dit table roots values htable hsize half stage hhalf hbound
    (table.vectors.val/(2*half.val)) data 0#usize
    (by simpa [Nat.mul_comm] using (Nat.div_mul_cancel hd).symm) (by simp) hprefix
  refine ⟨out, ?_, ho⟩
  cases dit <;> exact hout

end LeanBlsSimd.Kzg.Extender.Kernel
