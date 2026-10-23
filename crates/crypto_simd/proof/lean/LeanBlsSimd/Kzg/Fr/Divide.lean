import LeanBlsSimd.Kzg.Fr.MultiplyAdd

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.FrScalar
open Word64


theorem divide_step (low : Array U64 4#usize) (m : U64)
    (quotient : Array U64 4#usize) (carry : U128) (j : Usize)
    (hj0 : 1 ≤ j.val) (hj : j.val < 4) (hc : carry.val < radix) :
    ∃ (s : U128) (prev next : Usize),
      s.val = (low.val[j.val]'(by rw [low.property]; exact hj)).val +
        m.val * (fr.R.val[j.val]'(by rw [fr.R.property]; exact hj)).val + carry.val ∧
      prev.val = j.val-1 ∧ next.val = j.val+1 ∧
      fr.divide_out_word_loop.body low m quotient carry j =
        ok (cont (quotient.set prev (UScalar.cast .U64 s), ⟨s.bv.ushiftRight 64⟩, next)) := by
  let x := low.val[j.val]'(by rw [low.property]; exact hj)
  let y := fr.R.val[j.val]'(by rw [fr.R.property]; exact hj)
  have hmac := mac_bounds m y x carry hc
  have hs : x.val+m.val*y.val+carry.val < 2^128 := by omega
  let s : U128 := UScalar.ofNatCore _ hs
  let prev : Usize := UScalar.ofNatCore (j.val-1)
    (lt_of_lt_of_le (by omega : j.val-1 < 2^32) two_pow_32_le_usize)
  let next : Usize := UScalar.ofNatCore (j.val+1)
    (lt_of_lt_of_le (by omega : j.val+1 < 2^32) two_pow_32_le_usize)
  refine ⟨s,prev,next,rfl,rfl,rfl,?_⟩
  have hj' : j < 4#usize := hj
  simp only [fr.divide_out_word_loop.body,hj',if_true]
  rw [index_usize_eq low j hj,index_usize_eq fr.R j hj]
  simp only [lift,bind_tc_ok]
  rw [mul_ok _ _ (by rw [cast128_val,cast128_val]; change m.val*y.val < 2^128; omega)]
  simp only [bind_tc_ok]
  rw [add_ok _ _ (by simp only [UScalar.ofNatCore_val_eq,cast128_val]; change x.val+m.val*y.val < 2^128; omega)]
  simp only [bind_tc_ok]
  rw [add_ok _ _ (by simp only [UScalar.ofNatCore_val_eq]; exact hs)]
  simp only [bind_tc_ok]
  rw [sub_ok j 1#usize hj0]
  simp only [bind_tc_ok]
  change (do
    let out ← Array.update quotient prev (UScalar.cast .U64 s)
    let high ← s >>> 64#i32
    let next' ← j+1#usize
    ok (cont (out,high,next'))) = _
  rw [update_eq quotient prev _ (by change j.val-1 < 4; omega),shiftRight_64_i32]
  simp only [bind_tc_ok]
  rw [usize_add_ok j 1#usize (by change j.val+1 < 2^32; omega)]
  rfl

theorem divide_loop_exact (low : Array U64 4#usize) (m : U64)
    (quotient : Array U64 4#usize) (carry : U128) (j : Usize)
    (hj0 : 1 ≤ j.val) (hj : j.val ≤ 4) (hc : carry.val < radix)
    (hz : ∀ i (hi : i < 4), j.val-1 ≤ i → quotient.val[i]'(by rw [quotient.property]; exact hi) = 0#u64) :
    ∃ (out : Array U64 4#usize) (top : U128),
      fr.divide_out_word_loop low m quotient carry j = ok (out,top) ∧ top.val < radix ∧
      out.val[3]'(by rw [out.property]; decide) = 0#u64 ∧
      value out + (top.val : ℤ)*(radix : ℤ)^3 =
        value quotient+(tail low j.val+tail fr.R j.val*m.val+carry.val)*(radix : ℤ)^(j.val-1) := by
  induction hn : 4-j.val generalizing quotient carry j with
  | zero =>
    have hj4 : j.val = 4 := by omega
    have hstop : ¬ j < 4#usize := by change ¬j.val < 4; omega
    refine ⟨quotient,carry,?_,hc,hz 3 (by decide) (by omega),?_⟩
    · rw [fr.divide_out_word_loop,loop.eq_1]
      simp [fr.divide_out_word_loop.body,hstop]
    · rw [hj4,tail_four,tail_four]
      ring
  | succ n ih =>
    have hjlt : j.val < 4 := by omega
    obtain ⟨s,prev,next,hs,hprev,hnxt,hbody⟩ := divide_step low m quotient carry j hj0 hjlt hc
    let quotient' := quotient.set prev (UScalar.cast .U64 s)
    let carry' : U128 := ⟨s.bv.ushiftRight 64⟩
    have hz' : ∀ i (hi : i < 4), next.val-1 ≤ i →
        quotient'.val[i]'(by rw [quotient'.property]; exact hi) = 0#u64 := by
      intro i hi hji
      change (quotient.val.set prev.val (UScalar.cast .U64 s))[i]'_ = _
      rw [List.getElem_set_ne (by omega)]
      exact hz i hi (by omega)
    obtain ⟨out,top,hloop,htop,hzero,heq⟩ := ih quotient' carry' next (by omega)
      (by omega) (high_bound s) hz' (by omega)
    refine ⟨out,top,?_,htop,hzero,?_⟩
    · rw [fr.divide_out_word_loop,loop.eq_1]
      simpa only [hbody] using hloop
    · rw [heq,value_set quotient prev _ (by change prev.val < 4; omega),hz prev.val (by omega) (by omega),cast64_val]
      have hs' : (s.val : ℤ) =
          (low.val[j.val]'(by rw [low.property]; exact hjlt)).val+
          m.val*(fr.R.val[j.val]'(by rw [fr.R.property]; exact hjlt)).val+carry.val := by
        exact_mod_cast hs
      have hdiv : ((s.val % radix : Nat) : ℤ)+(radix : ℤ)*(s.val/radix : Nat) = s.val := by
        exact_mod_cast Nat.mod_add_div s.val radix
      have hp : (radix : ℤ)^j.val = (radix : ℤ)^(j.val-1)*(radix : ℤ) := by
        conv_lhs => rw [show j.val = (j.val-1)+1 by omega]
        rw [pow_succ]
      simp only [show (0#u64).val = 0 from rfl,Nat.cast_zero,sub_zero,
        tail_step low j.val hjlt,tail_step fr.R j.val hjlt,carry',high_val,hnxt,
        Nat.add_sub_cancel,hprev,hp]
      linear_combination (hdiv+hs')*(radix : ℤ)^(j.val-1)

theorem cancellation (x : U64) :
    ((x.val : ℤ)+(((x.val*fr.R_INV64.val)%radix : Nat) : ℤ)*
      (fr.R.val[0]'(by rw [fr.R.property]; decide)).val) % radix = 0 := by
  have h := Nat.mod_add_div (x.val*fr.R_INV64.val) radix
  norm_num [fr.R_INV64,fr.R,radix,Array.make] at h ⊢
  omega

theorem divide_run (low : Array U64 4#usize) (top : U64)
    (product v s : U128) (q : Array U64 4#usize) (c n : U128)
    (hp : (UScalar.cast .U128 (low.val[0]'(by rw [low.property]; decide))) *
      (UScalar.cast .U128 fr.R_INV64) = ok product)
    (hv : (UScalar.cast .U128 (UScalar.cast .U64 product)) *
      (UScalar.cast .U128 (fr.R.val[0]'(by rw [fr.R.property]; decide))) = ok v)
    (hs : (UScalar.cast .U128 (low.val[0]'(by rw [low.property]; decide)))+v = ok s)
    (hl : fr.divide_out_word_loop low (UScalar.cast .U64 product)
      (Array.repeat 4#usize 0#u64) ⟨s.bv.ushiftRight 64⟩ 1#usize = ok (q,c))
    (hn : (UScalar.cast .U128 top)+c = ok n) :
    fr.divide_out_word low top = ok (q.set 3#usize (UScalar.cast .U64 n)) := by
  simp only [fr.divide_out_word]
  rw [index_usize_eq low 0#usize (by decide),index_usize_eq fr.R 0#usize (by decide)]
  simp only [show (0#usize).val = 0 from rfl,lift,bind_tc_ok,hp,hv,hs,shiftRight_64_i32,hl]
  change (do
    let n' ← (UScalar.cast .U128 top)+c
    Array.update q 3#usize (UScalar.cast .U64 n')) = _
  rw [hn]
  simp only [bind_tc_ok]
  exact update_eq q 3#usize _ (by decide)

theorem divide_arithmetic (low : Array U64 4#usize) (top m : U64)
    (s c n : U128) (quotient : Array U64 4#usize)
    (hzero : quotient.val[3]'(by rw [quotient.property]; decide) = 0#u64)
    (hs' : (s.val : ℤ) = (low.val[0]'(by rw [low.property]; decide)).val+
      (m.val : ℤ)*(fr.R.val[0]'(by rw [fr.R.property]; decide)).val)
    (hcancel : s.val%radix = 0)
    (heq : value quotient+(c.val : ℤ)*(radix : ℤ)^3 =
      tail low 1+tail fr.R 1*m.val+(s.val/radix : Nat))
    (hnval : (n.val : ℤ) = top.val+(c.val : ℤ)) :
    value (quotient.set 3#usize (UScalar.cast .U64 n)) =
      ((value low+(top.val : ℤ)*(radix : ℤ)^4+value fr.R*m.val)/(radix : ℤ)) % (radix : ℤ)^4 ∧
    (value low+(top.val : ℤ)*(radix : ℤ)^4+value fr.R*m.val) % (radix : ℤ) = 0 := by
  let x := low.val[0]'(@id (0 < low.val.length) (by rw [low.property]; decide))
  let r0 := fr.R.val[0]'(by rw [fr.R.property]; decide)
  let out := quotient.set 3#usize (UScalar.cast .U64 n)
  constructor
  all_goals
    have hl := tail_step low 0 (by decide)
    have hr := tail_step fr.R 0 (by decide)
    change value low = (x.val : ℤ)+(radix : ℤ)*tail low 1 at hl
    change value fr.R = (r0.val : ℤ)+(radix : ℤ)*tail fr.R 1 at hr
    have hdiv : (radix : ℤ)*(s.val/radix : Nat) = s.val := by
      have h := Nat.mod_add_div s.val radix
      rw [hcancel,zero_add] at h
      exact_mod_cast h
    have hsplit : value low+(top.val : ℤ)*(radix : ℤ)^4+value fr.R*m.val =
        (value quotient+((c.val : ℤ)+top.val)*(radix : ℤ)^3)*(radix : ℤ) := by
      linear_combination hl+(m.val : ℤ)*hr-hs'-hdiv-(radix : ℤ)*heq
  · have hout : value out = value quotient+((n.val%radix : Nat) : ℤ)*(radix : ℤ)^3 := by
      rw [value_set quotient 3#usize _ (by decide)]
      simp only [show (3#usize).val = 3 from rfl,hzero,cast64_val]
      rfl
    have hndiv : ((n.val%radix : Nat) : ℤ)+(radix : ℤ)*(n.val/radix : Nat) = n.val := by
      exact_mod_cast Nat.mod_add_div n.val radix
    change value out = _
    have hb := value_bounds out
    norm_num [radix] at hsplit hout hndiv hb ⊢
    omega
  · rw [hsplit]
    exact Int.mul_emod_left _ _


theorem divide_initial (low : Array U64 4#usize) :
    ∃ product v s : U128,
      (UScalar.cast .U128 (low.val[0]'(by rw [low.property]; decide))) *
        (UScalar.cast .U128 fr.R_INV64) = ok product ∧
      (UScalar.cast .U128 (UScalar.cast .U64 product)) *
        (UScalar.cast .U128 (fr.R.val[0]'(by rw [fr.R.property]; decide))) = ok v ∧
      (UScalar.cast .U128 (low.val[0]'(by rw [low.property]; decide)))+v = ok s ∧
      (s.val : ℤ) = (low.val[0]'(by rw [low.property]; decide)).val+
        ((UScalar.cast .U64 product).val : ℤ)*(fr.R.val[0]'(by rw [fr.R.property]; decide)).val ∧
      s.val%radix = 0 := by
  let x := low.val[0]'(by rw [low.property]; decide)
  let r0 := fr.R.val[0]'(by rw [fr.R.property]; decide)
  obtain ⟨product,hproduct,hpval⟩ := multiply_wide x fr.R_INV64
  let m := UScalar.cast .U64 product
  have hm : m.val = (x.val*fr.R_INV64.val)%radix := by
    rw [cast64_val,hpval]
  obtain ⟨v,hv,hvval⟩ := multiply_wide m r0
  have hbound : (UScalar.cast .U128 x).val+v.val < 2^128 := by
    have h := mac_bounds m r0 x 0#u128 (by decide)
    change m.val*r0.val+x.val+0 < 2^128 at h
    rw [cast128_val,hvval]
    omega
  obtain ⟨s,hs,hsval⟩ := add_value (UScalar.cast .U128 x) v hbound
  have hs' : (s.val : ℤ) = x.val+(m.val : ℤ)*r0.val := by
    rw [hsval,cast128_val,hvval]
    push_cast
    rfl
  have hcancel : s.val%radix = 0 := by
    have h := cancellation x
    rw [← hm] at h
    change ((x.val : ℤ)+(m.val : ℤ)*r0.val)%radix = 0 at h
    rw [← hs'] at h
    exact_mod_cast h
  exact ⟨product,v,s,hproduct,hv,hs,hs',hcancel⟩

theorem divide_out_word_refines (low : Array U64 4#usize) (top : U64) :
    ∃ (out : Array U64 4#usize) (m : U64),
      fr.divide_out_word low top = ok out ∧
      value out = ((value low+(top.val : ℤ)*(radix : ℤ)^4+value fr.R*m.val) /
        (radix : ℤ)) % (radix : ℤ)^4 ∧
      (value low+(top.val : ℤ)*(radix : ℤ)^4+value fr.R*m.val) % (radix : ℤ) = 0 := by
  obtain ⟨product,v,s,hproduct,hv,hs,hs',hcancel⟩ := divide_initial low
  let m := UScalar.cast .U64 product
  let carry : U128 := ⟨s.bv.ushiftRight 64⟩
  obtain ⟨quotient,c,hloop,hc,hzero,heq⟩ := divide_loop_exact low m
    (Array.repeat 4#usize 0#u64) carry 1#usize (by decide) (by decide)
    (high_bound s) (by
      intro i hi _
      change (List.replicate 4 0#u64)[i]'_ = _
      simp only [List.getElem_replicate])
  have hn : top.val+c.val < 2^128 := by
    have ht := top.hBounds
    norm_num [UScalarTy.numBits,radix] at ht hc ⊢
    omega
  let n : U128 := UScalar.ofNatCore _ hn
  let out := quotient.set 3#usize (UScalar.cast .U64 n)
  refine ⟨out,m,?_,?_,?_⟩
  · exact divide_run low top product v s quotient c n hproduct hv hs hloop
      (add_ok _ _ (by simpa only [cast128_val] using hn))
  all_goals
    change value quotient+(c.val : ℤ)*(radix : ℤ)^3 =
      0+(tail low 1+tail fr.R 1*m.val+carry.val)*(radix : ℤ)^(1-1) at heq
    simp only [carry,high_val,Nat.sub_self,pow_zero,mul_one,zero_add] at heq
    have hnval : (n.val : ℤ) = top.val+(c.val : ℤ) := by
      change ((top.val+c.val : Nat) : ℤ) = _
      push_cast
      rfl
    have hmath := divide_arithmetic low top m s c n quotient hzero hs' hcancel heq hnval
  · exact hmath.1
  · exact hmath.2

end LeanBlsSimd.FrScalar
