import LeanBlsSimd.Portable.Fp.Words

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd

set_option maxRecDepth 4096
set_option maxHeartbeats 2000000

namespace LeanBlsSimd.Portable.Fp
open Word64

private theorem products_loop (a lo hi : Array U64 6#usize) (b : U64) (j : Usize)
    (hj : j.val ≤ 6)
    (hz : ∀ i (h : i < 6), j.val ≤ i →
      lo.val[i]'(by rw [lo.property]; exact h) = 0#u64 ∧
      hi.val[i]'(by rw [hi.property]; exact h) = 0#u64) :
    ∃ low high, portable.fp.mul_add_loop0 a b lo hi j = ok (low,high) ∧
      value low+(radix : ℤ)*value high = value lo+(radix : ℤ)*value hi+
        tail a j.val*b.val*(radix : ℤ)^j.val := by
  induction hn : 6-j.val generalizing lo hi j with
  | zero =>
    have hje : j.val = 6 := by omega
    have hstop : ¬j < 6#usize := by change ¬j.val < 6; omega
    refine ⟨lo,hi,?_,?_⟩
    · rw [portable.fp.mul_add_loop0,loop.eq_1]
      simp [portable.fp.mul_add_loop0.body,hstop]
    · have haend : tail a 6 = 0 := tail_end a
      rw [hje,haend]
      ring
  | succ n ih =>
    have hjlt : j.val < 6 := by omega
    let word := a.val[j.val]'(by rw [a.property]; exact hjlt)
    obtain ⟨l,h,hm,hv⟩ := wide_mul_refines word b
    let next : Usize := UScalar.ofNatCore (j.val+1)
      (lt_of_lt_of_le (by omega : j.val+1 < 2^32) two_pow_32_le_usize)
    have hnxt : next.val = j.val+1 := rfl
    have hz' : ∀ i (hi' : i < 6), next.val ≤ i →
        (lo.set j l).val[i]'(by rw [(lo.set j l).property]; exact hi') = 0#u64 ∧
        (hi.set j h).val[i]'(by rw [(hi.set j h).property]; exact hi') = 0#u64 := by
      intro i hi' hji
      change (lo.val.set j.val l)[i]'_ = _ ∧ (hi.val.set j.val h)[i]'_ = _
      rw [List.getElem_set_ne (by omega),List.getElem_set_ne (by omega)]
      exact hz i hi' (by omega)
    obtain ⟨low,high,he,heq⟩ := ih (lo.set j l) (hi.set j h) next (by omega) hz' (by omega)
    have hbody : portable.fp.mul_add_loop0.body a b lo hi j =
        ok (cont (lo.set j l,hi.set j h,next)) := by
      have hj' : j < 6#usize := hjlt
      simp only [portable.fp.mul_add_loop0.body,hj',if_true]
      rw [index_usize_eq a j hjlt]
      simp only [bind_tc_ok]
      change (do
        let (l,h) ← portable.fp.wide_mul word b
        let lo' ← Array.update lo j l
        let hi' ← Array.update hi j h
        let next ← j+1#usize
        ok (cont (lo',hi',next))) = _
      rw [hm]
      simp only [bind_tc_ok]
      rw [update_eq lo j l hjlt,update_eq hi j h hjlt,
        usize_add_ok j 1#usize (by change j.val+1 < 2^32; omega)]
      rfl
    refine ⟨low,high,?_,?_⟩
    · rw [portable.fp.mul_add_loop0,loop.eq_1]
      simpa only [hbody] using he
    · rw [heq,value_set lo j l hjlt,value_set hi j h hjlt,
        (hz j.val hjlt (by omega)).1,(hz j.val hjlt (by omega)).2]
      have hv' : (l.val : ℤ)+(radix : ℤ)*h.val = word.val*b.val := by exact_mod_cast hv
      simp only [show (0#u64).val = 0 from rfl,Nat.cast_zero,sub_zero,hnxt,
        tail_step a j.val hjlt,pow_succ]
      linear_combination hv'*(radix : ℤ)^j.val

private theorem low_loop (acc : Array U64 7#usize) (lo : Array U64 6#usize)
    (out : Array U64 7#usize) (carry : U64) (j : Usize)
    (hj : j.val ≤ 6) (hc : carry.val ≤ 1)
    (hz : ∀ i (hi : i < 7), j.val ≤ i → out.val[i]'(by rw [out.property]; exact hi) = 0#u64) :
    ∃ result top, portable.fp.mul_add_loop1 acc lo j out carry = ok (result,top) ∧ top.val ≤ 1 ∧
      result.val[6]'(by rw [result.property]; decide) = 0#u64 ∧
      value result+(top.val : ℤ)*(radix : ℤ)^6+tail acc 6*(radix : ℤ)^6 =
        value out+(tail acc j.val+tail lo j.val+carry.val)*(radix : ℤ)^j.val := by
  have hseven : (7#usize).val = 7 := rfl
  induction hn : 6-j.val generalizing out carry j with
  | zero =>
    have hje : j.val = 6 := by omega
    have hstop : ¬j < 6#usize := by change ¬j.val < 6; omega
    refine ⟨out,carry,?_,hc,hz 6 (by decide) (by omega),?_⟩
    · rw [portable.fp.mul_add_loop1,loop.eq_1]
      simp [portable.fp.mul_add_loop1.body,hstop]
    · have hle : tail lo 6 = 0 := tail_end lo
      rw [hje,hle]
      ring
  | succ n ih =>
    have hjlt : j.val < 6 := by omega
    let x := acc.val[j.val]'(by rw [acc.property]; omega)
    let y := lo.val[j.val]'(by rw [lo.property]; exact hjlt)
    obtain ⟨s,c,he,hc',hv⟩ := add_carry_refines x y carry hc
    let next : Usize := UScalar.ofNatCore (j.val+1)
      (lt_of_lt_of_le (by omega : j.val+1 < 2^32) two_pow_32_le_usize)
    have hnxt : next.val = j.val+1 := rfl
    have hz' : ∀ i (hi : i < 7), next.val ≤ i →
      (out.set j s).val[i]'(by rw [(out.set j s).property]; exact hi) = 0#u64 := by
      intro i hi hji
      change (out.val.set j.val s)[i]'_ = _
      rw [List.getElem_set_ne (by omega)]
      exact hz i hi (by omega)
    obtain ⟨result,top,hr,ht,hzero,heq⟩ := ih (out.set j s) c next (by omega) hc' hz' (by omega)
    have hbody : portable.fp.mul_add_loop1.body acc lo j out carry = ok (cont (next,out.set j s,c)) := by
      have hj' : j < 6#usize := hjlt
      simp only [portable.fp.mul_add_loop1.body,hj',if_true]
      rw [index_usize_eq acc j (by omega),index_usize_eq lo j hjlt]
      simp only [bind_tc_ok]
      change (do
        let (s,c) ← portable.fp.add_carry x y carry
        let out ← Array.update out j s
        let next ← j+1#usize
        ok (cont (next,out,c))) = _
      rw [he]
      simp only [bind_tc_ok]
      rw [update_eq out j s (by omega),usize_add_ok j 1#usize (by change j.val+1 < 2^32; omega)]
      rfl
    refine ⟨result,top,?_,ht,hzero,?_⟩
    · rw [portable.fp.mul_add_loop1,loop.eq_1]
      simpa only [hbody] using hr
    · rw [heq,value_set out j s (by omega),hz j.val (by omega) (by omega)]
      have hv' : (s.val : ℤ)+(radix : ℤ)*c.val = x.val+y.val+carry.val := by exact_mod_cast hv
      simp only [show (0#u64).val = 0 from rfl,Nat.cast_zero,sub_zero,hnxt,
        tail_step acc j.val (by omega),tail_step lo j.val hjlt,pow_succ]
      linear_combination hv'*(radix : ℤ)^j.val

private theorem high_loop (hi : Array U64 6#usize) (out : Array U64 7#usize)
    (carry : U64) (j : Usize) (hj : j.val ≤ 6) (hc : carry.val ≤ 1) :
    ∃ (result : Array U64 7#usize) (top : U64), portable.fp.mul_add_loop2 hi j out carry = ok result ∧ top.val ≤ 1 ∧
      value result+(top.val : ℤ)*(radix : ℤ)^7 =
        value out+(tail hi j.val+carry.val)*(radix : ℤ)^(j.val+1) := by
  have hseven : (7#usize).val = 7 := rfl
  induction hn : 6-j.val generalizing out carry j with
  | zero =>
    have hje : j.val = 6 := by omega
    have hstop : ¬j < 6#usize := by change ¬j.val < 6; omega
    refine ⟨out,carry,?_,hc,?_⟩
    · rw [portable.fp.mul_add_loop2,loop.eq_1]
      simp [portable.fp.mul_add_loop2.body,hstop]
    · have he : tail hi 6 = 0 := tail_end hi
      rw [hje,he]
      ring
  | succ n ih =>
    have hjlt : j.val < 6 := by omega
    let next : Usize := UScalar.ofNatCore (j.val+1)
      (lt_of_lt_of_le (by omega : j.val+1 < 2^32) two_pow_32_le_usize)
    have hnxt : next.val = j.val+1 := rfl
    let x := out.val[next.val]'(by rw [out.property]; omega)
    let y := hi.val[j.val]'(by rw [hi.property]; exact hjlt)
    obtain ⟨s,c,he,hc',hv⟩ := add_carry_refines x y carry hc
    obtain ⟨result,top,hr,ht,heq⟩ := ih (out.set next s) c next (by omega) hc' (by omega)
    have hbody : portable.fp.mul_add_loop2.body hi j out carry = ok (cont (next,out.set next s,c)) := by
      have hj' : j < 6#usize := hjlt
      simp only [portable.fp.mul_add_loop2.body,hj',if_true]
      rw [usize_add_ok j 1#usize (by change j.val+1 < 2^32; omega)]
      simp only [bind_tc_ok]
      change (do
        let x ← Array.index_usize out next
        let y ← Array.index_usize hi j
        let (s,c) ← portable.fp.add_carry x y carry
        let out ← Array.update out next s
        ok (cont (next,out,c))) = _
      rw [index_usize_eq out next (by omega),index_usize_eq hi j hjlt]
      simp only [bind_tc_ok]
      rw [he]
      simp only [bind_tc_ok]
      rw [update_eq out next s (by omega)]
      rfl
    refine ⟨result,top,?_,ht,?_⟩
    · rw [portable.fp.mul_add_loop2,loop.eq_1]
      simpa only [hbody] using hr
    · rw [heq,value_set out next s (by omega)]
      have hv' : (s.val : ℤ)+(radix : ℤ)*c.val = x.val+y.val+carry.val := by exact_mod_cast hv
      simp only [hnxt,tail_step hi j.val hjlt,pow_succ]
      dsimp only [x] at hv'
      simp only [hnxt] at hv'
      linear_combination hv'*(radix : ℤ)^j.val*(radix : ℤ)

theorem mul_add_refines (acc : Array U64 7#usize) (a : Array U64 6#usize) (b : U64) :
    ∃ out, portable.fp.mul_add acc a b = ok out ∧
      value out = (value acc+value a*b.val) % (radix : ℤ)^7 := by
  obtain ⟨lo,hi,hproducts,hp⟩ := products_loop a (Array.repeat 6#usize 0#u64)
    (Array.repeat 6#usize 0#u64) b 0#usize (by decide) (by
      intro i h _
      constructor <;> change (List.replicate 6 0#u64)[i]'_ = _ <;> simp only [List.getElem_replicate])
  change value lo+(radix : ℤ)*value hi = 0+(radix : ℤ)*0+value a*b.val*(radix : ℤ)^0 at hp
  simp only [mul_zero,add_zero,zero_add,pow_zero,mul_one] at hp
  obtain ⟨low,carry,hlow,hc,hzero,hl⟩ := low_loop acc lo (Array.repeat 7#usize 0#u64)
    0#u64 0#usize (by decide) (by decide) (by
      intro i h _
      change (List.replicate 7 0#u64)[i]'_ = _
      simp only [List.getElem_replicate])
  change value low+(carry.val : ℤ)*(radix : ℤ)^6+tail acc 6*(radix : ℤ)^6 =
    0+(value acc+value lo+0)*(radix : ℤ)^0 at hl
  simp only [add_zero,zero_add,pow_zero,mul_one] at hl
  let a6 := acc.val[6]'(by rw [acc.property]; decide)
  have hend : tail acc 7 = 0 := tail_end acc
  have htail : tail acc 6 = (a6.val : ℤ) := by
    rw [tail_step acc 6 (by decide),hend,mul_zero,add_zero]
  rw [htail] at hl
  let w := core.num.U64.wrapping_add a6 carry
  have hw : w.val = (a6.val+carry.val)%radix := by
    simpa only [UScalar.size,UScalarTy.numBits] using core.num.U64.wrapping_add_val_eq a6 carry
  obtain ⟨result,top,hhigh,ht,hh⟩ := high_loop hi (low.set 6#usize w) 0#u64 0#usize
    (by decide) (by decide)
  change value result+(top.val : ℤ)*(radix : ℤ)^7 = value (low.set 6#usize w)+
    (value hi+0)*(radix : ℤ)^(0+1) at hh
  simp only [add_zero,zero_add,pow_one] at hh
  have hdiv : (((a6.val+carry.val)%radix : Nat) : ℤ)+(radix : ℤ)*
      ((a6.val+carry.val)/radix : Nat) = a6.val+carry.val := by
    exact_mod_cast Nat.mod_add_div (a6.val+carry.val) radix
  have heq : value result+((top.val : ℤ)+((a6.val+carry.val)/radix : Nat))*(radix : ℤ)^7 =
      value acc+value a*b.val := by
    rw [value_set low 6#usize w (by decide)] at hh
    change value result+(top.val : ℤ)*(radix : ℤ)^7 =
      value low+((w.val : ℤ)-(low.val[6]'(by rw [low.property]; decide)).val)*(radix : ℤ)^6+
        value hi*(radix : ℤ) at hh
    rw [hzero,hw] at hh
    simp only [show (0#u64).val = 0 from rfl,Nat.cast_zero,sub_zero] at hh
    linear_combination hh+hl+hp+hdiv*(radix : ℤ)^6
  refine ⟨result,?_,?_⟩
  · simp only [portable.fp.mul_add,hproducts,bind_tc_ok]
    change (do
      let (out,c) ← portable.fp.mul_add_loop1 acc lo 0#usize (Array.repeat 7#usize 0#u64) 0#u64
      let a6 ← Array.index_usize acc 6#usize
      let word ← lift (core.num.U64.wrapping_add a6 c)
      let out' ← Array.update out 6#usize word
      portable.fp.mul_add_loop2 hi 0#usize out' 0#u64) = _
    rw [hlow]
    simp only [bind_tc_ok]
    rw [index_usize_eq acc 6#usize (by decide)]
    simp only [lift,bind_tc_ok]
    change (do let out' ← Array.update low 6#usize w; portable.fp.mul_add_loop2 hi 0#usize out' 0#u64) = _
    rw [update_eq low 6#usize w (by decide)]
    simpa only [bind_tc_ok] using hhigh
  · have hb : 0 ≤ value result ∧ value result < (radix : ℤ)^7 := value_bounds result
    have hm := congrArg (fun z : ℤ => z % (radix : ℤ)^7) heq
    dsimp only at hm
    rw [Int.add_mul_emod_self_right,Int.emod_eq_of_lt hb.1 hb.2] at hm
    exact hm

end LeanBlsSimd.Portable.Fp
