import LeanBlsSimd.Kzg.Fr.Words

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.FrScalar
open Word64

theorem multiply_add_step (t a : Array U64 4#usize) (w : U64)
    (sum : Array U64 4#usize) (carry : U128) (j : Usize)
    (hj : j.val < 4) (hc : carry.val < radix) :
    ∃ (s : U128) (next : Usize),
      s.val = (t.val[j.val]'(by rw [t.property]; exact hj)).val +
        (a.val[j.val]'(by rw [a.property]; exact hj)).val * w.val + carry.val ∧
      next.val = j.val+1 ∧
      fr.multiply_add_loop.body t a w sum carry j =
        ok (cont (sum.set j (UScalar.cast .U64 s), ⟨s.bv.ushiftRight 64⟩, next)) := by
  let x := t.val[j.val]'(by rw [t.property]; exact hj)
  let y := a.val[j.val]'(by rw [a.property]; exact hj)
  have hmac := mac_bounds y w x carry hc
  have hs : x.val+y.val*w.val+carry.val < 2^128 := by omega
  let s : U128 := UScalar.ofNatCore _ hs
  let next : Usize := UScalar.ofNatCore (j.val+1)
    (lt_of_lt_of_le (by omega : j.val+1 < 2^32) two_pow_32_le_usize)
  refine ⟨s,next,rfl,rfl,?_⟩
  have hj' : j < 4#usize := hj
  simp only [fr.multiply_add_loop.body,hj',if_true]
  rw [index_usize_eq t j hj,index_usize_eq a j hj]
  simp only [lift,bind_tc_ok]
  rw [mul_ok _ _ (by rw [cast128_val,cast128_val]; change y.val*w.val < 2^128; omega)]
  simp only [bind_tc_ok]
  rw [add_ok _ _ (by simp only [UScalar.ofNatCore_val_eq,cast128_val]; change x.val+y.val*w.val < 2^128; omega)]
  simp only [bind_tc_ok]
  rw [add_ok _ _ (by simp only [UScalar.ofNatCore_val_eq]; exact hs)]
  simp only [bind_tc_ok]
  change (do
    let out ← Array.update sum j (UScalar.cast .U64 s)
    let high ← s >>> 64#i32
    let next' ← j+1#usize
    ok (cont (out,high,next'))) = _
  rw [update_eq sum j _ hj,shiftRight_64_i32]
  simp only [bind_tc_ok]
  rw [usize_add_ok j 1#usize (by change j.val+1 < 2^32; omega)]
  rfl

theorem multiply_add_loop_exact (t a : Array U64 4#usize) (w : U64)
    (sum : Array U64 4#usize) (carry : U128) (j : Usize)
    (hj : j.val ≤ 4) (hc : carry.val < radix)
    (hz : ∀ i (hi : i < 4), j.val ≤ i → sum.val[i]'(by rw [sum.property]; exact hi) = 0#u64) :
    ∃ (out : Array U64 4#usize) (top : U128),
      fr.multiply_add_loop t a w sum carry j = ok (out,top) ∧ top.val < radix ∧
      value out + (top.val : ℤ)*(radix : ℤ)^4 =
        value sum+(tail t j.val+tail a j.val*w.val+carry.val)*(radix : ℤ)^j.val := by
  induction hn : 4-j.val generalizing sum carry j with
  | zero =>
    have hj4 : j.val = 4 := by omega
    have hstop : ¬ j < 4#usize := by change ¬j.val < 4; omega
    refine ⟨sum,carry,?_,hc,?_⟩
    · rw [fr.multiply_add_loop,loop.eq_1]
      simp [fr.multiply_add_loop.body,hstop]
    · rw [hj4,tail_four,tail_four]
      ring
  | succ n ih =>
    have hjlt : j.val < 4 := by omega
    obtain ⟨s,next,hs,hnxt,hbody⟩ := multiply_add_step t a w sum carry j hjlt hc
    let sum' := sum.set j (UScalar.cast .U64 s)
    let carry' : U128 := ⟨s.bv.ushiftRight 64⟩
    have hz' : ∀ i (hi : i < 4), next.val ≤ i →
        sum'.val[i]'(by rw [sum'.property]; exact hi) = 0#u64 := by
      intro i hi hji
      change (sum.val.set j.val (UScalar.cast .U64 s))[i]'_ = _
      rw [List.getElem_set_ne (by omega)]
      exact hz i hi (by omega)
    obtain ⟨out,top,hloop,htop,heq⟩ := ih sum' carry' next (by omega) (high_bound s) hz' (by omega)
    refine ⟨out,top,?_,htop,?_⟩
    · rw [fr.multiply_add_loop,loop.eq_1]
      simpa only [hbody] using hloop
    · rw [heq,value_set sum j _ hjlt,hz j.val hjlt (by omega),cast64_val]
      have hs' : (s.val : ℤ) =
          (t.val[j.val]'(by rw [t.property]; exact hjlt)).val+
          (a.val[j.val]'(by rw [a.property]; exact hjlt)).val*w.val+carry.val := by
        exact_mod_cast hs
      have hdiv : ((s.val % radix : Nat) : ℤ)+(radix : ℤ)*(s.val/radix : Nat) = s.val := by
        exact_mod_cast Nat.mod_add_div s.val radix
      simp only [show (0#u64).val = 0 from rfl,Nat.cast_zero,sub_zero,
        tail_step t j.val hjlt,tail_step a j.val hjlt,carry',high_val,hnxt,pow_succ]
      linear_combination (hdiv+hs')*(radix : ℤ)^j.val

theorem multiply_add_refines (t a : Array U64 4#usize) (w : U64) :
    ∃ (out : Array U64 4#usize) (top : U64),
      fr.multiply_add t a w = ok (out,top) ∧
      value out+(top.val : ℤ)*(radix : ℤ)^4 = value t+value a*w.val := by
  obtain ⟨out,top,hr,ht,heq⟩ := multiply_add_loop_exact t a w (Array.repeat 4#usize 0#u64)
    0#u128 0#usize (by decide) (by decide) (by
      intro i hi _
      change (List.replicate 4 0#u64)[i]'_ = _
      simp only [List.getElem_replicate])
  refine ⟨out,UScalar.cast .U64 top,?_,?_⟩
  · simp only [fr.multiply_add,hr,bind_tc_ok]
    rfl
  · rw [cast64_val,Nat.mod_eq_of_lt ht]
    change value out+(top.val : ℤ)*(radix : ℤ)^4 =
      0+(value t+value a*w.val+0)*(radix : ℤ)^0 at heq
    simpa only [zero_add,add_zero,pow_zero,mul_one] using heq

end LeanBlsSimd.FrScalar
