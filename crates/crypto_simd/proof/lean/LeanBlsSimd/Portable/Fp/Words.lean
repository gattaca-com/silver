import LeanBlsSimd.Refines.Word64
import LeanBlsSimd.Kzg.PortableFp

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd
open EthLib.Cryptography Bls

set_option maxRecDepth 4096
set_option maxHeartbeats 2000000

namespace LeanBlsSimd.Portable.Fp
open Word64

abbrev Rep := Kzg.PortableFpRep

def tail {n : Usize} (a : Array U64 n) (i : Nat) : ℤ := wordsValue (a.val.drop i)

theorem tail_step {n : Usize} (a : Array U64 n) (i : Nat) (hi : i < n.val) :
    tail a i = (a.val[i]'(by rw [a.property]; exact hi)).val +
      (radix : ℤ) * tail a (i+1) := by
  unfold tail
  rw [List.drop_eq_getElem_cons (by rw [a.property]; exact hi)]
  rfl

theorem tail_end {n : Usize} (a : Array U64 n) : tail a n.val = 0 := by
  simp [tail, a.property, wordsValue]

theorem wordsValue_eq_limbs (xs : List U64) : wordsValue xs = (Kzg.limbs xs : ℤ) := by
  induction xs with
  | nil => rfl
  | cons x xs ih =>
    simp only [wordsValue,Kzg.limbs,List.foldr_cons,Nat.cast_add,Nat.cast_mul]
    rw [ih]
    rfl

theorem value_eq_limbs {n : Usize} (a : Array U64 n) : value a = (Kzg.limbs a.val : ℤ) :=
  wordsValue_eq_limbs a.val

theorem modulus_words : value bls.constants.P_U64 = (Bls.Fp.modulus : ℤ) := by
  unfold bls.constants.P_U64
  rfl

theorem add_carry_refines (a b carry : U64) (hc : carry.val ≤ 1) :
    ∃ s c, portable.fp.add_carry a b carry = ok (s,c) ∧ c.val ≤ 1 ∧
      s.val + radix*c.val = a.val+b.val+carry.val := by
  have hc01 : carry = 0#u64 ∨ carry = 1#u64 := by
    have h : carry.val = 0 ∨ carry.val = 1 := by omega
    exact h.elim (fun h => Or.inl (UScalar.eq_of_val_eq h))
      (fun h => Or.inr (UScalar.eq_of_val_eq h))
  have ha := a.hBounds
  have hb := b.hBounds
  rcases hc01 with rfl | rfl <;>
    simp only [portable.fp.add_carry,lift,bind_tc_ok,
      core.core_arch.x86_64.adx._addcarry_u64,LeanBlsSimd._addcarry_u64] <;>
    refine ⟨_,_,rfl,?_,?_⟩ <;>
    dsimp only <;>
    rw [UScalar.cast_val_eq]
  all_goals
    simp only [UScalar.val,UInt8.toBitVec_ofNat',UInt64.toBitVec_ofNat']
  · change (a.val+b.val) / radix % 256 % radix ≤ 1
    norm_num [UScalarTy.numBits,radix] at ha hb ⊢
    omega
  · change (a.val+b.val) % radix + radix*((a.val+b.val)/radix%256%radix) = a.val+b.val+0
    norm_num [UScalarTy.numBits,radix] at ha hb ⊢
    omega
  · change (a.val+b.val+1) / radix % 256 % radix ≤ 1
    norm_num [UScalarTy.numBits,radix] at ha hb ⊢
    omega
  · change (a.val+b.val+1) % radix + radix*((a.val+b.val+1)/radix%256%radix) = a.val+b.val+1
    norm_num [UScalarTy.numBits,radix] at ha hb ⊢
    omega

theorem wide_mul_refines (a b : U64) :
    ∃ lo hi, portable.fp.wide_mul a b = ok (lo,hi) ∧
      lo.val+radix*hi.val = a.val*b.val := by
  obtain ⟨p,hp,hv⟩ := multiply_wide a b
  simp only [portable.fp.wide_mul,lift,bind_tc_ok,hp]
  rw [shiftRight_64_i32]
  simp only [bind_tc_ok]
  refine ⟨_,_,rfl,?_⟩
  have hhigh : p.val / radix < radix := by simpa only [high_val] using high_bound p
  rw [cast64_val,cast64_val,high_val,Nat.mod_eq_of_lt hhigh]
  rw [Nat.mod_add_div,hv]

theorem wordsValue_repeat_zero (n : Nat) : wordsValue (List.replicate n 0#u64) = 0 := by
  induction n with
  | zero => rfl
  | succ n ih => simp [List.replicate_succ,wordsValue,ih]

theorem sub_step {N : Usize} (a b d : Array U64 N) (carry : U64) (j : Usize)
    (hj : j.val < N.val) (hc : carry.val ≤ 1) :
    ∃ (s c : U64) (next : Usize), c.val ≤ 1 ∧ next.val = j.val+1 ∧
      (s.val : ℤ)+(radix : ℤ)*(c.val-1) =
        (a.val[j.val]'(by rw [a.property]; exact hj)).val-
        (b.val[j.val]'(by rw [b.property]; exact hj)).val+carry.val-1 ∧
      portable.fp.sub_words_loop.body a b d carry j = ok (cont (d.set j s,c,next)) := by
  let x := a.val[j.val]'(by rw [a.property]; exact hj)
  let y := b.val[j.val]'(by rw [b.property]; exact hj)
  obtain ⟨s,c,he,hc',hv⟩ := add_carry_refines x (~~~y) carry hc
  have hnext : j.val+1 < 2^UScalarTy.Usize.numBits := by
    have := N.hBounds
    omega
  let next : Usize := UScalar.ofNatCore _ hnext
  refine ⟨s,c,next,hc',rfl,?_,?_⟩
  · change (s.val : ℤ)+(radix : ℤ)*(c.val-1) = x.val-y.val+carry.val-1
    rw [complement_val] at hv
    have hy := y.hBounds
    have hv' : (s.val : ℤ)+(radix : ℤ)*c.val = x.val+(radix-1-y.val : Nat)+carry.val := by
      exact_mod_cast hv
    norm_num [UScalarTy.numBits,radix] at hy hv' ⊢
    omega
  · have hj' : j < N := hj
    simp only [portable.fp.sub_words_loop.body,hj',if_true]
    rw [index_usize_eq a j hj,index_usize_eq b j hj]
    simp only [lift,bind_tc_ok]
    change (do
      let (s,c) ← portable.fp.add_carry x (~~~y) carry
      let out ← Array.update d j s
      let next ← j+1#usize
      ok (cont (out,c,next))) = _
    rw [he]
    simp only [bind_tc_ok]
    rw [update_eq d j s hj,add_ok j 1#usize hnext]
    rfl

theorem sub_loop_exact {N : Usize} (a b d : Array U64 N) (carry : U64) (j : Usize)
    (hj : j.val ≤ N.val) (hc : carry.val ≤ 1)
    (hz : ∀ i (hi : i < N.val), j.val ≤ i → d.val[i]'(by rw [d.property]; exact hi) = 0#u64) :
    ∃ out top, portable.fp.sub_words_loop a b d carry j = ok (out,top) ∧ top.val ≤ 1 ∧
      value out+((top.val : ℤ)-1)*(radix : ℤ)^N.val =
        value d+(tail a j.val-tail b j.val+carry.val-1)*(radix : ℤ)^j.val := by
  induction hn : N.val-j.val generalizing d carry j with
  | zero =>
    have hje : j.val = N.val := by omega
    have hstop : ¬ j < N := by change ¬ j.val < N.val; omega
    refine ⟨d,carry,?_,hc,?_⟩
    · rw [portable.fp.sub_words_loop,loop.eq_1]
      simp [portable.fp.sub_words_loop.body,hstop]
    · rw [hje,tail_end,tail_end]
      ring
  | succ n ih =>
    have hjlt : j.val < N.val := by omega
    obtain ⟨s,c,next,hc',hnxt,hv,hbody⟩ := sub_step a b d carry j hjlt hc
    let d' := d.set j s
    have hz' : ∀ i (hi : i < N.val), next.val ≤ i → d'.val[i]'(by rw [d'.property]; exact hi) = 0#u64 := by
      intro i hi hji
      change (d.val.set j.val s)[i]'_ = _
      rw [List.getElem_set_ne (by omega)]
      exact hz i hi (by omega)
    obtain ⟨out,top,hloop,htop,heq⟩ := ih d' c next (by omega) hc' hz' (by omega)
    refine ⟨out,top,?_,htop,?_⟩
    · rw [portable.fp.sub_words_loop,loop.eq_1]
      simpa only [hbody] using hloop
    · rw [heq,value_set d j s hjlt,hz j.val hjlt (by omega)]
      simp only [show (0#u64).val = 0 from rfl,Nat.cast_zero,sub_zero,
        tail_step a j.val hjlt,tail_step b j.val hjlt,hnxt,pow_succ]
      linear_combination hv*(radix : ℤ)^j.val

theorem sub_words_refines {N : Usize} (a b : Array U64 N) :
    ∃ out, portable.fp.sub_words a b = ok (out,decide (value a < value b)) ∧
      value out = (value a-value b) % (radix : ℤ)^N.val := by
  obtain ⟨out,top,he,ht,hv⟩ := sub_loop_exact a b (Array.repeat N 0#u64) 1#u64 0#usize
    (by change 0 ≤ N.val; omega) (by decide) (by
      intro i hi _
      change (List.replicate N.val 0#u64)[i]'_ = _
      simp only [List.getElem_replicate])
  have hz : value (Array.repeat N 0#u64) = 0 := wordsValue_repeat_zero N.val
  change value out+((top.val : ℤ)-1)*(radix : ℤ)^N.val =
    value (Array.repeat N 0#u64)+(value a-value b+1-1)*(radix : ℤ)^0 at hv
  rw [hz] at hv
  simp only [pow_zero,mul_one,zero_add,add_sub_cancel_right] at hv
  have ho := value_bounds out
  have hp : (0 : ℤ) < (radix : ℤ)^N.val := by positivity
  have ht01 : top.val = 0 ∨ top.val = 1 := by omega
  have hborrow : (top = 0#u64) ↔ value a < value b := by
    constructor
    · intro h
      have := congrArg UScalar.val h
      norm_num at this
      rw [this] at hv
      simp only [Nat.cast_zero,zero_sub,neg_mul,one_mul] at hv
      omega
    · intro h
      apply UScalar.eq_of_val_eq
      change top.val = 0
      rcases ht01 with h0 | h1
      · exact h0
      · rw [h1] at hv
        simp only [Nat.cast_one,sub_self,zero_mul,add_zero] at hv
        omega
  refine ⟨out,?_,?_⟩
  · simp only [portable.fp.sub_words,he,bind_tc_ok]
    change ok (out,decide (top = 0#u64)) = _
    simp only [hborrow]
  · have hm := congrArg (fun z : ℤ => z % (radix : ℤ)^N.val) hv
    simp only [Int.add_emod,Int.mul_emod,Int.emod_self,mul_zero,Int.zero_emod,add_zero,Int.emod_emod] at hm
    rw [Int.emod_eq_of_lt ho.1 ho.2] at hm
    exact hm
theorem add_step (a b s : Array U64 6#usize) (carry : U64) (j : Usize)
    (hj : j.val < 6) (hc : carry.val ≤ 1) :
    ∃ (word c : U64) (next : Usize), c.val ≤ 1 ∧ next.val = j.val+1 ∧
      (word.val : ℤ)+(radix : ℤ)*c.val =
        (a.val[j.val]'(by rw [a.property]; exact hj)).val+
        (b.val[j.val]'(by rw [b.property]; exact hj)).val+carry.val ∧
      portable.fp.add_words_loop.body a b s carry j = ok (cont (s.set j word,c,next)) := by
  let x := a.val[j.val]'(by rw [a.property]; exact hj)
  let y := b.val[j.val]'(by rw [b.property]; exact hj)
  obtain ⟨word,c,he,hc',hv⟩ := add_carry_refines x y carry hc
  let next : Usize := UScalar.ofNatCore (j.val+1)
    (lt_of_lt_of_le (by omega : j.val+1 < 2^32) two_pow_32_le_usize)
  refine ⟨word,c,next,hc',rfl,by exact_mod_cast hv,?_⟩
  have hj' : j < 6#usize := hj
  simp only [portable.fp.add_words_loop.body,hj',if_true]
  rw [index_usize_eq a j hj,index_usize_eq b j hj]
  simp only [bind_tc_ok]
  change (do
    let (word,c) ← portable.fp.add_carry x y carry
    let out ← Array.update s j word
    let next ← j+1#usize
    ok (cont (out,c,next))) = _
  rw [he]
  simp only [bind_tc_ok]
  rw [update_eq s j word hj,usize_add_ok j 1#usize (by change j.val+1 < 2^32; omega)]
  rfl

theorem add_loop_exact (a b s : Array U64 6#usize) (carry : U64) (j : Usize)
    (hj : j.val ≤ 6) (hc : carry.val ≤ 1)
    (hz : ∀ i (hi : i < 6), j.val ≤ i → s.val[i]'(by rw [s.property]; exact hi) = 0#u64) :
    ∃ out top, portable.fp.add_words_loop a b s carry j = ok (out,top) ∧ top.val ≤ 1 ∧
      value out+(top.val : ℤ)*(radix : ℤ)^6 =
        value s+(tail a j.val+tail b j.val+carry.val)*(radix : ℤ)^j.val := by
  induction hn : 6-j.val generalizing s carry j with
  | zero =>
    have hje : j.val = 6 := by omega
    have hstop : ¬ j < 6#usize := by change ¬ j.val < 6; omega
    refine ⟨s,carry,?_,hc,?_⟩
    · rw [portable.fp.add_words_loop,loop.eq_1]
      simp [portable.fp.add_words_loop.body,hstop]
    · have haend : tail a 6 = 0 := tail_end a
      have hbend : tail b 6 = 0 := tail_end b
      rw [hje,haend,hbend]
      ring
  | succ n ih =>
    have hjlt : j.val < 6 := by omega
    obtain ⟨word,c,next,hc',hnxt,hv,hbody⟩ := add_step a b s carry j hjlt hc
    let s' := s.set j word
    have hz' : ∀ i (hi : i < 6), next.val ≤ i → s'.val[i]'(by rw [s'.property]; exact hi) = 0#u64 := by
      intro i hi hji
      change (s.val.set j.val word)[i]'_ = _
      rw [List.getElem_set_ne (by omega)]
      exact hz i hi (by omega)
    obtain ⟨out,top,hloop,htop,heq⟩ := ih s' c next (by omega) hc' hz' (by omega)
    refine ⟨out,top,?_,htop,?_⟩
    · rw [portable.fp.add_words_loop,loop.eq_1]
      simpa only [hbody] using hloop
    · rw [heq,value_set s j word hjlt,hz j.val hjlt (by omega)]
      simp only [show (0#u64).val = 0 from rfl,Nat.cast_zero,sub_zero,
        tail_step a j.val hjlt,tail_step b j.val hjlt,hnxt,pow_succ]
      linear_combination hv*(radix : ℤ)^j.val

theorem add_words_refines (a b : Array U64 6#usize) :
    ∃ out, portable.fp.add_words a b = ok (out,decide ((radix : ℤ)^6 ≤ value a+value b)) ∧
      value out = (value a+value b) % (radix : ℤ)^6 := by
  obtain ⟨out,top,he,ht,hv⟩ := add_loop_exact a b (Array.repeat 6#usize 0#u64) 0#u64 0#usize
    (by decide) (by decide) (by
      intro i hi _
      change (List.replicate 6 0#u64)[i]'_ = _
      simp only [List.getElem_replicate])
  change value out+(top.val : ℤ)*(radix : ℤ)^6 = 0+(value a+value b+0)*(radix : ℤ)^0 at hv
  simp only [pow_zero,mul_one,zero_add,add_zero] at hv
  have ho := value_bounds out
  have hcarry : (top = 1#u64) ↔ (radix : ℤ)^6 ≤ value a+value b := by
    constructor
    · intro h
      have hval := congrArg UScalar.val h
      norm_num [radix] at ho hv hval ⊢
      omega
    · intro h
      apply UScalar.eq_of_val_eq
      change top.val = 1
      norm_num [radix] at ho hv h
      omega
  refine ⟨out,?_,?_⟩
  · simp only [portable.fp.add_words,he,bind_tc_ok]
    change ok (out,decide (top = 1#u64)) = _
    simp only [hcarry]
  · norm_num [radix] at ho hv ⊢
    omega

end LeanBlsSimd.Portable.Fp
