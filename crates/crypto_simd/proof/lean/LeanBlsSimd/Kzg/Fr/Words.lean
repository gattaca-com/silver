import LeanBlsSimd.Refines.Word64
import LeanBlsSimd.Kzg.Representation

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.FrScalar

open Word64

def tail (a : Array U64 4#usize) (i : Nat) : ℤ := wordsValue (a.val.drop i)

theorem tail_step (a : Array U64 4#usize) (i : Nat) (hi : i < 4) :
    tail a i = (a.val[i]'(by rw [a.property]; exact hi)).val +
      (radix : ℤ) * tail a (i+1) := by
  unfold tail
  rw [List.drop_eq_getElem_cons (by rw [a.property]; exact hi)]
  rfl

theorem tail_four (a : Array U64 4#usize) : tail a 4 = 0 := by
  simp [tail, a.property, wordsValue]

theorem wordsValue_eq_limbs (xs : List U64) : wordsValue xs = (Kzg.limbs xs : ℤ) := by
  induction xs with
  | nil => rfl
  | cons x xs ih =>
    simp only [wordsValue, Kzg.limbs, List.foldr_cons, Nat.cast_add, Nat.cast_mul]
    rw [ih]
    rfl

theorem value_eq_limbs {n : Usize} (a : Array U64 n) : value a = (Kzg.limbs a.val : ℤ) :=
  wordsValue_eq_limbs a.val

theorem add_step (a b sum : Array U64 4#usize) (carry : U128) (j : Usize)
    (hj : j.val < 4) (hc : carry.val ≤ 1) :
    ∃ (s : U128) (next : Usize),
      s.val = (a.val[j.val]'(by rw [a.property]; exact hj)).val +
        (b.val[j.val]'(by rw [b.property]; exact hj)).val + carry.val ∧
      s.val < 2*radix ∧ next.val = j.val+1 ∧
      fr.add_words_loop.body a b sum carry j =
        ok (cont (sum.set j (UScalar.cast .U64 s), ⟨s.bv.ushiftRight 64⟩, next)) := by
  let x := a.val[j.val]'(by rw [a.property]; exact hj)
  let y := b.val[j.val]'(by rw [b.property]; exact hj)
  have hx := x.hBounds
  have hy := y.hBounds
  have hs : x.val + y.val + carry.val < 2*radix := by
    norm_num [UScalarTy.numBits, radix] at *
    omega
  have hs128 : x.val + y.val + carry.val < 2^128 := by
    norm_num [radix] at hs ⊢
    omega
  let s : U128 := UScalar.ofNatCore _ hs128
  let next : Usize := UScalar.ofNatCore (j.val+1)
    (lt_of_lt_of_le (by omega : j.val+1 < 2^32) two_pow_32_le_usize)
  refine ⟨s, next, rfl, hs, rfl, ?_⟩
  have hj' : j < 4#usize := hj
  simp only [fr.add_words_loop.body, hj', if_true]
  rw [index_usize_eq a j hj, index_usize_eq b j hj]
  simp only [lift, bind_tc_ok]
  rw [add_ok _ _ (by rw [cast128_val, cast128_val]; change x.val+y.val < 2^128; omega)]
  simp only [bind_tc_ok]
  rw [add_ok _ _ (by rw [UScalar.ofNatCore_val_eq]; exact hs128)]
  simp only [bind_tc_ok]
  change (do
    let out ← Array.update sum j (UScalar.cast .U64 s)
    let high ← s >>> 64#i32
    let next ← j + 1#usize
    ok (cont (out, high, next))) = _
  rw [update_eq sum j _ hj, shiftRight_64_i32]
  simp only [bind_tc_ok]
  rw [usize_add_ok j 1#usize (by change j.val+1 < 2^32; omega)]
  rfl

theorem add_loop_exact (a b sum : Array U64 4#usize) (carry : U128) (j : Usize)
    (hj : j.val ≤ 4) (hc : carry.val ≤ 1)
    (hz : ∀ i (hi : i < 4), j.val ≤ i → sum.val[i]'(by rw [sum.property]; exact hi) = 0#u64) :
    ∃ (out : Array U64 4#usize) (top : U128),
      fr.add_words_loop a b sum carry j = ok out ∧ top.val ≤ 1 ∧
      value out + (top.val : ℤ) * (radix : ℤ)^4 =
        value sum + (tail a j.val + tail b j.val + carry.val) * (radix : ℤ)^j.val := by
  induction hn : 4-j.val generalizing sum carry j with
  | zero =>
    have hj4 : j.val = 4 := by omega
    have hstop : ¬ j < 4#usize := by change ¬j.val < 4; omega
    refine ⟨sum, carry, ?_, hc, ?_⟩
    · rw [fr.add_words_loop, loop.eq_1]
      simp [fr.add_words_loop.body, hstop]
    · rw [hj4, tail_four, tail_four]
      ring
  | succ n ih =>
    have hjlt : j.val < 4 := by omega
    obtain ⟨s,next,hs,hsb,hnxt,hbody⟩ := add_step a b sum carry j hjlt hc
    let sum' := sum.set j (UScalar.cast .U64 s)
    let carry' : U128 := ⟨s.bv.ushiftRight 64⟩
    have hc' : carry'.val ≤ 1 := by
      rw [high_val]
      norm_num [radix] at hsb ⊢
      omega
    have hz' : ∀ i (hi : i < 4), next.val ≤ i →
        sum'.val[i]'(by rw [sum'.property]; exact hi) = 0#u64 := by
      intro i hi hji
      change (sum.val.set j.val (UScalar.cast .U64 s))[i]'_ = _
      rw [List.getElem_set_ne (by omega)]
      exact hz i hi (by omega)
    obtain ⟨out,top,hloop,htop,heq⟩ := ih sum' carry' next (by omega) hc' hz' (by omega)
    refine ⟨out,top,?_,htop,?_⟩
    · rw [fr.add_words_loop, loop.eq_1]
      simpa only [hbody] using hloop
    · rw [heq, value_set sum j _ hjlt, hz j.val hjlt (by omega), cast64_val]
      have hs' : (s.val : ℤ) =
          (a.val[j.val]'(by rw [a.property]; exact hjlt)).val +
          (b.val[j.val]'(by rw [b.property]; exact hjlt)).val + carry.val := by
        exact_mod_cast hs
      have hdiv : ((s.val % radix : Nat) : ℤ) + (radix : ℤ)*(s.val / radix : Nat) = s.val := by
        exact_mod_cast Nat.mod_add_div s.val radix
      simp only [show (0#u64).val = 0 from rfl, Nat.cast_zero, sub_zero,
        tail_step a j.val hjlt, tail_step b j.val hjlt, carry', high_val, hnxt, pow_succ]
      linear_combination (hdiv + hs') * (radix : ℤ)^j.val

theorem add_words_refines (a b : Array U64 4#usize) :
    ∃ out, fr.add_words a b = ok out ∧
      value out = (value a + value b) % (radix : ℤ)^4 := by
  obtain ⟨out,top,hr,ht,heq⟩ := add_loop_exact a b (Array.repeat 4#usize 0#u64)
    0#u128 0#usize (by decide) (by decide) (by
      intro i hi _
      change (List.replicate 4 0#u64)[i]'_ = _
      simp only [List.getElem_replicate])
  refine ⟨out, hr, ?_⟩
  have hb := value_bounds out
  change value out + (top.val : ℤ)*(radix : ℤ)^4 =
    0 + (value a + value b + 0)*(radix : ℤ)^0 at heq
  simp only [add_zero, zero_add, pow_zero, mul_one] at heq
  norm_num [radix] at hb heq ⊢
  omega

theorem radix_shift : 1#u128 <<< 64#i32 = ok 18446744073709551616#u128 := by
  rfl

theorem sub_step (a b difference : Array U64 4#usize) (borrow : U64) (j : Usize)
    (hj : j.val < 4) (hb : borrow.val ≤ 1) :
    ∃ (s : U128) (borrow' : U64) (next : Usize),
      (s.val : ℤ) = (radix : ℤ) +
        (a.val[j.val]'(by rw [a.property]; exact hj)).val -
        (b.val[j.val]'(by rw [b.property]; exact hj)).val - borrow.val ∧
      s.val < 2*radix ∧ borrow'.val + s.val / radix = 1 ∧ next.val = j.val+1 ∧
      fr.sub_words_loop.body a b difference borrow j =
        ok (cont (difference.set j (UScalar.cast .U64 s), borrow', next)) := by
  let x := a.val[j.val]'(by rw [a.property]; exact hj)
  let y := b.val[j.val]'(by rw [b.property]; exact hj)
  have hx := x.hBounds
  have hy := y.hBounds
  have hsafe : radix+x.val < 2^128 ∧ y.val ≤ radix+x.val ∧
      borrow.val ≤ radix+x.val-y.val ∧ radix+x.val-y.val-borrow.val < 2*radix := by
    norm_num [UScalarTy.numBits,radix] at *
    omega
  have hs128 : radix+x.val-y.val-borrow.val < 2^128 := by
    norm_num [radix] at hsafe ⊢
    omega
  let s : U128 := UScalar.ofNatCore _ hs128
  have hs : (s.val : ℤ) = (radix : ℤ)+x.val-y.val-borrow.val := by
    change ((radix+x.val-y.val-borrow.val : Nat) : ℤ) = _
    norm_num [radix] at hsafe ⊢
    omega
  have hsb : s.val < 2*radix := hsafe.2.2.2
  have hhigh : s.val / radix ≤ 1 := by
    norm_num [radix] at hsb ⊢
    omega
  let high : U64 := UScalar.cast .U64 (⟨s.bv.ushiftRight 64⟩ : U128)
  have hhighval : high.val = s.val / radix := by
    rw [cast64_val, high_val, Nat.mod_eq_of_lt]
    norm_num [radix]
    omega
  let borrow' : U64 := UScalar.ofNatCore (1-high.val) (by norm_num [UScalarTy.numBits]; omega)
  let next : Usize := UScalar.ofNatCore (j.val+1)
    (lt_of_lt_of_le (by omega : j.val+1 < 2^32) two_pow_32_le_usize)
  refine ⟨s,borrow',next,hs,hsb,?_,rfl,?_⟩
  · change 1-high.val+s.val/radix = 1
    rw [hhighval]
    omega
  · have hj' : j < 4#usize := hj
    simp only [fr.sub_words_loop.body, hj', if_true]
    rw [radix_shift]
    simp only [bind_tc_ok]
    rw [index_usize_eq a j hj, index_usize_eq b j hj]
    simp only [lift, bind_tc_ok]
    rw [add_ok _ _ (by rw [cast128_val]; exact hsafe.1)]
    simp only [bind_tc_ok]
    rw [sub_ok _ _ (by simp only [UScalar.ofNatCore_val_eq,cast128_val]; exact hsafe.2.1)]
    simp only [bind_tc_ok]
    rw [sub_ok _ _ (by simp only [UScalar.ofNatCore_val_eq,cast128_val]; exact hsafe.2.2.1)]
    simp only [bind_tc_ok]
    change (do
      let out ← Array.update difference j (UScalar.cast .U64 s)
      let high' ← s >>> 64#i32
      let borrow'' ← 1#u64 - UScalar.cast .U64 high'
      let next' ← j+1#usize
      ok (cont (out,borrow'',next'))) = _
    rw [update_eq difference j _ hj, shiftRight_64_i32]
    simp only [bind_tc_ok]
    rw [sub_ok 1#u64 high (by change high.val ≤ 1; omega)]
    simp only [bind_tc_ok]
    rw [usize_add_ok j 1#usize (by change j.val+1 < 2^32; omega)]
    rfl

theorem sub_loop_exact (a b difference : Array U64 4#usize) (borrow : U64) (j : Usize)
    (hj : j.val ≤ 4) (hb : borrow.val ≤ 1)
    (hz : ∀ i (hi : i < 4), j.val ≤ i → difference.val[i]'(by rw [difference.property]; exact hi) = 0#u64) :
    ∃ (out : Array U64 4#usize) (top : U64),
      fr.sub_words_loop a b difference borrow j = ok (out,top) ∧ top.val ≤ 1 ∧
      value out - (top.val : ℤ)*(radix : ℤ)^4 =
        value difference + (tail a j.val-tail b j.val-borrow.val)*(radix : ℤ)^j.val := by
  induction hn : 4-j.val generalizing difference borrow j with
  | zero =>
    have hj4 : j.val = 4 := by omega
    have hstop : ¬ j < 4#usize := by change ¬j.val < 4; omega
    refine ⟨difference,borrow,?_,hb,?_⟩
    · rw [fr.sub_words_loop,loop.eq_1]
      simp [fr.sub_words_loop.body,hstop]
    · rw [hj4,tail_four,tail_four]
      ring
  | succ n ih =>
    have hjlt : j.val < 4 := by omega
    obtain ⟨s,borrow',next,hs,hsb,hborrow,hnxt,hbody⟩ := sub_step a b difference borrow j hjlt hb
    let difference' := difference.set j (UScalar.cast .U64 s)
    have hz' : ∀ i (hi : i < 4), next.val ≤ i →
        difference'.val[i]'(by rw [difference'.property]; exact hi) = 0#u64 := by
      intro i hi hji
      change (difference.val.set j.val (UScalar.cast .U64 s))[i]'_ = _
      rw [List.getElem_set_ne (by omega)]
      exact hz i hi (by omega)
    have hb' : borrow'.val ≤ 1 := by
      calc
        borrow'.val ≤ borrow'.val + s.val / radix := Nat.le_add_right _ _
        _ = 1 := hborrow
    obtain ⟨out,top,hloop,htop,heq⟩ := ih difference' borrow' next (by omega) hb' hz' (by omega)
    refine ⟨out,top,?_,htop,?_⟩
    · rw [fr.sub_words_loop,loop.eq_1]
      simpa only [hbody] using hloop
    · rw [heq,value_set difference j _ hjlt,hz j.val hjlt (by omega),cast64_val]
      have hdiv : ((s.val % radix : Nat) : ℤ)+(radix : ℤ)*(s.val/radix : Nat) = s.val := by
        exact_mod_cast Nat.mod_add_div s.val radix
      have hborrow' : (borrow'.val : ℤ)+(s.val/radix : Nat) = 1 := by exact_mod_cast hborrow
      have hword : ((s.val % radix : Nat) : ℤ)-(borrow'.val : ℤ)*(radix : ℤ) =
          (a.val[j.val]'(by rw [a.property]; exact hjlt)).val-
          (b.val[j.val]'(by rw [b.property]; exact hjlt)).val-borrow.val := by
        linear_combination hdiv + hs - (radix : ℤ)*hborrow'
      simp only [show (0#u64).val = 0 from rfl,Nat.cast_zero,sub_zero,
        tail_step a j.val hjlt,tail_step b j.val hjlt,hnxt,pow_succ]
      linear_combination hword * (radix : ℤ)^j.val

theorem sub_words_refines (a b : Array U64 4#usize) :
    ∃ out, fr.sub_words a b = ok (out, decide (value a < value b)) ∧
      value out = (value a-value b) % (radix : ℤ)^4 := by
  obtain ⟨out,top,hr,ht,heq⟩ := sub_loop_exact a b (Array.repeat 4#usize 0#u64)
    0#u64 0#usize (by decide) (by decide) (by
      intro i hi _
      change (List.replicate 4 0#u64)[i]'_ = _
      simp only [List.getElem_replicate])
  change value out-(top.val : ℤ)*(radix : ℤ)^4 =
    0+(value a-value b-0)*(radix : ℤ)^0 at heq
  simp only [sub_zero,zero_add,pow_zero,mul_one] at heq
  have hout := value_bounds out
  have hborrow : (top = 1#u64) ↔ value a < value b := by
    constructor
    · intro h
      have hv := congrArg UScalar.val h
      norm_num [radix] at hout heq hv
      omega
    · intro h
      apply UScalar.eq_of_val_eq
      change top.val = 1
      norm_num [radix] at hout heq
      omega
  refine ⟨out,?_,?_⟩
  · simp only [fr.sub_words,hr,bind_tc_ok]
    change ok (out,decide (top = 1#u64)) = _
    simp only [hborrow]
  · norm_num [radix] at hout heq ⊢
    omega

end LeanBlsSimd.FrScalar
