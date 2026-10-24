import LeanBlsSimd.Portable.Fp.Equality
import LeanBlsSimd.Portable.Fp.Correct

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Fp
open Word64
set_option maxRecDepth 4096
set_option maxHeartbeats 2000000

def halfWord (a b : U64) : U64 := ⟨(a.bv.ushiftRight 1) ||| (b.bv <<< 63)⟩

theorem half_word_run (a b : U64) :
    (do let low ← a >>> 1#i32; let high ← b <<< 63#i32; lift (low ||| high)) =
      ok (halfWord a b) := rfl

theorem half_word_value (a b : U64) :
    (halfWord a b).val = a.val/2+2^63*(b.val%2) := by
  change ((a.bv >>> (1 : Nat)) ||| (b.bv <<< (63 : Nat))).toNat = _
  rw [BitVec.toNat_or,BitVec.toNat_ushiftRight,BitVec.toNat_shiftLeft,
    Nat.shiftRight_eq_div_pow,Nat.shiftLeft_eq]
  change a.val/2 ||| b.val*2^63%2^64 = _
  have ha := a.hBounds
  have hlow : a.val/2 < 2^63 := by norm_num [UScalarTy.numBits] at ha ⊢; omega
  have hhigh : b.val*2^63%2^64 = 2^63*(b.val%2) := by omega
  rw [hhigh,Nat.or_comm,←Nat.two_pow_add_eq_or_of_lt hlow]
  omega

theorem half_word_equation (a b : U64) :
    2*(halfWord a b).val+a.val%2 = a.val+radix*(b.val%2) := by
  rw [half_word_value]
  norm_num [radix]
  omega

private theorem exists_words6 (a : portable.fp.Fp) :
    ∃ a0 a1 a2 a3 a4 a5 : U64, a = Array.make 6#usize [a0,a1,a2,a3,a4,a5] (by rfl) := by
  refine ⟨a.val[0]'(by rw [a.property]; decide),a.val[1]'(by rw [a.property]; decide),a.val[2]'(by rw [a.property]; decide),a.val[3]'(by rw [a.property]; decide),a.val[4]'(by rw [a.property]; decide),a.val[5]'(by rw [a.property]; decide),?_⟩
  apply Subtype.ext
  exact list_6 a

def halfWords (a : portable.fp.Fp) (top : U64) : portable.fp.Fp :=
  Array.make 6#usize [halfWord (a.val[0]'(by rw [a.property]; decide)) (a.val[1]'(by rw [a.property]; decide)),halfWord (a.val[1]'(by rw [a.property]; decide)) (a.val[2]'(by rw [a.property]; decide)),halfWord (a.val[2]'(by rw [a.property]; decide)) (a.val[3]'(by rw [a.property]; decide)),halfWord (a.val[3]'(by rw [a.property]; decide)) (a.val[4]'(by rw [a.property]; decide)),halfWord (a.val[4]'(by rw [a.property]; decide)) (a.val[5]'(by rw [a.property]; decide)),halfWord (a.val[5]'(by rw [a.property]; decide)) (top)] (by rfl)

private theorem shr_one (a : U64) : a >>> 1#i32 = ok ⟨a.bv.ushiftRight 1⟩ := rfl
private theorem shl_63 (a : U64) : a <<< 63#i32 = ok ⟨a.bv <<< 63⟩ := rfl

theorem halve_run (a : portable.fp.Fp) (top : U64) :
    portable.fp.halve a top = ok (halfWords a top) := by
  obtain ⟨a0,a1,a2,a3,a4,a5,rfl⟩ := exists_words6 a
  simp (disch := decide) only [portable.fp.halve,portable.fp.halve_loop,
    loop.eq_1,portable.fp.halve_loop.body,if_pos,if_neg,index_usize_eq,
    usize_add_ok,update_eq,shr_one,shl_63,lift,bind_tc_ok]
  rfl

theorem value_mod_two (a : portable.fp.Fp) :
    value a % (2 : ℤ) = (((a.val[0]'(by rw [a.property]; decide)).val % 2 : Nat) : ℤ) := by
  obtain ⟨a0,a1,a2,a3,a4,a5,rfl⟩ := exists_words6 a
  norm_num [value,wordsValue,Array.make,radix,Int.add_emod,Int.mul_emod]

theorem halfWords_equation (a : portable.fp.Fp) (top : U64) (ht : top.val ≤ 1) :
    2*value (halfWords a top)+value a%2 = value a+top.val*(radix : ℤ)^6 := by
  obtain ⟨a0,a1,a2,a3,a4,a5,rfl⟩ := exists_words6 a
  have htmod : top.val%2 = top.val := Nat.mod_eq_of_lt (by omega)
  have h0 : (2 : ℤ)*(halfWord a0 a1).val+(a0.val%2 : Nat) = a0.val+(radix : ℤ)*(a1.val%2 : Nat) := by exact_mod_cast half_word_equation a0 a1
  have h1 : (2 : ℤ)*(halfWord a1 a2).val+(a1.val%2 : Nat) = a1.val+(radix : ℤ)*(a2.val%2 : Nat) := by exact_mod_cast half_word_equation a1 a2
  have h2 : (2 : ℤ)*(halfWord a2 a3).val+(a2.val%2 : Nat) = a2.val+(radix : ℤ)*(a3.val%2 : Nat) := by exact_mod_cast half_word_equation a2 a3
  have h3 : (2 : ℤ)*(halfWord a3 a4).val+(a3.val%2 : Nat) = a3.val+(radix : ℤ)*(a4.val%2 : Nat) := by exact_mod_cast half_word_equation a3 a4
  have h4 : (2 : ℤ)*(halfWord a4 a5).val+(a4.val%2 : Nat) = a4.val+(radix : ℤ)*(a5.val%2 : Nat) := by exact_mod_cast half_word_equation a4 a5
  have h5 : (2 : ℤ)*(halfWord a5 top).val+(a5.val%2 : Nat) = a5.val+(radix : ℤ)*(top.val%2 : Nat) := by exact_mod_cast half_word_equation a5 top
  rw [htmod] at h5
  rw [value_mod_two]
  simp only [halfWords,value,Array.make,wordsValue]
  norm_num only [List.getElem_cons_zero,List.getElem_cons_succ,Nat.cast_zero]
  linear_combination h0*(radix : ℤ)^0+h1*(radix : ℤ)^1+h2*(radix : ℤ)^2+h3*(radix : ℤ)^3+h4*(radix : ℤ)^4+h5*(radix : ℤ)^5

theorem halve_refines (a : portable.fp.Fp) (top : U64) (ht : top.val ≤ 1) :
    ∃ out, portable.fp.halve a top = ok out ∧
      2*value out+value a%2 = value a+top.val*(radix : ℤ)^6 :=
  ⟨halfWords a top,halve_run a top,halfWords_equation a top ht⟩

private theorem word_eq_value (a b : U64) : a = b ↔ a.val = b.val :=
  ⟨congrArg UScalar.val,fun h => UScalar.eq_of_val_eq h⟩

theorem is_even_refines (a : portable.fp.Fp) :
    portable.fp.is_even a = ok (decide (value a % (2 : ℤ) = 0)) := by
  let lo := a.val[0]'(by rw [a.property]; decide)
  have hand : (lo &&& 1#u64).val = lo.val%2 := by
    change (lo.bv &&& (1 : BitVec 64)).toNat = _
    rw [BitVec.toNat_and]
    exact Nat.and_two_pow_sub_one_eq_mod lo.val 1
  have heven : (lo &&& 1#u64) = 0#u64 ↔ value a % (2 : ℤ) = 0 := by
    rw [word_eq_value,hand,value_mod_two]
    change lo.val%2 = 0 ↔ ((lo.val%2 : Nat) : ℤ) = 0
    omega
  simp (disch := decide) only [portable.fp.is_even,index_usize_eq,bind_tc_ok,lift]
  change ok (decide ((lo &&& 1#u64) = 0#u64)) = _
  simp only [heven]

theorem is_one_refines (a : portable.fp.Fp) :
    portable.fp.is_one a = ok (decide (value a = 1)) := by
  obtain ⟨a0,a1,a2,a3,a4,a5,rfl⟩ := exists_words6 a
  have hh : ((((a1 ||| a2) ||| a3) ||| a4) ||| a5) = 0#u64 ↔
      a1 = 0#u64 ∧ a2 = 0#u64 ∧ a3 = 0#u64 ∧ a4 = 0#u64 ∧ a5 = 0#u64 := by
    have hor (x y : U64) : (x ||| y) = 0#u64 ↔ x = 0#u64 ∧ y = 0#u64 := by
      rw [UScalar.eq_equiv_bv_eq (x ||| y) 0#u64,UScalar.eq_equiv_bv_eq x 0#u64,
        UScalar.eq_equiv_bv_eq y 0#u64]
      exact BitVec.or_eq_zero_iff
    simp only [hor,and_assoc]
  have hv : value (Array.make 6#usize [a0,a1,a2,a3,a4,a5] (by rfl)) = 1 ↔
      a0 = 1#u64 ∧ a1 = 0#u64 ∧ a2 = 0#u64 ∧ a3 = 0#u64 ∧ a4 = 0#u64 ∧ a5 = 0#u64 := by
    simp only [word_eq_value]
    norm_num [value,wordsValue,Array.make,radix]
    omega
  simp only [hv]
  simp (disch := decide) only [portable.fp.is_one,index_usize_eq,bind_tc_ok,lift]
  change (if a0 = 1#u64 then ok (decide (((((a1 ||| a2) ||| a3) ||| a4) ||| a5) = 0#u64))
    else ok false) = _
  simp only [hh]
  by_cases h0 : a0 = 1#u64 <;> simp [h0]

theorem geq_refines (a b : portable.fp.Fp) :
    portable.fp.geq a b = ok (decide (value b ≤ value a)) := by
  obtain ⟨out,he,hv⟩ := sub_words_refines a b
  by_cases h : value a < value b
  · have hnot : ¬value b ≤ value a := by omega
    simp [portable.fp.geq,he,h,hnot]
  · have hle : value b ≤ value a := by omega
    simp [portable.fp.geq,he,h,hle]

theorem zero_eq_refines (a : portable.fp.Fp) :
    core.array.equality.PartialEqArray.eq core.cmp.PartialEqU64 a
      (Array.repeat 6#usize 0#u64) = ok (decide (value a = 0)) := by
  have hz : value (Array.repeat 6#usize 0#u64) = 0 := wordsValue_repeat_zero 6
  have he : a.val = (Array.repeat 6#usize 0#u64).val ↔ value a = 0 := by
    constructor
    · intro h
      change wordsValue a.val = 0
      rw [h]
      exact hz
    · intro h
      have ha := value_injective a (Array.repeat 6#usize 0#u64) (h.trans hz.symm)
      exact congrArg Subtype.val ha
  simp only [array_eq_refines,he]

theorem halve_mod_p_refines (x : portable.fp.Fp) (hx : value x < Bls.Fp.modulus) :
    ∃ out, portable.fp.halve_mod_p x = ok out ∧ value out < Bls.Fp.modulus ∧
      2*value out = value x + if value x % (2 : ℤ) = 0 then 0 else (Bls.Fp.modulus : ℤ) := by
  have hx0 := (value_bounds x).1
  have hp : (0 : ℤ) < Bls.Fp.modulus := by decide
  by_cases heven : value x % (2 : ℤ) = 0
  · obtain ⟨out,he,hv⟩ := halve_refines x 0#u64 (by decide)
    simp only [heven,show (0#u64).val = 0 from rfl,Nat.cast_zero,zero_mul,add_zero] at hv
    refine ⟨out,?_,by omega,?_⟩
    · simp only [portable.fp.halve_mod_p,is_even_refines,heven,decide_true,bind_tc_ok,if_true,he]
    · simpa only [heven,if_true,add_zero] using hv
  · have hxodd : value x % (2 : ℤ) = 1 := by omega
    obtain ⟨sum,ha,hs⟩ := add_words_refines x bls.constants.P_U64
    have hfit : 0 ≤ value x+(Bls.Fp.modulus : ℤ) ∧
        value x+(Bls.Fp.modulus : ℤ) < (radix : ℤ)^6 := by
      norm_num [Bls.Fp.modulus,radix] at hx ⊢
      omega
    rw [modulus_words,Int.emod_eq_of_lt hfit.1 hfit.2] at hs
    have hnc : ¬(radix : ℤ)^6 ≤ value x+(Bls.Fp.modulus : ℤ) := by omega
    rw [modulus_words] at ha
    simp only [hnc,decide_false] at ha
    obtain ⟨out,he,hv⟩ := halve_refines sum 0#u64 (by decide)
    have hsum_even : value sum % (2 : ℤ) = 0 := by
      rw [hs]
      norm_num [Bls.Fp.modulus] at hxodd ⊢
      omega
    simp only [hsum_even,show (0#u64).val = 0 from rfl,Nat.cast_zero,zero_mul,add_zero] at hv
    refine ⟨out,?_,by omega,?_⟩
    · simp only [portable.fp.halve_mod_p,is_even_refines,heven,decide_false,bind_tc_ok,ha,lift]
      exact he
    · simpa only [heven,if_false,hs] using hv

def coefficientSub (a b : portable.fp.Fp) : Result portable.fp.Fp := do
  let (d,borrow) ← portable.fp.sub_words a b
  if borrow then
    let (out,_) ← portable.fp.add_words d bls.constants.P_U64
    ok out
  else ok d

theorem coefficientSub_eq_sub (a b : portable.fp.Fp) :
    coefficientSub a b = portable.fp.Fp.sub a b := by
  obtain ⟨d,hs,hv⟩ := sub_words_refines a b
  by_cases hb : value a < value b
  · simp only [coefficientSub,portable.fp.Fp.sub,hs,bind_tc_ok,hb,decide_true,
      p_if_refines]
    rfl
  · obtain ⟨out,ha,hout⟩ := add_words_refines d (Array.repeat 6#usize 0#u64)
    have hz : value (Array.repeat 6#usize 0#u64) = 0 := wordsValue_repeat_zero 6
    have hd := value_bounds d
    change 0 ≤ value d ∧ value d < (radix : ℤ)^6 at hd
    rw [hz,add_zero,Int.emod_eq_of_lt hd.1 hd.2] at hout
    have ho : out = d := value_injective out d hout
    subst out
    simp only [coefficientSub,portable.fp.Fp.sub,hs,bind_tc_ok,hb,decide_false,
      p_if_refines]
    change ok d = (do let (out,_) ← portable.fp.add_words d (Array.repeat 6#usize 0#u64); ok out)
    rw [ha]
    rfl

theorem coefficientSub_refines (a b : portable.fp.Fp)
    (ha : value a < Bls.Fp.modulus) (hb : value b < Bls.Fp.modulus) :
    ∃ out, coefficientSub a b = ok out ∧ value out < Bls.Fp.modulus ∧
      value out = (value a-value b) % (Bls.Fp.modulus : ℤ) := by
  obtain ⟨out,he,hv⟩ := sub_value_refines a b ha hb
  refine ⟨out,by rw [coefficientSub_eq_sub]; exact he,?_,hv⟩
  rw [hv]
  exact Int.emod_lt_of_pos _ (by decide)

end LeanBlsSimd.Portable.Fp
