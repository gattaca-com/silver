import LeanBlsSimd.Portable.Fp.Arithmetic

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls
open scoped EthLib.Cryptography.Bls.Fp

namespace LeanBlsSimd.Portable.Fp
open Word64
set_option maxRecDepth 4096
set_option exponentiation.threshold 4096

private theorem or_zero_iff (a b : U64) : (a ||| b) = 0#u64 ↔ a = 0#u64 ∧ b = 0#u64 := by
  rw [UScalar.eq_equiv_bv_eq (a ||| b) 0#u64,UScalar.eq_equiv_bv_eq a 0#u64,
    UScalar.eq_equiv_bv_eq b 0#u64]
  exact BitVec.or_eq_zero_iff

private theorem word_zero_iff (a : U64) : a = 0#u64 ↔ a.val = 0 := by
  constructor
  · intro h; rw [h]; rfl
  · intro h
    apply UScalar.eq_of_val_eq
    exact h

theorem is_zero_value_refines (a : portable.fp.Fp) :
    portable.fp.Fp.is_zero a = ok (decide (value a = 0)) := by
  have hz : (((((a.val[0]'(by rw [a.property]; decide)) ||| a.val[1]'(by rw [a.property]; decide)) |||
      a.val[2]'(by rw [a.property]; decide)) ||| a.val[3]'(by rw [a.property]; decide)) |||
      a.val[4]'(by rw [a.property]; decide)) ||| a.val[5]'(by rw [a.property]; decide) = 0#u64 ↔ value a = 0 := by
    simp only [or_zero_iff]
    simp only [word_zero_iff]
    conv_rhs => unfold value; rw [list_6 a]
    norm_num [wordsValue,radix]
    omega
  simp (disch := decide) only [portable.fp.Fp.is_zero,index_usize_eq,lift,bind_tc_ok]
  simp only [show (0#usize).val = 0 from rfl,show (1#usize).val = 1 from rfl,
    show (2#usize).val = 2 from rfl,show (3#usize).val = 3 from rfl,
    show (4#usize).val = 4 from rfl,show (5#usize).val = 5 from rfl,hz]

theorem is_zero_encoded (x : Bls.Fp) :
    portable.fp.Fp.is_zero (Kzg.fpEncode x).l = ok x.isZero := by
  rw [is_zero_value_refines]
  have hz : value (Kzg.fpEncode x).l = 0 ↔ x.val = 0 := by
    constructor
    · intro h
      have heq : (Kzg.fpEncode x).l = portable.fp.Fp.ZERO := by
        apply value_injective
        simpa only [portable.fp.Fp.ZERO,value,wordsValue_repeat_zero] using h
      have hr := (Kzg.portableFpRep_encode x).2
      rw [heq,Kzg.portableFpRep_zero.2] at hr
      exact congrArg Fin.val hr.symm
    · intro h
      rw [encode_value,h]
      norm_num
  congr 1
  apply Bool.eq_iff_iff.mpr
  simp only [decide_eq_true_eq,hz,Bls.Fp.isZero,beq_iff_eq]

theorem portable_fp_correct [RuntimeFeatures] : Kzg.PortableFpCorrect where
  add := by
    intro a b x y ha hb
    rw [rep_eq_encode ha,rep_eq_encode hb]
    exact ⟨(Kzg.fpEncode (x+y)).l,add_encoded x y,Kzg.portableFpRep_encode _⟩
  sub := by
    intro a b x y ha hb
    rw [rep_eq_encode ha,rep_eq_encode hb]
    exact ⟨(Kzg.fpEncode (x-y)).l,sub_encoded x y,Kzg.portableFpRep_encode _⟩
  mul := by
    intro a b x y ha hb
    rw [rep_eq_encode ha,rep_eq_encode hb]
    exact ⟨(Kzg.fpEncode (x*y)).l,mul_encoded x y,Kzg.portableFpRep_encode _⟩
  is_zero := by
    intro a x ha
    rw [rep_eq_encode ha]
    exact is_zero_encoded x

end LeanBlsSimd.Portable.Fp
