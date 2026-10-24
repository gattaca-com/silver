import LeanBlsSimd.Portable.Fp.MultiplyAdd
import LeanBlsSimd.Portable.Fp.Reduction

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

set_option maxRecDepth 4096
set_option maxHeartbeats 2000000

namespace LeanBlsSimd.Portable.Fp
open Word64

theorem list_6 (a : Array U64 6#usize) :
    a.val = [a.val[0]'(by rw [a.property]; decide),a.val[1]'(by rw [a.property]; decide),a.val[2]'(by rw [a.property]; decide),a.val[3]'(by rw [a.property]; decide),a.val[4]'(by rw [a.property]; decide),a.val[5]'(by rw [a.property]; decide)] := by
  apply List.ext_getElem
  · exact a.property
  · intro i hi _
    have hin : i < 6 := by simpa only [a.property] using hi
    interval_cases i <;> rfl

theorem list_7 (a : Array U64 7#usize) :
    a.val = [a.val[0]'(by rw [a.property]; decide),a.val[1]'(by rw [a.property]; decide),a.val[2]'(by rw [a.property]; decide),a.val[3]'(by rw [a.property]; decide),a.val[4]'(by rw [a.property]; decide),a.val[5]'(by rw [a.property]; decide),a.val[6]'(by rw [a.property]; decide)] := by
  apply List.ext_getElem
  · exact a.property
  · intro i hi _
    have hin : i < 7 := by simpa only [a.property] using hi
    interval_cases i <;> rfl

def extend (a : Array U64 6#usize) : Array U64 7#usize :=
  Array.make 7#usize [a.val[0]'(by rw [a.property]; decide),a.val[1]'(by rw [a.property]; decide),a.val[2]'(by rw [a.property]; decide),a.val[3]'(by rw [a.property]; decide),a.val[4]'(by rw [a.property]; decide),a.val[5]'(by rw [a.property]; decide),0#u64] (by rfl)

def shift (a : Array U64 7#usize) : Array U64 6#usize :=
  Array.make 6#usize [a.val[1]'(by rw [a.property]; decide),a.val[2]'(by rw [a.property]; decide),a.val[3]'(by rw [a.property]; decide),a.val[4]'(by rw [a.property]; decide),a.val[5]'(by rw [a.property]; decide),a.val[6]'(by rw [a.property]; decide)] (by rfl)

theorem value_extend (a : Array U64 6#usize) : value (extend a) = value a := by
  unfold value extend
  conv_rhs => rw [list_6 a]
  rfl

theorem value_shift (a : Array U64 7#usize) : value (shift a) = value a / (radix : ℤ) := by
  have h0 := (a.val[0]'(by rw [a.property]; decide)).hBounds
  unfold value shift
  conv_rhs => rw [list_7 a]
  change wordsValue [a.val[1]'(by rw [a.property]; decide),a.val[2]'(by rw [a.property]; decide),a.val[3]'(by rw [a.property]; decide),a.val[4]'(by rw [a.property]; decide),a.val[5]'(by rw [a.property]; decide),a.val[6]'(by rw [a.property]; decide)] =
    ((a.val[0]'(by rw [a.property]; decide)).val+(radix : ℤ)*wordsValue [a.val[1]'(by rw [a.property]; decide),a.val[2]'(by rw [a.property]; decide),a.val[3]'(by rw [a.property]; decide),a.val[4]'(by rw [a.property]; decide),a.val[5]'(by rw [a.property]; decide),a.val[6]'(by rw [a.property]; decide)])/(radix : ℤ)
  norm_num [radix,UScalarTy.numBits] at h0 ⊢
  omega

theorem low_word_remainder (a : Array U64 7#usize) :
    value a % (radix : ℤ) = (a.val[0]'(by rw [a.property]; decide)).val := by
  have h0 := (a.val[0]'(by rw [a.property]; decide)).hBounds
  unfold value
  conv_lhs => rw [list_7 a]
  change ((a.val[0]'(by rw [a.property]; decide)).val+(radix : ℤ)*wordsValue [a.val[1]'(by rw [a.property]; decide),a.val[2]'(by rw [a.property]; decide),a.val[3]'(by rw [a.property]; decide),a.val[4]'(by rw [a.property]; decide),a.val[5]'(by rw [a.property]; decide),a.val[6]'(by rw [a.property]; decide)])%(radix : ℤ) = _
  norm_num [radix,UScalarTy.numBits] at h0 ⊢
  omega

theorem cancellation (sum : Array U64 7#usize) :
    let m := core.num.U64.wrapping_mul (sum.val[0]'(by rw [sum.property]; decide)) portable.constants.P_INV
    (value sum+(m.val : ℤ)*Bls.Fp.modulus) % (radix : ℤ) = 0 := by
  dsimp only
  rw [core.num.U64.wrapping_mul_val_eq]
  have hs := Int.emod_add_mul_ediv (value sum) (radix : ℤ)
  rw [low_word_remainder] at hs
  have hm := Nat.mod_add_div ((sum.val[0]'(by rw [sum.property]; decide)).val*portable.constants.P_INV.val) radix
  norm_num [U64.size,U64.numBits,UScalar.size,UScalarTy.numBits,portable.constants.P_INV,Bls.Fp.modulus,radix] at hs hm ⊢
  omega

theorem row_run (t a : Array U64 6#usize) (w : U64) (sum reduced : Array U64 7#usize)
    (hfirst : portable.fp.mul_add (extend t) a w = ok sum)
    (hsecond : portable.fp.mul_add sum bls.constants.P_U64
      (core.num.U64.wrapping_mul (sum.val[0]'(by rw [sum.property]; decide)) portable.constants.P_INV) = ok reduced) :
    portable.fp.row t a w = ok (shift reduced) := by
  simp only [portable.fp.row]
  simp (disch := decide) only [index_usize_eq,bind_tc_ok]
  change (do
    let sum ← portable.fp.mul_add (extend t) a w
    let reduced ← portable.fp.mul_add sum bls.constants.P_U64
      (core.num.U64.wrapping_mul (sum.val[0]'(by rw [sum.property]; decide)) portable.constants.P_INV)
    ok (shift reduced)) = _
  rw [hfirst]
  simp only [bind_tc_ok]
  rw [hsecond]
  rfl

theorem row_refines (t a : Array U64 6#usize) (w : U64)
    (ha : value a < Bls.Fp.modulus) (ht : value t < value a+Bls.Fp.modulus) :
    ∃ (out : Array U64 6#usize) (m : U64), portable.fp.row t a w = ok out ∧
      value out < value a+Bls.Fp.modulus ∧
      value out*(radix : ℤ) = value t+value a*w.val+(m.val : ℤ)*Bls.Fp.modulus := by
  have ha0 := (value_bounds a).1
  have ht0 := (value_bounds t).1
  have hw : (w.val : ℤ) ≤ (radix : ℤ)-1 := by
    have := w.hBounds
    norm_num [UScalarTy.numBits,radix] at this ⊢
    omega
  have hwmul := mul_le_mul_of_nonneg_left hw ha0
  have hsfit : 0 ≤ value t+value a*w.val ∧ value t+value a*w.val < (radix : ℤ)^7 := by
    constructor
    · positivity
    · norm_num [radix,Bls.Fp.modulus] at ha ht hwmul ⊢
      nlinarith
  obtain ⟨sum,hfirst,hs⟩ := mul_add_refines (extend t) a w
  rw [value_extend,Int.emod_eq_of_lt hsfit.1 hsfit.2] at hs
  let m := core.num.U64.wrapping_mul (sum.val[0]'(by rw [sum.property]; decide)) portable.constants.P_INV
  have hm : (m.val : ℤ) ≤ (radix : ℤ)-1 := by
    have := m.hBounds
    norm_num [UScalarTy.numBits,radix] at this ⊢
    omega
  have hmmul := mul_le_mul_of_nonneg_left hm (show (0 : ℤ) ≤ Bls.Fp.modulus by decide)
  have hbound : value t+value a*w.val+(m.val : ℤ)*Bls.Fp.modulus <
      (value a+Bls.Fp.modulus)*(radix : ℤ) := by nlinarith
  have hredfit : 0 ≤ value sum+(Bls.Fp.modulus : ℤ)*m.val ∧
      value sum+(Bls.Fp.modulus : ℤ)*m.val < (radix : ℤ)^7 := by
    rw [hs]
    constructor
    · positivity
    · norm_num [radix,Bls.Fp.modulus] at ha hbound ⊢
      nlinarith
  obtain ⟨reduced,hsecond,hr⟩ := mul_add_refines sum bls.constants.P_U64 m
  rw [modulus_words,Int.emod_eq_of_lt hredfit.1 hredfit.2] at hr
  have hcancel : (value sum+(m.val : ℤ)*Bls.Fp.modulus) % (radix : ℤ) = 0 := cancellation sum
  refine ⟨shift reduced,m,row_run t a w sum reduced hfirst hsecond,?_,?_⟩
  · rw [value_shift,hr,hs,mul_comm (Bls.Fp.modulus : ℤ) (m.val : ℤ)]
    norm_num [radix] at hbound ⊢
    omega
  · have hdiv := Int.emod_add_mul_ediv (value sum+(m.val : ℤ)*Bls.Fp.modulus) (radix : ℤ)
    rw [hcancel,zero_add] at hdiv
    rw [value_shift,hr]
    have heq : value sum+(Bls.Fp.modulus : ℤ)*m.val = value sum+(m.val : ℤ)*Bls.Fp.modulus := by ring
    rw [heq]
    rw [hs] at hdiv ⊢
    nlinarith

theorem product_refines (a b : Array U64 6#usize) (ha : value a < Bls.Fp.modulus) :
    ∃ out, portable.fp.Fp.product a b = ok out ∧ value out < Bls.Fp.modulus ∧
      ∃ k : ℤ, value out*(radix : ℤ)^6 = value a*value b+k*Bls.Fp.modulus := by
  have ha0 := (value_bounds a).1
  have hz : value (Array.repeat 6#usize 0#u64) < value a+Bls.Fp.modulus := by
    change (0 : ℤ) < value a+Bls.Fp.modulus
    have hp : (0 : ℤ) < Bls.Fp.modulus := by decide
    omega
  obtain ⟨t0,m0,hr0,hb0,hv0⟩ := row_refines (Array.repeat 6#usize 0#u64) a (b.val[0]'(by rw [b.property]; decide)) ha hz
  obtain ⟨t1,m1,hr1,hb1,hv1⟩ := row_refines t0 a (b.val[1]'(by rw [b.property]; decide)) ha hb0
  obtain ⟨t2,m2,hr2,hb2,hv2⟩ := row_refines t1 a (b.val[2]'(by rw [b.property]; decide)) ha hb1
  obtain ⟨t3,m3,hr3,hb3,hv3⟩ := row_refines t2 a (b.val[3]'(by rw [b.property]; decide)) ha hb2
  obtain ⟨t4,m4,hr4,hb4,hv4⟩ := row_refines t3 a (b.val[4]'(by rw [b.property]; decide)) ha hb3
  obtain ⟨t5,m5,hr5,hb5,hv5⟩ := row_refines t4 a (b.val[5]'(by rw [b.property]; decide)) ha hb4
  obtain ⟨out,hbelow,hout⟩ := below_p_refines t5 (by omega)
  let q : ℤ := (m0.val : ℤ)*(radix : ℤ)^0+(m1.val : ℤ)*(radix : ℤ)^1+(m2.val : ℤ)*(radix : ℤ)^2+(m3.val : ℤ)*(radix : ℤ)^3+(m4.val : ℤ)*(radix : ℤ)^4+(m5.val : ℤ)*(radix : ℤ)^5
  have hrows : value t5*(radix : ℤ)^6 = value a*value b+q*Bls.Fp.modulus := by
    unfold value at ⊢
    conv_rhs => arg 1; arg 2; rw [list_6 b]
    change value t5*(radix : ℤ)^6 = value a*((b.val[0]'(by rw [b.property]; decide)).val+
      (radix : ℤ)*((b.val[1]'(by rw [b.property]; decide)).val+
      (radix : ℤ)*((b.val[2]'(by rw [b.property]; decide)).val+
      (radix : ℤ)*((b.val[3]'(by rw [b.property]; decide)).val+
      (radix : ℤ)*((b.val[4]'(by rw [b.property]; decide)).val+
      (radix : ℤ)*((b.val[5]'(by rw [b.property]; decide)).val))))))+q*Bls.Fp.modulus
    dsimp only [q]
    change value t0*(radix : ℤ) = 0+value a*(b.val[0]'(by rw [b.property]; decide)).val+(m0.val : ℤ)*Bls.Fp.modulus at hv0
    linear_combination hv0*(radix : ℤ)^0 + hv1*(radix : ℤ)^1 + hv2*(radix : ℤ)^2 + hv3*(radix : ℤ)^3 + hv4*(radix : ℤ)^4 + hv5*(radix : ℤ)^5
  refine ⟨out,?_,?_,q-(value t5/(Bls.Fp.modulus : ℤ))*(radix : ℤ)^6,?_⟩
  · simp (disch := decide) only [portable.fp.Fp.product,index_usize_eq,bind_tc_ok]
    simp only [show (0#usize).val = 0 from rfl, show (1#usize).val = 1 from rfl, show (2#usize).val = 2 from rfl, show (3#usize).val = 3 from rfl, show (4#usize).val = 4 from rfl, show (5#usize).val = 5 from rfl]
    simp only [hr0,hr1,hr2,hr3,hr4,hr5,bind_tc_ok,hbelow]
  · rw [hout]
    exact Int.emod_lt_of_pos _ (by decide)
  · have hd := Int.emod_add_mul_ediv (value t5) (Bls.Fp.modulus : ℤ)
    rw [←hout] at hd
    linear_combination hrows+(radix : ℤ)^6*hd

end LeanBlsSimd.Portable.Fp
