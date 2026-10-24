import LeanBlsSimd.Portable.Fp.Wide

open Aeneas Aeneas.Std Result
open silver_crypto_simd

namespace LeanBlsSimd.Portable.Fp.Wide
open Word64
set_option maxRecDepth 4096
set_option maxHeartbeats 2000000

private theorem exists12 (t : Array U64 12#usize) :
    ∃ x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 x10 x11 : U64, t = Array.make 12#usize [x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11] (by rfl) := by
  refine ⟨t.val[0]'(by rw [t.property]; decide),t.val[1]'(by rw [t.property]; decide),t.val[2]'(by rw [t.property]; decide),t.val[3]'(by rw [t.property]; decide),t.val[4]'(by rw [t.property]; decide),t.val[5]'(by rw [t.property]; decide),t.val[6]'(by rw [t.property]; decide),t.val[7]'(by rw [t.property]; decide),t.val[8]'(by rw [t.property]; decide),t.val[9]'(by rw [t.property]; decide),t.val[10]'(by rw [t.property]; decide),t.val[11]'(by rw [t.property]; decide),?_⟩
  apply Subtype.ext
  exact list_12 t

private theorem exists7 (t : Array U64 7#usize) :
    ∃ x0 x1 x2 x3 x4 x5 x6 : U64, t = Array.make 7#usize [x0,x1,x2,x3,x4,x5,x6] (by rfl) := by
  refine ⟨t.val[0]'(by rw [t.property]; decide),t.val[1]'(by rw [t.property]; decide),t.val[2]'(by rw [t.property]; decide),t.val[3]'(by rw [t.property]; decide),t.val[4]'(by rw [t.property]; decide),t.val[5]'(by rw [t.property]; decide),t.val[6]'(by rw [t.property]; decide),?_⟩
  apply Subtype.ext
  exact list_7 t

def rowIndex (i : Fin 6) : Usize :=
  UScalar.ofNatCore i.val (lt_of_lt_of_le (by omega : i.val < 2^32) two_pow_32_le_usize)

def window (t : portable.fp.Wide) (i : Fin 6) : Array U64 6#usize :=
  Array.make 6#usize ((t.val.drop i.val).take 6) (by
    have ht : t.val.length = 12 := t.property
    have hi := i.isLt
    simp only [List.length_take,List.length_drop]
    change min 6 (t.val.length-i.val) = 6
    omega)

def replaceRow (t : portable.fp.Wide) (i : Fin 6) (s : Array U64 7#usize) : portable.fp.Wide :=
  Array.make 12#usize (t.val.take i.val ++ s.val ++ t.val.drop (i.val+7)) (by
    have ht : t.val.length = 12 := t.property
    have hs : s.val.length = 7 := s.property
    have hi := i.isLt
    simp only [List.length_append,List.length_take,List.length_drop]
    change min i.val t.val.length+s.val.length+(t.val.length-(i.val+7)) = 12
    omega)

theorem add_row_run (t : portable.fp.Wide) (a : portable.fp.Fp) (b : U64)
    (i : Fin 6) (s : Array U64 7#usize)
    (hz : t.val[i.val+6]'(by rw [t.property]; change i.val+6 < 12; have := i.isLt; omega) = 0#u64)
    (hm : portable.fp.mul_add (extend (window t i)) a b = ok s) :
    portable.fp.add_row_at t a b (rowIndex i) = ok (replaceRow t i s) := by
  obtain ⟨t0,t1,t2,t3,t4,t5,t6,t7,t8,t9,t10,t11,rfl⟩ := exists12 t
  obtain ⟨s0,s1,s2,s3,s4,s5,s6,rfl⟩ := exists7 s
  fin_cases i
  all_goals
    simp only [rowIndex]
    simp (disch := decide) only [portable.fp.add_row_at,usize_add_ok,index_usize_eq,bind_tc_ok]
    simp only [show (0#usize).val = 0 from rfl,show (1#usize).val = 1 from rfl,
      show (2#usize).val = 2 from rfl,show (3#usize).val = 3 from rfl,
      show (4#usize).val = 4 from rfl,show (5#usize).val = 5 from rfl,
      show (6#usize).val = 6 from rfl,show (7#usize).val = 7 from rfl,
      show (8#usize).val = 8 from rfl,show (9#usize).val = 9 from rfl,
      show (10#usize).val = 10 from rfl,show (11#usize).val = 11 from rfl] at *
    rw [hz]
    simp only [massert,if_true,bind_tc_ok]
    simp only [extend,window,Array.make,List.getElem_take,List.getElem_drop] at hm
    norm_num only at hm
    simp only [Array.make]
    rw [hm]
    simp (disch := decide) only [bind_tc_ok,update_eq]
    congr 1

theorem word_zero_of_bound {n : Usize} (t : Array U64 n) (i : Nat)
    (hi : i < n.val) (ht : value t < (radix : ℤ)^i) :
    t.val[i]'(by rw [t.property]; exact hi) = 0#u64 := by
  have hsplit := wordsValue_take_drop t.val i
  have htail := tail_step t i hi
  have hlo := (wordsValue_bounds (t.val.take i)).1
  have hrest := (wordsValue_bounds (t.val.drop (i+1))).1
  have hp : (0 : ℤ) < (radix : ℤ)^i := by positivity
  have hr : (0 : ℤ) ≤ radix := by decide
  have hnonneg := mul_nonneg hp.le (mul_nonneg hr hrest)
  change value t = wordsValue (t.val.take i)+(radix : ℤ)^i*tail t i at hsplit
  have hword : (radix : ℤ)^i*(t.val[i]'(by rw [t.property]; exact hi)).val ≤ value t := by
    rw [htail] at hsplit
    change 0 ≤ (radix : ℤ)^i*((radix : ℤ)*tail t (i+1)) at hnonneg
    nlinarith
  apply UScalar.eq_of_val_eq
  change (t.val[i]'_).val = 0
  by_contra h
  have hone : (1 : ℤ) ≤ (t.val[i]'(by rw [t.property]; exact hi)).val := by omega
  have hm := mul_le_mul_of_nonneg_left hone hp.le
  nlinarith

theorem replaceRow_value (t : portable.fp.Wide) (i : Fin 6) (s : Array U64 7#usize)
    (hz : t.val[i.val+6]'(by rw [t.property]; change i.val+6 < 12; have := i.isLt; omega) = 0#u64) :
    value (replaceRow t i s) = value t+(radix : ℤ)^i.val*(value s-value (extend (window t i))) := by
  obtain ⟨t0,t1,t2,t3,t4,t5,t6,t7,t8,t9,t10,t11,rfl⟩ := exists12 t
  obtain ⟨s0,s1,s2,s3,s4,s5,s6,rfl⟩ := exists7 s
  fin_cases i
  all_goals
    simp only [value,replaceRow,extend,window,Array.make]
    norm_num only [List.take, List.drop, List.nil_append, List.cons_append, List.getElem_cons_zero,
      List.getElem_cons_succ, Fin.val_mk, wordsValue, Nat.cast_zero, Nat.cast_add]
    norm_num only [Array.make,List.getElem_cons_zero,List.getElem_cons_succ] at hz
    rw [hz]
    simp only [show (0#u64).val = 0 from rfl,Nat.cast_zero]
    ring

theorem add_row_refines (t : portable.fp.Wide) (a : portable.fp.Fp) (b : U64)
    (i : Fin 6) (ht : value t < (radix : ℤ)^(i.val+6)) :
    ∃ out, portable.fp.add_row_at t a b (rowIndex i) = ok out ∧
      value out = value t+(radix : ℤ)^i.val*value a*b.val ∧
      value out < (radix : ℤ)^(i.val+7) := by
  have hz := word_zero_of_bound t (i.val+6) (by change i.val+6 < 12; have := i.isLt; omega) ht
  obtain ⟨s,he,hv⟩ := mul_add_refines (extend (window t i)) a b
  have ha := value_bounds a
  have hw := value_bounds (window t i)
  change 0 ≤ value a ∧ value a < (radix : ℤ)^6 at ha
  change 0 ≤ value (window t i) ∧ value (window t i) < (radix : ℤ)^6 at hw
  have hb := b.hBounds
  have hb0 : (0 : ℤ) ≤ b.val := by positivity
  have hb1 : (b.val : ℤ) ≤ (radix : ℤ)-1 := by
    norm_num [radix,UScalarTy.numBits] at hb ⊢
    omega
  have hm : value a*b.val ≤ (radix : ℤ)^6*((radix : ℤ)-1) := by
    have ha' : value a ≤ (radix : ℤ)^6 := ha.2.le
    have hprod := mul_le_mul_of_nonneg_right ha' hb0
    have hprod' := mul_le_mul_of_nonneg_left hb1 (by positivity : (0 : ℤ) ≤ (radix : ℤ)^6)
    exact hprod.trans hprod'
  have hfit : 0 ≤ value (window t i)+value a*b.val ∧
      value (window t i)+value a*b.val < (radix : ℤ)^7 := by
    constructor
    · exact add_nonneg hw.1 (mul_nonneg ha.1 hb0)
    · rw [pow_succ]
      nlinarith
  rw [value_extend,Int.emod_eq_of_lt hfit.1 hfit.2] at hv
  refine ⟨replaceRow t i s,add_row_run t a b i s hz he,?_,?_⟩
  · rw [replaceRow_value t i s hz,value_extend,hv]
    ring
  · rw [replaceRow_value t i s hz,value_extend,hv]
    have hp : (0 : ℤ) < (radix : ℤ)^i.val := by positivity
    have hm' := mul_le_mul_of_nonneg_left hm hp.le
    rw [pow_add] at ht ⊢
    rw [show (radix : ℤ)^7 = (radix : ℤ)^6*(radix : ℤ) from pow_succ _ _]
    nlinarith

theorem product_refines (a b : portable.fp.Fp) :
    ∃ out, portable.fp.Wide.product a b = ok out ∧ value out = value a*value b := by
  let start : portable.fp.Wide := Array.repeat 12#usize 0#u64
  have hz : value start = 0 := wordsValue_repeat_zero 12
  obtain ⟨t1,he1,hv1,hb1⟩ := add_row_refines start a
    (b.val[0]'(by rw [b.property]; decide)) ⟨0,by decide⟩ (by rw [hz]; positivity)
  obtain ⟨t2,he2,hv2,hb2⟩ := add_row_refines t1 a
    (b.val[1]'(by rw [b.property]; decide)) ⟨1,by decide⟩ hb1
  obtain ⟨t3,he3,hv3,hb3⟩ := add_row_refines t2 a
    (b.val[2]'(by rw [b.property]; decide)) ⟨2,by decide⟩ hb2
  obtain ⟨t4,he4,hv4,hb4⟩ := add_row_refines t3 a
    (b.val[3]'(by rw [b.property]; decide)) ⟨3,by decide⟩ hb3
  obtain ⟨t5,he5,hv5,hb5⟩ := add_row_refines t4 a
    (b.val[4]'(by rw [b.property]; decide)) ⟨4,by decide⟩ hb4
  obtain ⟨t6,he6,hv6,hb6⟩ := add_row_refines t5 a
    (b.val[5]'(by rw [b.property]; decide)) ⟨5,by decide⟩ hb5
  refine ⟨t6,?_,?_⟩
  · simp (disch := decide) only [portable.fp.Wide.product,index_usize_eq,bind_tc_ok]
    change portable.fp.add_row_at (Array.repeat 12#usize 0#u64) a (b.val[0]'(by rw [b.property]; decide)) 0#usize = ok t1 at he1
    change portable.fp.add_row_at t1 a (b.val[1]'(by rw [b.property]; decide)) 1#usize = ok t2 at he2
    change portable.fp.add_row_at t2 a (b.val[2]'(by rw [b.property]; decide)) 2#usize = ok t3 at he3
    change portable.fp.add_row_at t3 a (b.val[3]'(by rw [b.property]; decide)) 3#usize = ok t4 at he4
    change portable.fp.add_row_at t4 a (b.val[4]'(by rw [b.property]; decide)) 4#usize = ok t5 at he5
    change portable.fp.add_row_at t5 a (b.val[5]'(by rw [b.property]; decide)) 5#usize = ok t6 at he6
    simp only [show (0#usize).val = 0 from rfl,show (1#usize).val = 1 from rfl,show (2#usize).val = 2 from rfl,show (3#usize).val = 3 from rfl,show (4#usize).val = 4 from rfl,show (5#usize).val = 5 from rfl]
    simp only [he1,he2,he3,he4,he5,he6,bind_tc_ok]
  · rw [hv6,hv5,hv4,hv3,hv2,hv1,hz]
    conv_rhs => arg 2; unfold value; rw [list_6 b]
    simp only [wordsValue]
    ring

end LeanBlsSimd.Portable.Fp.Wide
