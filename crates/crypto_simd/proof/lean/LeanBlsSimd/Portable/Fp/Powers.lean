import LeanBlsSimd.Portable.Fp.Sign
import LeanBlsSimd.Refines.Constants
import LeanBlsSimd.Refines.Loop
import LeanBlsSimd.Proofs.Pow

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd
open EthLib.Cryptography Bls
open scoped EthLib.Cryptography.Bls.Fp

namespace LeanBlsSimd.Portable.Fp
set_option maxRecDepth 4096
set_option maxHeartbeats 2000000
set_option exponentiation.threshold 4096

def powerTable (x : ZMod Bls.Fp.modulus) : Array portable.fp.Fp 16#usize :=
  toArray (fun y => (Kzg.fpEncode y).l) (Vector.ofFn (fun i : Fin 16 => x^i.val))

theorem powerTable_get (x : ZMod Bls.Fp.modulus) (i : Nat) (hi : i < 16) :
    (powerTable x).val[i]'(by rw [(powerTable x).property]; exact hi) = (Kzg.fpEncode (x^i)).l := by
  simp [powerTable,toArray]

theorem powerTable_index (x : ZMod Bls.Fp.modulus) (i : Usize) (hi : i.val < 16) :
    Array.index_usize (powerTable x) i = ok (Kzg.fpEncode (x^i.val)).l := by
  rw [index_usize_eq _ _ hi,powerTable_get x i.val hi]

theorem power_table_loop [RuntimeFeatures] (x : ZMod Bls.Fp.modulus) (table : Array portable.fp.Fp 16#usize)
    (j : Usize) (hj : 1 ≤ j.val ∧ j.val ≤ 16)
    (hp : ∀ i (hi : i < 16), i < j.val →
      table.val[i]'(by rw [table.property]; exact hi) = (Kzg.fpEncode (x^i)).l) :
    portable.fp.Fp.pow_p_minus_3_over_4_loop0 (Kzg.fpEncode x).l table j = ok (powerTable x) := by
  induction hn : 16-j.val generalizing table j with
  | zero =>
    have hje : j.val = 16 := by omega
    have hstop : ¬j < 16#usize := by change ¬j.val < 16; omega
    have heq : table = powerTable x := by
      apply Subtype.ext
      apply List.ext_getElem
      · rw [table.property,(powerTable x).property]
      · intro i hi ht
        have hi16 : i < 16 := by simpa only [table.property] using hi
        rw [powerTable_get x i hi16]
        exact hp i hi16 (by omega)
    rw [portable.fp.Fp.pow_p_minus_3_over_4_loop0,loop.eq_1]
    simp [portable.fp.Fp.pow_p_minus_3_over_4_loop0.body,hstop,heq]
  | succ n ih =>
    have hjlt : j.val < 16 := by omega
    let next : Usize := UScalar.ofNatCore (j.val+1)
      (lt_of_lt_of_le (by omega : j.val+1 < 2^32) two_pow_32_le_usize)
    let prev : Usize := UScalar.ofNatCore (j.val-1)
      (lt_of_lt_of_le (by omega : j.val-1 < 2^32) two_pow_32_le_usize)
    let word := (Kzg.fpEncode (x^j.val)).l
    have hnxt : next.val = j.val+1 := rfl
    have hprev : prev.val = j.val-1 := rfl
    have hbody : portable.fp.Fp.pow_p_minus_3_over_4_loop0.body (Kzg.fpEncode x).l table j =
        ok (cont (table.set j word,next)) := by
      have hj' : j < 16#usize := hjlt
      simp only [portable.fp.Fp.pow_p_minus_3_over_4_loop0.body,hj',if_true]
      rw [sub_ok _ _ (by change 1 ≤ j.val; omega)]
      change (do
        let f ← Array.index_usize table prev
        let f1 ← portable.fp.Fp.mul f (Kzg.fpEncode x).l
        let a ← Array.update table j f1
        let j1 ← j + 1#usize
        ok (cont (a,j1))) = _
      rw [index_usize_eq table prev (by change j.val-1 < 16; omega)]
      simp only [bind_tc_ok,hp prev.val (by change j.val-1 < 16; omega) (by change j.val-1 < j.val; omega),mul_encoded]
      have he : x^prev.val*x = x^j.val := by rw [←pow_succ,hprev,show j.val-1+1 = j.val by omega]
      change (do
        let a ← Array.update table j (Kzg.fpEncode ((x^prev.val*x) : ZMod Bls.Fp.modulus)).l
        let j1 ← j + 1#usize
        ok (cont (a,j1))) = _
      rw [he,update_eq table j word hjlt,usize_add_ok j 1#usize (by change j.val+1 < 2^32; omega)]
      rfl
    have hp' : ∀ i (hi : i < 16), i < next.val →
      (table.set j word).val[i]'(by rw [(table.set j word).property]; exact hi) = (Kzg.fpEncode (x^i)).l := by
      intro i hi hij
      change (table.val.set j.val word)[i]'_ = _
      by_cases h : j.val = i
      · subst i; rw [List.getElem_set_self]
      · rw [List.getElem_set_ne h]
        exact hp i hi (by omega)
    rw [portable.fp.Fp.pow_p_minus_3_over_4_loop0,loop.eq_1]
    simpa only [hbody] using ih (table.set j word) next (by omega) hp' (by omega)

theorem power_table_refines [RuntimeFeatures] (x : ZMod Bls.Fp.modulus) :
    portable.fp.Fp.pow_p_minus_3_over_4_loop0 (Kzg.fpEncode x).l
      (Array.repeat 16#usize portable.constants.ONE) 1#usize = ok (powerTable x) := by
  apply power_table_loop x _ _ (by decide)
  intro i hi hj
  have he : i=0 := by change i < 1 at hj; omega
  subst i
  change portable.constants.ONE = (Kzg.fpEncode ((x^(0 : Nat)) : ZMod Bls.Fp.modulus)).l
  rw [pow_zero]
  exact rep_eq_encode Kzg.portableFpRep_one

theorem power_windows_refines [RuntimeFeatures] (x : ZMod Bls.Fp.modulus) (e : Nat) (w : Usize) (n : Nat)
    (hwn : w.val = n) (hn : n ≤ 95) :
    portable.fp.Fp.pow_p_minus_3_over_4_loop1 (powerTable x) (Kzg.fpEncode (x^e)).l w =
      ok (Kzg.fpEncode (x^((List.range n).reverse.foldl
        (fun e w => 16*e+P_MINUS_3_OVER_4_WINDOWS[w]!) e))).l := by
  unfold portable.fp.Fp.pow_p_minus_3_over_4_loop1
  refine loop_countdown _ (fun e c => ((Kzg.fpEncode (x^e)).l,c))
    (fun e w => 16*e+P_MINUS_3_OVER_4_WINDOWS[w]!) (fun e => (Kzg.fpEncode (x^e)).l) n ?_ ?_ w e hwn
  · intro m c hc
    simp [portable.fp.Fp.pow_p_minus_3_over_4_loop1.body,hc]
    rfl
  · intro m c c' hc hcn
    simp only [portable.fp.Fp.pow_p_minus_3_over_4_loop1.body]
    rw [if_pos (by simp; omega),sub_ok _ _ (by simp; omega)]
    have hc'v : c'.val < 95 := by omega
    have he : (UScalar.ofNatCore (c.val-(1#usize).val) (by have := c.hBounds; omega) : Usize) = c' :=
      UScalar.eq_of_val_eq (by simp; omega)
    simp only [he,bind_tc_ok,square_encoded,P_MINUS_3_OVER_4_WINDOWS_index c' hc'v,lift,cast_Usize_ofNatCore]
    rw [powerTable_index x _ (by simp only [UScalar.ofNatCore_val_eq]; exact windows_lt c'.val (List.mem_range.mpr hc'v))]
    simp only [bind_tc_ok,mul_encoded,UScalar.ofNatCore_val_eq]
    apply congrArg (fun y : ZMod Bls.Fp.modulus => ok (cont ((Kzg.fpEncode y).l,c')))
    show (((x^m*x^m)*(x^m*x^m))*((x^m*x^m)*(x^m*x^m)))*
      (((x^m*x^m)*(x^m*x^m))*((x^m*x^m)*(x^m*x^m)))*x^P_MINUS_3_OVER_4_WINDOWS[c'.val]! = _
    simp only [←pow_add]
    congr 1
    omega

theorem pow_p_minus_3_over_4_refines [RuntimeFeatures] (x : ZMod Bls.Fp.modulus) :
    portable.fp.Fp.pow_p_minus_3_over_4 (Kzg.fpEncode x).l =
      ok (Kzg.fpEncode (x^((Bls.Fp.modulus-3)/4))).l := by
  unfold portable.fp.Fp.pow_p_minus_3_over_4
  simp only [power_table_refines,bind_tc_ok,lift]
  have h94 : P_MINUS_3_OVER_4_WINDOWS[94]! < 16 := windows_lt 94 (by simp)
  have hlen : Slice.len (Array.to_slice bls.constants.P_MINUS_3_OVER_4_WINDOWS) = 95#usize := by
    apply UScalar.eq_of_val_eq
    simp [Slice.len,Array.to_slice,bls.constants.P_MINUS_3_OVER_4_WINDOWS]
  rw [hlen]
  change (do
    let i ← 95#usize - 1#usize
    let i1 ← Array.index_usize bls.constants.P_MINUS_3_OVER_4_WINDOWS i
    let result ← Array.index_usize (powerTable x) (UScalar.cast .Usize i1)
    portable.fp.Fp.pow_p_minus_3_over_4_loop1 (powerTable x) result i) = _
  rw [show 95#usize-1#usize = ok 94#usize by rw [sub_ok _ _ (by decide)]; rfl]
  simp only [bind_tc_ok,P_MINUS_3_OVER_4_WINDOWS_index 94#usize (by decide),cast_Usize_ofNatCore]
  rw [powerTable_index x _ (by simp only [UScalar.ofNatCore_val_eq]; exact h94)]
  simp only [bind_tc_ok,UScalar.ofNatCore_val_eq]
  rw [power_windows_refines _ _ _ 94 rfl (by decide),windows_horner]

end LeanBlsSimd.Portable.Fp
