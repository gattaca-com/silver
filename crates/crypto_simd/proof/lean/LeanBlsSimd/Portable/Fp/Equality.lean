import LeanBlsSimd.Portable.Fp.Correct

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Fp

private theorem list_eq_refines (xs ys : List U64) (h : xs.length = ys.length) :
    List.allM (fun (x,y) => (ok (decide (x=y)) : Result Bool)) (List.zip xs ys) =
      ok (decide (xs=ys)) := by
  induction xs generalizing ys with
  | nil =>
    cases ys <;> simp_all
    rfl
  | cons x xs ih =>
    cases ys with
    | nil => simp_all
    | cons y ys =>
      have hl : xs.length = ys.length := by simpa using h
      simp only [List.zip_cons_cons,List.allM_cons,bind_tc_ok]
      by_cases he : x=y
      · subst y
        simpa only [decide_true,ite_true,List.cons.injEq,true_and] using ih ys hl
      · simp [he]
        rfl

theorem array_eq_refines {n : Usize} (a b : Array U64 n) :
    core.array.equality.PartialEqArray.eq core.cmp.PartialEqU64 a b =
      ok (decide (a.val=b.val)) := by
  simp only [core.array.equality.PartialEqArray.eq,Array.length,a.property,b.property,if_true,
    liftFun2]
  exact list_eq_refines a.val b.val (a.property.trans b.property.symm)

theorem encoded_eq_iff (x y : Bls.Fp) : (Kzg.fpEncode x).l.val = (Kzg.fpEncode y).l.val ↔ x=y := by
  constructor
  · intro h
    have he : (Kzg.fpEncode x).l = (Kzg.fpEncode y).l := Subtype.ext h
    have hr := (Kzg.portableFpRep_encode x).2
    rw [he,Kzg.portableFpRep_encode y |>.2] at hr
    exact hr.symm
  · intro h; subst y; rfl

theorem eq_encoded (x y : Bls.Fp) :
    portable.fp.Fp.Insts.CoreCmpPartialEqFp.eq (Kzg.fpEncode x).l (Kzg.fpEncode y).l = ok (decide (x=y)) := by
  simp only [portable.fp.Fp.Insts.CoreCmpPartialEqFp.eq,array_eq_refines,encoded_eq_iff]

end LeanBlsSimd.Portable.Fp
