import LeanBlsSimd.Portable.Msm.Store
import LeanBlsSimd.Msm8.Affine

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Msm.Batch

abbrev Field := ZMod Bls.Fp.modulus

def finishValues (xa ya xb yb inverse : Field) : Field × Field :=
  let slope := (yb-ya)*inverse
  let x := slope^2-xa-xb
  (x, slope*(xa-x)-ya)

theorem finish_encoded [RuntimeFeatures]
    (adds : portable.msm.pairs.BatchedAdds) (store : portable.msm.store.PointStore)
    (i : Usize) (ra rb output : U32) (xa ya xb yb inverse : Field)
    (ha : adds.a.val[i.val]? = some ra) (hb : adds.b.val[i.val]? = some rb)
    (ho : adds.out.val[i.val]? = some output)
    (hsa : store.signed ra = ok ((Kzg.fpEncode xa).l,(Kzg.fpEncode ya).l))
    (hsb : store.signed rb = ok ((Kzg.fpEncode xb).l,(Kzg.fpEncode yb).l))
    (hbound : output.val < store.points.val.length) :
    adds.finish store i (Kzg.fpEncode inverse).l = ok
      (Store.write store output.val (finishValues xa ya xb yb inverse).1
        (finishValues xa ya xb yb inverse).2) := by
  have hia := (List.getElem?_eq_some_iff.mp ha).choose
  have hib := (List.getElem?_eq_some_iff.mp hb).choose
  have hio := (List.getElem?_eq_some_iff.mp ho).choose
  have hea : adds.a.val[i.val] = ra := by simpa only [List.getElem?_eq_getElem hia, Option.some.injEq] using ha
  have heb : adds.b.val[i.val] = rb := by simpa only [List.getElem?_eq_getElem hib, Option.some.injEq] using hb
  have heo : adds.out.val[i.val] = output := by simpa only [List.getElem?_eq_getElem hio, Option.some.injEq] using ho
  simp only [portable.msm.pairs.BatchedAdds.finish, BucketsRefines.vec_index _ _ hia, hea,
    BucketsRefines.vec_index _ _ hib, heb, BucketsRefines.vec_index _ _ hio, heo,
    hsa,hsb,bind_tc_ok,Function.uncurry_def,Fp.sub_encoded,Fp.mul_encoded,Fp.square_encoded,Store.set_refines _ _ _ _ hbound]
  simp only [finishValues, pow_two]
  rfl

theorem finishValues_nonsingular {xa ya xb yb : Field}
    (ha : G1Spec.E.Nonsingular xa ya) (hb : G1Spec.E.Nonsingular xb yb) (hne : xa ≠ xb) :
    G1Spec.E.Nonsingular (finishValues xa ya xb yb (xb-xa)⁻¹).1
      (finishValues xa ya xb yb (xb-xa)⁻¹).2 :=
  LeanBlsSimd.Msm8.affine_sum_nonsingular ha hb hne

theorem finishValues_point {xa ya xb yb : Field}
    (ha : G1Spec.E.Nonsingular xa ya) (hb : G1Spec.E.Nonsingular xb yb) (hne : xa ≠ xb) :
    WeierstrassCurve.Affine.Point.some _ _ (finishValues_nonsingular ha hb hne) =
      WeierstrassCurve.Affine.Point.some xa ya ha + .some xb yb hb :=
  (LeanBlsSimd.Msm8.affine_sum_point ha hb hne).symm

end LeanBlsSimd.Portable.Msm.Batch
