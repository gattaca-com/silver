import LeanBlsSimd.Portable.G1.Coordinates

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls
open scoped EthLib.Cryptography.Bls.Fp

namespace LeanBlsSimd.Portable.G1
set_option maxRecDepth 4096

structure MixedValues where
  zz : Bls.Fp
  h : Bls.Fp
  r : Bls.Fp

structure MixedRep (raw : portable.g1.MixedTerms) (t : MixedValues) : Prop where
  zz : Kzg.PortableFpRep raw.z1z1 t.zz
  h : Kzg.PortableFpRep raw.h t.h
  r : Kzg.PortableFpRep raw.r t.r

def mixedValues (P : Bls.G1) (x y : Bls.Fp) : MixedValues :=
  let zz := P.z*P.z
  let h := x*zz-P.x
  let r := y*P.z*zz-P.y
  ⟨zz,h,r+r⟩

theorem mixed_new_refines [RuntimeFeatures] (p : portable.g1.G1) (qx qy : portable.fp.Fp)
    (P : Bls.G1) (x y : Bls.Fp) (hp : Coords p P)
    (hx : Kzg.PortableFpRep qx x) (hy : Kzg.PortableFpRep qy y) :
    ∃ out, portable.g1.MixedTerms.new p qx qy = ok out ∧ MixedRep out (mixedValues P x y) := by
  have f := Fp.portable_fp_correct
  obtain ⟨zz,ezz,hzz⟩ := f.square hp.z
  obtain ⟨u,eu,hu⟩ := f.mul hx hzz
  obtain ⟨h,eh,hh⟩ := f.sub hu hp.x
  obtain ⟨yz,eyz,hyz⟩ := f.mul hy hp.z
  obtain ⟨s,es,hs⟩ := f.mul hyz hzz
  obtain ⟨r,er,hr⟩ := f.sub hs hp.y
  obtain ⟨rr,err,hrr⟩ := f.double hr
  refine ⟨⟨zz,h,rr⟩,?_,⟨hzz,hh,hrr⟩⟩
  simp only [portable.g1.MixedTerms.new,ezz,eu,eh,eyz,es,er,err,bind_tc_ok]

def mixedSum (t : MixedValues) (P : Bls.G1) : Bls.G1 :=
  let hh := t.h*t.h
  let i := (hh+hh)+(hh+hh)
  let j := t.h*i
  let v := P.x*i
  let x := t.r*t.r-j-(v+v)
  let y := t.r*(v-x)-(P.y*j+P.y*j)
  let z := (P.z+t.h)*(P.z+t.h)-t.zz-hh
  ⟨x,y,z⟩

theorem mixed_sum_refines [RuntimeFeatures] (p : portable.g1.G1) (raw : portable.g1.MixedTerms)
    (P : Bls.G1) (t : MixedValues) (hp : Coords p P) (ht : MixedRep raw t) :
    ∃ out, portable.g1.MixedTerms.sum raw p = ok out ∧ Coords out (mixedSum t P) := by
  have f := Fp.portable_fp_correct
  obtain ⟨hh,ehh,hhh⟩ := f.square ht.h
  obtain ⟨h2,eh2,hh2⟩ := f.double hhh
  obtain ⟨i,ei,hi⟩ := f.double hh2
  obtain ⟨j,ej,hj⟩ := f.mul ht.h hi
  obtain ⟨v,ev,hv⟩ := f.mul hp.x hi
  obtain ⟨rr,err,hrr⟩ := f.square ht.r
  obtain ⟨x0,ex0,hx0⟩ := f.sub hrr hj
  obtain ⟨v2,ev2,hv2⟩ := f.double hv
  obtain ⟨x,ex,hx⟩ := f.sub hx0 hv2
  obtain ⟨vx,evx,hvx⟩ := f.sub hv hx
  obtain ⟨rvx,ervx,hrvx⟩ := f.mul ht.r hvx
  obtain ⟨yj,eyj,hyj⟩ := f.mul hp.y hj
  obtain ⟨y2,ey2,hy2⟩ := f.double hyj
  obtain ⟨y,ey,hy⟩ := f.sub hrvx hy2
  obtain ⟨zh,ezh,hzh⟩ := f.add hp.z ht.h
  obtain ⟨zh2,ezh2,hzh2⟩ := f.square hzh
  obtain ⟨z0,ez0,hz0⟩ := f.sub hzh2 ht.zz
  obtain ⟨z,ez,hz⟩ := f.sub hz0 hhh
  refine ⟨⟨x,y,z⟩,?_,⟨hx,hy,hz⟩⟩
  simp only [portable.g1.MixedTerms.sum,ehh,eh2,ei,ej,ev,err,ex0,ev2,ex,evx,ervx,
    eyj,ey2,ey,ezh,ezh2,ez0,ez,bind_tc_ok]

private theorem fp_mul_one (x : Bls.Fp) : x*Bls.Fp.one = x :=
  (show ∀ x : ZMod Bls.Fp.modulus, x*1=x from mul_one) x

private theorem terms_affine (P : Bls.G1) (x y : Bls.Fp) :
    Kzg.PortableG1.termsValues P ⟨x,y,Bls.Fp.one⟩ =
      ⟨(mixedValues P x y).zz,Bls.Fp.one,P.x,P.y,(mixedValues P x y).h,(mixedValues P x y).r⟩ := by
  simp only [Kzg.PortableG1.termsValues,mixedValues,fp_mul_one]

private theorem mixed_sum_polynomial (x y z h r : ZMod Bls.Fp.modulus) :
    let i := (h*h+h*h)+(h*h+h*h)
    let j := h*i
    let v := x*i
    let X := r*r-j-(v+v)
    ![X,r*(v-X)-(y*j+y*j),(z+h)*(z+h)-z*z-h*h] =
      let i := (h+h)*(h+h)
      let j := h*i
      let v := x*i
      let X := r*r-j-(v+v)
      ![X,r*(v-X)-(y*j+y*j),((z+1)*(z+1)-z*z-1)*h] := by
  funext k
  fin_cases k <;> dsimp only <;> ring_nf

theorem mixed_sum_eq (P : Bls.G1) (x y : Bls.Fp) :
    mixedSum (mixedValues P x y) P =
      Kzg.PortableG1.sumValues (Kzg.PortableG1.termsValues P ⟨x,y,Bls.Fp.one⟩) P ⟨x,y,Bls.Fp.one⟩ := by
  rw [terms_affine]
  have h := mixed_sum_polynomial P.x P.y P.z (mixedValues P x y).h (mixedValues P x y).r
  have hg := congrArg (fun v : Fin 3 → ZMod Bls.Fp.modulus => (⟨v 0,v 1,v 2⟩ : Bls.G1)) h
  exact hg

def mixedAddValues (P : Bls.G1) (x y : Bls.Fp) : Bls.G1 :=
  if P.z.isZero then ⟨x,y,Bls.Fp.one⟩ else
    let t := mixedValues P x y
    if t.h.isZero then
      if t.r.isZero then Kzg.PortableG1.doubleValues P else Bls.G1.zero
    else mixedSum t P

theorem mixed_add_eq (P : Bls.G1) (x y : Bls.Fp) :
    mixedAddValues P x y = Bls.G1.add P ⟨x,y,Bls.Fp.one⟩ := by
  rw [←Kzg.PortableG1.addValues_eq_add]
  have hs := mixed_sum_eq P x y
  rw [terms_affine] at hs
  simp only [mixedAddValues,Kzg.PortableG1.addValues,terms_affine,
    show Bls.Fp.one.isZero = false from rfl,Bool.false_eq_true,if_false]
  split_ifs <;> first | rfl | exact hs

theorem add_affine_complete_coords [RuntimeFeatures] (p : portable.g1.G1) (qx qy : portable.fp.Fp)
    (P : Bls.G1) (x y : Bls.Fp) (hp : Coords p P)
    (hx : Kzg.PortableFpRep qx x) (hy : Kzg.PortableFpRep qy y) :
    ∃ out, portable.g1.G1.add_affine_complete p qx qy = ok out ∧
      Coords out (Bls.G1.add P ⟨x,y,Bls.Fp.one⟩) := by
  rw [←mixed_add_eq]
  unfold mixedAddValues
  have hz := Fp.portable_fp_correct.is_zero hp.z
  split
  · rename_i hpz
    refine ⟨⟨qx,qy,portable.constants.ONE⟩,?_,⟨hx,hy,Kzg.portableFpRep_one⟩⟩
    simp only [portable.g1.G1.add_affine_complete,portable.g1.G1.is_infinity,hz,
      hpz,bind_tc_ok,if_true,portable.g1.G1.from_affine]
  · rename_i hpz
    obtain ⟨t,ht,htr⟩ := mixed_new_refines p qx qy P x y hp hx hy
    have hh := Fp.portable_fp_correct.is_zero htr.h
    have hr := Fp.portable_fp_correct.is_zero htr.r
    dsimp only
    split
    · rename_i hzero
      split
      · rename_i rzero
        obtain ⟨out,he,hc⟩ := Kzg.PortableG1.doubleValues_refines hp
        refine ⟨out,?_,hc⟩
        simp only [portable.g1.G1.add_affine_complete,portable.g1.G1.is_infinity,hz,
          hpz,bind_tc_ok,Bool.false_eq_true,if_false,ht,hh,hr,hzero,rzero,if_true,he]
      · rename_i rzero
        refine ⟨portable.g1.G1.INFINITY,?_,Kzg.PortableG1.infinity_coords⟩
        simp only [portable.g1.G1.add_affine_complete,portable.g1.G1.is_infinity,hz,
          hpz,bind_tc_ok,Bool.false_eq_true,if_false,ht,hh,hr,hzero,rzero,if_true]
    · rename_i hzero
      obtain ⟨out,he,hc⟩ := mixed_sum_refines p t P (mixedValues P x y) hp htr
      refine ⟨out,?_,hc⟩
      simp only [portable.g1.G1.add_affine_complete,portable.g1.G1.is_infinity,hz,
        hpz,bind_tc_ok,Bool.false_eq_true,if_false,ht,hh,hzero,he]

theorem add_affine_complete_encoded [RuntimeFeatures] (P : Bls.G1) (x y : Bls.Fp) :
    portable.g1.G1.add_affine_complete (encode P) (Kzg.fpEncode x).l (Kzg.fpEncode y).l =
      ok (encode (Bls.G1.add P ⟨x,y,Bls.Fp.one⟩)) := by
  obtain ⟨out,he,hc⟩ := add_affine_complete_coords _ _ _ _ _ _ (encode_coords P)
    (Kzg.portableFpRep_encode x) (Kzg.portableFpRep_encode y)
  rwa [coords_eq_encode hc] at he

end LeanBlsSimd.Portable.G1
