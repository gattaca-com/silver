import LeanBlsSimd.Kzg.PortableG1
import LeanBlsSimd.Portable.Fp.Inverse

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls
open WeierstrassCurve.Jacobian
open scoped EthLib.Cryptography.Bls.Fp

namespace LeanBlsSimd.Portable.G1
set_option maxRecDepth 4096

abbrev Coords := Kzg.PortableG1.Coords

def encode (P : Bls.G1) : portable.g1.G1 :=
  ⟨(Kzg.fpEncode P.x).l,(Kzg.fpEncode P.y).l,(Kzg.fpEncode P.z).l⟩

theorem encode_coords (P : Bls.G1) : Coords (encode P) P :=
  ⟨Kzg.portableFpRep_encode _,Kzg.portableFpRep_encode _,Kzg.portableFpRep_encode _⟩

theorem coords_eq_encode {p : portable.g1.G1} {P : Bls.G1} (h : Coords p P) :
    p = encode P := by
  rcases p with ⟨x,y,z⟩
  have hx := Fp.rep_eq_encode h.x
  have hy := Fp.rep_eq_encode h.y
  have hz := Fp.rep_eq_encode h.z
  simp only [encode,←hx,←hy,←hz]

private theorem curve_negY (P : Fin 3 → ZMod Bls.Fp.modulus) :
    Bls.G1.curve.negY P = -P 1 := by simp [negY,Bls.G1.curve]

private theorem double_rep_polynomial (x y z : ZMod Bls.Fp.modulus) :
    let a := x*x
    let b := y*y
    let c := b*b
    let d := ((x+b)*(x+b)-a-c)+((x+b)*(x+b)-a-c)
    let e := a+a+a
    let X := e*e-(d+d)
    ![X,e*(d-X)-((c+c)+(c+c)+((c+c)+(c+c))),y*z+y*z] =
      Bls.G1.curve.dblXYZ ![x,y,z] := by
  dsimp only
  funext i
  fin_cases i <;>
    simp only [dblXYZ,dblY,curve_negY,negDblY,dblX,dblU_eq,dblZ,curve_negY,
      Matrix.cons_val_zero,Matrix.cons_val_one,Matrix.cons_val_two,Matrix.head_cons,Matrix.tail_cons,
      show Bls.G1.curve.a₁ = 0 from rfl,show Bls.G1.curve.a₂ = 0 from rfl,
      show Bls.G1.curve.a₄ = 0 from rfl] <;> ring

theorem double_values_rep (P : Bls.G1) :
    Bls.G1.rep (Kzg.PortableG1.doubleValues P) = Bls.G1.curve.dblXYZ (Bls.G1.rep P) :=
  double_rep_polynomial P.x P.y P.z

theorem double_values_valid {P : Bls.G1} (h : Bls.G1.Valid P) :
    Bls.G1.Valid (Kzg.PortableG1.doubleValues P) := by
  rw [Bls.G1.Valid,double_values_rep,←WeierstrassCurve.Jacobian.add_self]
  exact nonsingular_add h h

theorem double_values_point {P : Bls.G1} (h : Bls.G1.Valid P) :
    Bls.G1.toPoint (Kzg.PortableG1.doubleValues P) = Bls.G1.toPoint P+Bls.G1.toPoint P := by
  rw [Bls.G1.toPoint,double_values_rep,←WeierstrassCurve.Jacobian.add_self]
  exact Point.toAffine_add h h

theorem double_encoded [RuntimeFeatures] (P : Bls.G1) :
    portable.g1.G1.double (encode P) = ok (encode (Kzg.PortableG1.doubleValues P)) := by
  obtain ⟨out,he,hc⟩ := Kzg.PortableG1.doubleValues_refines Fp.portable_fp_correct (encode_coords P)
  rwa [coords_eq_encode hc] at he

theorem add_complete_encoded [RuntimeFeatures] (P Q : Bls.G1) :
    portable.g1.G1.add_complete (encode P) (encode Q) = ok (encode (Bls.G1.add P Q)) := by
  obtain ⟨out,he,hc⟩ := Kzg.PortableG1.add_complete_coords Fp.portable_fp_correct
    (encode_coords P) (encode_coords Q)
  rwa [coords_eq_encode hc] at he

theorem neg_encoded [RuntimeFeatures] (P : Bls.G1) :
    portable.g1.G1.neg (encode P) = ok (encode (Bls.G1.neg P)) := by
  obtain ⟨out,he,hc⟩ := Kzg.PortableG1.neg_coords Fp.portable_fp_correct (encode_coords P)
  rwa [coords_eq_encode hc] at he

theorem from_affine_encoded (x y : Bls.Fp) :
    portable.g1.G1.from_affine (Kzg.fpEncode x).l (Kzg.fpEncode y).l =
      ok (encode ⟨x,y,Bls.Fp.one⟩) := by
  have hone := Fp.rep_eq_encode Kzg.portableFpRep_one
  simp only [portable.g1.G1.from_affine,encode,hone]

end LeanBlsSimd.Portable.G1
