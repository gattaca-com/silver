import LeanBlsSimd.Portable.G1.Mixed
import LeanBlsSimd.Portable.Msm.BatchGroup

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls
open scoped EthLib.Cryptography.Bls.Fp

namespace LeanBlsSimd.Portable.Msm.Group
set_option maxRecDepth 4096

/-- Canonical projective coordinates representing a valid affine group point. -/
def PointRep (p : portable.g1.G1) (P : G1Spec.E.Point) : Prop :=
  ∃ q : Bls.G1, p = G1.encode q ∧ Bls.G1.Valid q ∧ Bls.G1.toPoint q = P

theorem infinity_rep : PointRep portable.g1.G1.INFINITY 0 :=
  ⟨Bls.G1.zero,G1.coords_eq_encode Kzg.PortableG1.infinity_coords,Bls.G1.valid_zero,Bls.G1.toPoint_zero⟩

theorem add_complete [RuntimeFeatures] (p q : portable.g1.G1) (P Q : G1Spec.E.Point)
    (hp : PointRep p P) (hq : PointRep q Q) :
    ∃ out, p.add_complete q = ok out ∧ PointRep out (P+Q) := by
  obtain ⟨a,rfl,ha,hpa⟩ := hp
  obtain ⟨b,rfl,hb,hpb⟩ := hq
  refine ⟨G1.encode (Bls.G1.add a b),G1.add_complete_encoded a b,_,rfl,Bls.G1.valid_add ha hb,?_⟩
  rw [Bls.G1.toPoint_add ha hb,hpa,hpb]

theorem double [RuntimeFeatures] (p : portable.g1.G1) (P : G1Spec.E.Point) (hp : PointRep p P) :
    ∃ out, p.double = ok out ∧ PointRep out (P+P) := by
  obtain ⟨a,rfl,ha,hpa⟩ := hp
  refine ⟨G1.encode (Kzg.PortableG1.doubleValues a),G1.double_encoded a,_,rfl,
    G1.double_values_valid ha,?_⟩
  rw [G1.double_values_point ha,hpa]

theorem signed_bind {α : Type} (store : portable.msm.store.PointStore)
    (r : U32) (x y : ZMod Bls.Fp.modulus)
    (hc : Store.Holds store (r.val % 2^31) x y)
    (f : portable.fp.Fp × portable.fp.Fp → Result α) :
    (store.signed r >>= f) =
      f ((Kzg.fpEncode x).l,(Kzg.fpEncode (if 2^31 ≤ r.val then -y else y)).l) := by
  exact congrArg (fun value => value >>= f) (Store.signed_refines store r x y hc)

theorem add_signed_encoded [RuntimeFeatures] (store : portable.msm.store.PointStore)
    (r : U32) (a : Bls.G1) (x y : ZMod Bls.Fp.modulus)
    (hc : Store.Holds store (r.val % 2^31) x y) :
    (do let (x,y) ← store.signed r; (G1.encode a).add_affine_complete x y) =
      ok (G1.encode (Bls.G1.add a ⟨x,(if 2^31 ≤ r.val then -y else y : ZMod Bls.Fp.modulus),Bls.Fp.one⟩)) := by
  exact (signed_bind store r x y hc (fun (x,y) => (G1.encode a).add_affine_complete x y)).trans
    (G1.add_affine_complete_encoded a x (show ZMod Bls.Fp.modulus from if 2^31 ≤ r.val then -y else y))

theorem add_reference [RuntimeFeatures] (store : portable.msm.store.PointStore)
    (values : ℕ → G1Spec.E.Point) (r : U32) (p : portable.g1.G1) (P : G1Spec.E.Point)
    (hp : PointRep p P)
    (hr : Store.PointRep store (QueueRefines.pointIndex r) (values (QueueRefines.pointIndex r))) :
    ∃ out, (do let (x,y) ← store.signed r; p.add_affine_complete x y) = ok out ∧
      PointRep out (P+BatchedRefines.signedReferenceValue values r) := by
  obtain ⟨a,rfl,ha,hpa⟩ := hp
  obtain ⟨hv,hq⟩ := Batch.signed_coordinates store values r hr
  have hc := hr.coordinates.1
  rw [BatchedRefines.pointIndex_mod] at hc
  let q : Bls.G1 := ⟨(Batch.signedPair (Store.coordinates store) r).1,
    (Batch.signedPair (Store.coordinates store) r).2,Bls.Fp.one⟩
  refine ⟨G1.encode (Bls.G1.add a q),?_,_,rfl,Bls.G1.valid_add ha hv,?_⟩
  · exact add_signed_encoded store r a _ _ hc
  · rw [Bls.G1.toPoint_add ha hv,hpa,hq]

end LeanBlsSimd.Portable.Msm.Group
