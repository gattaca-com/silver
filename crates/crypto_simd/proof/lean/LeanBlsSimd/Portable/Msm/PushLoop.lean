import LeanBlsSimd.Portable.Msm.Push

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd

namespace LeanBlsSimd.Portable.Msm.Store
local instance : Inhabited blst.blst_p1_affine := ⟨Kzg.g1Affine EthLib.Cryptography.Bls.G1.zero⟩

theorem push_loop_refines [RuntimeFeatures] (s : portable.msm.store.PointStore)
    (points : Slice blst.blst_p1_affine) (negated : Slice Bool) (endomorphism : Bool) (k : Usize)
    (hk : k.val ≤ points.val.length) (hn : negated.val.length = points.val.length)
    (hcap : s.len.val + (points.val.length-k.val) ≤ s.points.val.length)
    (hp : ∀ j < points.val.length, Kzg.G1AffineValid points.val[j]!)
    (hf : ∀ j < points.val.length, (Kzg.g1ReadAffine points.val[j]!).isInfinity ≠ true) :
    ∃ out, portable.msm.store.PointStore.push_blst_loop s.points s.len points negated endomorphism k =
      ok (out.points,out.len) ∧ out.len.val = s.len.val+(points.val.length-k.val) ∧
      out.points.val.length = s.points.val.length ∧
      (∀ j, k.val ≤ j → j < points.val.length → PointRep out (s.len.val+(j-k.val))
        (Msm8.transformedPoint points.val[j]! endomorphism negated.val[j]!)) ∧
      (∀ p < s.len.val, out.points.val[p]? = s.points.val[p]?) := by
  induction hrem : points.val.length-k.val generalizing s k with
  | zero =>
    have he : k.val = points.val.length := by omega
    refine ⟨s,?_,by omega,rfl,?_,fun _ _ => rfl⟩
    · rw [portable.msm.store.PointStore.push_blst_loop,loop.eq_1]
      simp only [portable.msm.store.PointStore.push_blst_loop.body,UScalar.lt_equiv,Slice.len_val,
        he,Nat.lt_irrefl,if_false]
    · intro j hj hlt
      omega
  | succ remaining ih =>
    have hlt : k.val < points.val.length := by omega
    have hslot : s.len.val < s.points.val.length := by omega
    let xy := inputCoordinates points.val[k.val]! endomorphism negated.val[k.val]!
    obtain ⟨next,cursor,hnval,hcursor,hstep⟩ := push_step s points negated endomorphism k
      hlt hn hslot (hp k.val hlt) (hf k.val hlt)
    let mid : portable.msm.store.PointStore := {write s s.len.val xy.1 xy.2 with len := next}
    have hmidlen : mid.len.val = s.len.val+1 := hnval
    have hmidsize : mid.points.val.length = s.points.val.length := by simp [mid,write]
    have hcap' : mid.len.val+(points.val.length-cursor.val) ≤ mid.points.val.length := by omega
    obtain ⟨out,hloop,hlen,hsize,hpoints,hframe⟩ := ih mid cursor (by omega) hcap' (by omega)
    refine ⟨out,?_,by omega,hsize.trans hmidsize,?_,?_⟩
    · rw [portable.msm.store.PointStore.push_blst_loop,loop.eq_1]
      simp only [hstep]
      exact hloop
    · intro j hj hjlt
      by_cases he : j = k.val
      · subst j
        obtain ⟨hv,hp⟩ := inputCoordinates_point points.val[k.val]! endomorphism negated.val[k.val]!
          (hp k.val hlt) (hf k.val hlt)
        have hrep : PointRep mid s.len.val
            (Msm8.transformedPoint points.val[k.val]! endomorphism negated.val[k.val]!) :=
          ⟨xy.1,xy.2,write_holds s s.len.val xy.1 xy.2 hslot,hv,hp⟩
        simpa only [Nat.sub_self,Nat.add_zero] using hrep.frame (hframe s.len.val (by omega))
      · have hpos : s.len.val+(j-k.val) = mid.len.val+(j-cursor.val) := by omega
        rw [hpos]
        exact hpoints j (by omega) hjlt
    · intro p hp
      rw [hframe p (by omega)]
      exact write_other s s.len.val p xy.1 xy.2 (by omega)

/-- Push only initializes its reserved suffix, preserving all earlier point slots. -/
theorem push_blst_refines [RuntimeFeatures] (s : portable.msm.store.PointStore)
    (points : Slice blst.blst_p1_affine) (negated : Slice Bool) (endomorphism : Bool)
    (hn : negated.val.length = points.val.length)
    (hcap : s.len.val+points.val.length ≤ s.points.val.length)
    (hp : ∀ j < points.val.length, Kzg.G1AffineValid points.val[j]!)
    (hf : ∀ j < points.val.length, (Kzg.g1ReadAffine points.val[j]!).isInfinity ≠ true) :
    ∃ out, s.push_blst points negated endomorphism = ok out ∧
      out.len.val = s.len.val+points.val.length ∧ out.points.val.length = s.points.val.length ∧
      (∀ j < points.val.length, PointRep out (s.len.val+j)
        (Msm8.transformedPoint points.val[j]! endomorphism negated.val[j]!)) ∧
      (∀ p < s.len.val, out.points.val[p]? = s.points.val[p]?) := by
  have hcount : Slice.len negated = Slice.len points := by
    apply UScalar.eq_of_val_eq
    exact hn
  have hb : s.len.val + (Slice.len points).val < 2^UScalarTy.Usize.numBits :=
    lt_of_le_of_lt hcap (QueueRefines.vec_length_bound s.points)
  obtain ⟨out,he,hlen,hsize,hpoints,hframe⟩ := push_loop_refines s points negated endomorphism
    0#usize (by simp) hn (by simpa using hcap) hp hf
  refine ⟨out,?_,by simpa using hlen,hsize,?_,hframe⟩
  · simp only [portable.msm.store.PointStore.push_blst,hcount,massert,if_true,bind_tc_ok]
    rw [add_ok _ _ hb]
    simp only [bind_tc_ok,UScalar.le_equiv,UScalar.ofNatCore_val_eq,Slice.len_val,
      hcap,if_true]
    rw [he]
    rfl
  · intro j hj
    simpa only [UScalar.ofNatCore_val_eq,Nat.sub_zero] using hpoints j (Nat.zero_le _) hj

end LeanBlsSimd.Portable.Msm.Store
