import LeanBlsSimd.Portable.Msm.BatchRun
import LeanBlsSimd.Portable.Msm.PointRep
import LeanBlsSimd.Msm8.BatchValues

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Msm.Batch
open QueueRefines BatchedRefines

/-- Both signed inputs refer to initialized finite points. -/
def InputsRep (store : portable.msm.store.PointStore) (jobs : ℕ → Job)
    (values : ℕ → G1Spec.E.Point) (n : ℕ) : Prop :=
  ∀ j < n, Store.PointRep store (pointIndex (jobs j).first) (values (pointIndex (jobs j).first)) ∧
    Store.PointRep store (pointIndex (jobs j).second) (values (pointIndex (jobs j).second))

theorem signed_coordinates (store : portable.msm.store.PointStore)
    (values : ℕ → G1Spec.E.Point) (r : U32)
    (h : Store.PointRep store (pointIndex r) (values (pointIndex r))) :
    G1.Valid ⟨(signedPair (Store.coordinates store) r).1,
      (signedPair (Store.coordinates store) r).2,Fp.one⟩ ∧
    G1.toPoint ⟨(signedPair (Store.coordinates store) r).1,
      (signedPair (Store.coordinates store) r).2,Fp.one⟩ = signedReferenceValue values r := by
  rw [pointIndex_mod] at h
  obtain ⟨_,hv,hp⟩ := h.coordinates
  constructor
  · simpa only [signedPair,decide_eq_true_eq] using
      Msm8.signed_affine_valid _ _ (decide (2^31 ≤ r.val)) hv
  · rw [BatchedRefines.signedReferenceValue_eq_sign]
    simpa only [signedPair,decide_eq_true_eq,hp] using
      Msm8.signed_affine_toPoint _ _ (decide (2^31 ≤ r.val)) hv

theorem jobResult_point (store : portable.msm.store.PointStore) (jobs : ℕ → Job)
    (values : ℕ → G1Spec.E.Point) (n j : ℕ) (hj : j < n)
    (hinputs : InputsRep store jobs values n)
    (hne : differences jobs (Store.coordinates store) j ≠ 0) :
    G1.Valid ⟨(jobResult jobs (Store.coordinates store) j).1,
      (jobResult jobs (Store.coordinates store) j).2,Fp.one⟩ ∧
    G1.toPoint ⟨(jobResult jobs (Store.coordinates store) j).1,
      (jobResult jobs (Store.coordinates store) j).2,Fp.one⟩ =
        signedReferenceValue values (jobs j).first + signedReferenceValue values (jobs j).second := by
  let a := signedPair (Store.coordinates store) (jobs j).first
  let b := signedPair (Store.coordinates store) (jobs j).second
  obtain ⟨hva,hpa⟩ := signed_coordinates store values (jobs j).first (hinputs j hj).1
  obtain ⟨hvb,hpb⟩ := signed_coordinates store values (jobs j).second (hinputs j hj).2
  have ha : G1Spec.E.Nonsingular a.1 a.2 :=
    (WeierstrassCurve.Jacobian.nonsingular_some (W' := G1.curve) a.1 a.2).mp hva
  have hb : G1Spec.E.Nonsingular b.1 b.2 :=
    (WeierstrassCurve.Jacobian.nonsingular_some (W' := G1.curve) b.1 b.2).mp hvb
  have hxab : a.1 ≠ b.1 := by
    intro he
    apply hne
    change b.1-a.1 = 0
    rw [he,sub_self]
  have hn := finishValues_nonsingular ha hb hxab
  have hv : G1.Valid ⟨(jobResult jobs (Store.coordinates store) j).1,
      (jobResult jobs (Store.coordinates store) j).2,Fp.one⟩ :=
    (WeierstrassCurve.Jacobian.nonsingular_some (W' := G1.curve) _ _).mpr hn
  refine ⟨hv,?_⟩
  rw [←hpa,←hpb]
  change WeierstrassCurve.Jacobian.Point.toAffine G1.curve ![_,_,1] =
    WeierstrassCurve.Jacobian.Point.toAffine G1.curve ![a.1,a.2,1] +
      WeierstrassCurve.Jacobian.Point.toAffine G1.curve ![b.1,b.2,1]
  rw [WeierstrassCurve.Jacobian.Point.toAffine_some hv,
    WeierstrassCurve.Jacobian.Point.toAffine_some hva,
    WeierstrassCurve.Jacobian.Point.toAffine_some hvb]
  exact finishValues_point ha hb hxab

/-- Rejection preserves the store; success realizes every queued group sum. -/
theorem run_points [RuntimeFeatures] (adds : portable.msm.pairs.BatchedAdds)
    (store : portable.msm.store.PointStore) (jobs : ℕ → Job)
    (values : ℕ → G1Spec.E.Point)
    (ha : ∀ j < adds.a.val.length, adds.a.val[j]? = some (jobs j).first)
    (hb : ∀ j < adds.a.val.length, adds.b.val[j]? = some (jobs j).second)
    (ho : ∀ j < adds.a.val.length, adds.out.val[j]? = some (jobs j).output)
    (hinputs : InputsRep store jobs values adds.a.val.length)
    (hbound : ∀ j < adds.a.val.length, (jobs j).output.val < store.points.val.length)
    (hind : ReverseIndependent jobs adds.a.val.length)
    (hunique : ∀ j < adds.a.val.length, ∀ k < adds.a.val.length,
      k ≠ j → (jobs k).output.val ≠ (jobs j).output.val) :
    ∃ flag next result, adds.run store = ok (flag,next,result) ∧
      next.a = adds.a ∧ next.b = adds.b ∧ next.out = adds.out ∧
      result.len = store.len ∧ result.points.val.length = store.points.val.length ∧
      (∀ p P, Store.PointRep store p P → (∀ j < adds.a.val.length, (jobs j).output.val ≠ p) →
        Store.PointRep result p P) ∧
      (if flag then ∀ j < adds.a.val.length, Store.PointRep result (jobs j).output.val
        (signedReferenceValue values (jobs j).first + signedReferenceValue values (jobs j).second)
       else result = store) := by
  have hs : ExecutionState store jobs (Store.coordinates store) adds.a.val.length := by
    intro j hj
    obtain ⟨ha,hb⟩ := hinputs j hj
    rw [pointIndex_mod] at ha hb
    exact ⟨ha.coordinates.1,hb.coordinates.1,hbound j hj⟩
  obtain ⟨next,hna,hnb,hno,hr|⟨hnz,hr⟩⟩ := run_cases adds store jobs (Store.coordinates store)
    ha hb ho hs hind
  · exact ⟨false,next,store,hr,hna,hnb,hno,rfl,rfl,fun _ _ h _ => h,rfl⟩
  · refine ⟨true,next,execute jobs (Store.coordinates store) adds.a.val.length store,
      hr,hna,hnb,hno,execute_len ..,execute_length ..,?_,?_⟩
    · intro p P h hne
      exact h.frame (execute_frame _ _ _ _ p hne)
    · intro j hj
      obtain ⟨hv,hp⟩ := jobResult_point store jobs values _ j hj hinputs (hnz j hj)
      exact ⟨_,_,execute_output _ _ _ _ j hj (hbound j hj) (hunique j hj),hv,hp⟩

end LeanBlsSimd.Portable.Msm.Batch
