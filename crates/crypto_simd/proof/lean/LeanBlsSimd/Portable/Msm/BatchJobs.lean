import LeanBlsSimd.Portable.Msm.BatchGroup

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Msm.Batch
open QueueRefines BatchedRefines

def jobAt (jobs : List Job) (i : ℕ) : Job := jobs[i]?.getD ⟨0#u32,0#u32,0#u32⟩

theorem jobAt_get (jobs : List Job) (i : ℕ) (hi : i < jobs.length) : jobAt jobs i = jobs[i] := by
  simp only [jobAt,List.getElem?_eq_getElem hi,Option.getD_some]

theorem run_jobs_correct [RuntimeFeatures] (adds : portable.msm.pairs.BatchedAdds)
    (store : portable.msm.store.PointStore) (jobs : List Job) (values : ℕ → G1Spec.E.Point)
    (ha : adds.a.val = jobs.map Job.first) (hb : adds.b.val = jobs.map Job.second)
    (ho : adds.out.val = jobs.map Job.output) (hind : jobs.Pairwise JobIndependent)
    (hinputs : ∀ job ∈ jobs,
      Store.PointRep store (pointIndex job.first) (values (pointIndex job.first)) ∧
      Store.PointRep store (pointIndex job.second) (values (pointIndex job.second)))
    (hbound : ∀ job ∈ jobs, job.output.val < store.points.val.length) :
    ∃ flag next result, adds.run store = ok (flag,next,result) ∧
      next.a = adds.a ∧ next.b = adds.b ∧ next.out = adds.out ∧
      result.len = store.len ∧ result.points.val.length = store.points.val.length ∧
      (∀ p P, Store.PointRep store p P → (∀ job ∈ jobs, p ≠ job.output.val) →
        Store.PointRep result p P) ∧
      (if flag then ∀ job ∈ jobs, Store.PointRep result job.output.val
        (signedReferenceValue values job.first + signedReferenceValue values job.second)
       else result = store) := by
  have hl : adds.a.val.length = jobs.length := by rw [ha,List.length_map]
  have hia : ∀ j < adds.a.val.length, adds.a.val[j]? = some (jobAt jobs j).first := by
    intro j hj
    rw [hl] at hj
    simp only [ha,List.getElem?_map,List.getElem?_eq_getElem hj,Option.map_some,jobAt_get jobs j hj]
  have hib : ∀ j < adds.a.val.length, adds.b.val[j]? = some (jobAt jobs j).second := by
    intro j hj
    rw [hl] at hj
    simp only [hb,List.getElem?_map,List.getElem?_eq_getElem hj,Option.map_some,jobAt_get jobs j hj]
  have hio : ∀ j < adds.a.val.length, adds.out.val[j]? = some (jobAt jobs j).output := by
    intro j hj
    rw [hl] at hj
    simp only [ho,List.getElem?_map,List.getElem?_eq_getElem hj,Option.map_some,jobAt_get jobs j hj]
  have hrep : InputsRep store (jobAt jobs) values adds.a.val.length := by
    intro j hj
    rw [hl] at hj
    rw [jobAt_get jobs j hj]
    exact hinputs _ (List.getElem_mem hj)
  have hbounds : ∀ j < adds.a.val.length, (jobAt jobs j).output.val < store.points.val.length := by
    intro j hj
    rw [hl] at hj
    rw [jobAt_get jobs j hj]
    exact hbound _ (List.getElem_mem hj)
  have hreverse : ReverseIndependent (jobAt jobs) adds.a.val.length := by
    intro j hj k hk
    rw [hl] at hj
    rw [jobAt_get jobs j hj,jobAt_get jobs k (by omega)]
    have hi := jobs_independent_get jobs hind j k hj (by omega) (by omega)
    simpa only [pointIndex_mod] using And.intro hi.2.1 hi.2.2.1
  have huniq : ∀ j < adds.a.val.length, ∀ k < adds.a.val.length,
      k ≠ j → (jobAt jobs k).output.val ≠ (jobAt jobs j).output.val := by
    intro j hj k hk hne
    rw [hl] at hj hk
    rw [jobAt_get jobs j hj,jobAt_get jobs k hk]
    exact (jobs_independent_get jobs hind k j hk hj hne).1
  obtain ⟨flag,next,result,he,hna,hnb,hno,hlen,hsize,hframe,hout⟩ :=
    run_points adds store (jobAt jobs) values hia hib hio hrep hbounds hreverse huniq
  refine ⟨flag,next,result,he,hna,hnb,hno,hlen,hsize,?_,?_⟩
  · intro p P hp hne
    apply hframe p P hp
    intro j hj
    rw [hl] at hj
    rw [jobAt_get jobs j hj]
    exact (hne _ (List.getElem_mem hj)).symm
  · cases flag with
    | false => exact hout
    | true =>
      intro job hj
      obtain ⟨j,hjb,rfl⟩ := List.mem_iff_getElem.mp hj
      have h := hout j (by omega)
      simpa only [jobAt_get jobs j hjb] using h

/-- Preserve live inputs and install all newly produced values after a successful batch. -/
theorem jobs_points_updated (jobs : List Job) (values : ℕ → G1Spec.E.Point)
    (hind : jobs.Pairwise JobIndependent) (before after : portable.msm.store.PointStore)
    (houtputs : ∀ job ∈ jobs, Store.PointRep after job.output.val
      (signedReferenceValue values job.first + signedReferenceValue values job.second))
    (hframe : ∀ p P, Store.PointRep before p P → (∀ job ∈ jobs, p ≠ job.output.val) →
      Store.PointRep after p P) :
    (∀ job ∈ jobs, Store.PointRep after job.output.val (updatedValues jobs values job.output.val)) ∧
    (∀ p, Store.PointRep before p (values p) → Store.PointRep after p (updatedValues jobs values p)) := by
  constructor
  · intro job hj
    rw [updatedValues_job jobs values hind job hj]
    exact houtputs job hj
  · intro p hp
    by_cases h : ∃ job ∈ jobs, job.output.val = p
    · obtain ⟨job,hj,rfl⟩ := h
      rw [updatedValues_job jobs values hind job hj]
      exact houtputs job hj
    · have hne : ∀ job ∈ jobs, p ≠ job.output.val := by
        intro job hj he
        exact h ⟨job,hj,he.symm⟩
      rw [updatedValues_frame jobs values p hne]
      exact hframe p (values p) hp hne

end LeanBlsSimd.Portable.Msm.Batch
