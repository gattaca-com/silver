import LeanBlsSimd.Msm8.BatchSemantics

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.BatchedRefines
open EthCryptographySpecs Bls Msm8 QueueRefines

theorem signedReferenceValue_eq_sign (values : ℕ → G1Spec.E.Point) (r : U32) :
    signedReferenceValue values r=
      if 2^31≤r.val then -values (r.val%2^31) else values (r.val%2^31) := by
  have hr : r.val<2^32 := by scalar_tac
  have hsign : r.bv.getLsbD 31=decide (2^31≤r.val) := by
    change r.val.testBit 31=decide (2^31≤r.val)
    rw [Nat.testBit_eq_decide_div_mod_eq]
    rw [decide_eq_decide]
    omega
  simp only [signedReferenceValue,pointIndex_mod,hsign,decide_eq_true_eq]

theorem jobs_output_injective (jobs : List Job) (hind : jobs.Pairwise JobIndependent)
    (a b : Job) (ha : a∈jobs) (hb : b∈jobs) (heq : a.output.val=b.output.val) : a=b := by
  obtain ⟨i,hi,rfl⟩ := List.mem_iff_getElem.mp ha
  obtain ⟨j,hj,rfl⟩ := List.mem_iff_getElem.mp hb
  by_cases h : i=j
  · subst j; rfl
  · exact False.elim ((jobs_independent_get jobs hind i j hi hj h).1 heq)

noncomputable def updatedValues (jobs : List Job) (values : ℕ → G1Spec.E.Point) (p : ℕ) : G1Spec.E.Point :=
  if h : ∃job∈jobs,job.output.val=p then
    signedReferenceValue values (Classical.choose h).first+
      signedReferenceValue values (Classical.choose h).second
  else values p

theorem updatedValues_job (jobs : List Job) (values : ℕ → G1Spec.E.Point)
    (hind : jobs.Pairwise JobIndependent) (job : Job) (hjob : job∈jobs) :
    updatedValues jobs values job.output.val=
      signedReferenceValue values job.first+signedReferenceValue values job.second := by
  have h : ∃j∈jobs,j.output.val=job.output.val := ⟨job,hjob,rfl⟩
  rw [updatedValues,dif_pos h]
  have he := jobs_output_injective jobs hind (Classical.choose h) job
    (Classical.choose_spec h).1 hjob (Classical.choose_spec h).2
  rw [he]

theorem updatedValues_frame (jobs : List Job) (values : ℕ → G1Spec.E.Point) (p : ℕ)
    (hne : ∀job∈jobs,p≠job.output.val) : updatedValues jobs values p=values p := by
  rw [updatedValues,dif_neg]
  rintro ⟨job,hjob,hp⟩
  exact hne job hjob hp.symm

theorem jobs_rows_updated (jobs : List Job) (values : ℕ → G1Spec.E.Point)
    (hind : jobs.Pairwise JobIndependent) (before after : msm8.store.PointStore)
    (houtputs : ∀job∈jobs,RowRep (pointRows after) job.output.val
      (signedReferenceValue values job.first+signedReferenceValue values job.second))
    (hframe : ∀p P,RowRep (pointRows before) p P → (∀job∈jobs,p≠job.output.val) →
      RowRep (pointRows after) p P) :
    (∀job∈jobs,RowRep (pointRows after) job.output.val (updatedValues jobs values job.output.val)) ∧
    (∀p,RowRep (pointRows before) p (values p) → RowRep (pointRows after) p (updatedValues jobs values p)) := by
  constructor
  · intro job hj
    rw [updatedValues_job jobs values hind job hj]
    exact houtputs job hj
  · intro p hp
    by_cases h : ∃job∈jobs,job.output.val=p
    · obtain ⟨job,hj,rfl⟩ := h
      rw [updatedValues_job jobs values hind job hj]
      exact houtputs job hj
    · have hne : ∀job∈jobs,p≠job.output.val := by
        intro job hj he
        exact h ⟨job,hj,he.symm⟩
      rw [updatedValues_frame jobs values p hne]
      exact hframe p (values p) hp hne

theorem pointIndex_output (job : Job) (h : job.output.val<2^31) :
    pointIndex job.output=job.output.val := by rw [pointIndex_mod,Nat.mod_eq_of_lt h]

end LeanBlsSimd.BatchedRefines
