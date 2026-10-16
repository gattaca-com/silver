import LeanBlsSimd.Kzg.G1Arithmetic
import EthCryptographySpecs.Proofs.Bls.G1Msm

open EthCryptographySpecs Bls

namespace LeanBlsSimd.Kzg

private def Related (p q : G1) : Prop :=
  G1Valid p ∧ G1Valid q ∧ G1.toPoint p = G1.toPoint q

private theorem related_zero : Related G1.zero G1.zero :=
  ⟨g1Valid_zero, g1Valid_zero, rfl⟩

private theorem related_add {p q p' q' : G1} (hp : Related p p')
    (hq : Related q q') : Related (G1.add p q) (G1.add p' q') := by
  refine ⟨g1Valid_add hp.1 hq.1, g1Valid_add hp.2.1 hq.2.1, ?_⟩
  rw [g1_toPoint_add hp.1 hq.1, g1_toPoint_add hp.2.1 hq.2.1, hp.2.2, hq.2.2]

private theorem related_double {p q : G1} (h : Related p q) :
    Related (G1.double p) (G1.double q) := by
  refine ⟨g1Valid_double h.1, g1Valid_double h.2.1, ?_⟩
  rw [g1_toPoint_double h.1, g1_toPoint_double h.2.1, h.2.2]

private def BucketsRelated (a b : Array G1) : Prop :=
  a.size = 1 <<< 8 ∧ b.size = 1 <<< 8 ∧
    ∀ j, j < 1 <<< 8 → Related a[j]! b[j]!

private theorem buckets_zero :
    BucketsRelated (Array.replicate (1 <<< 8) G1.zero)
      (Array.replicate (1 <<< 8) G1.zero) := by
  refine ⟨by simp, by simp, ?_⟩
  intro j hj
  rw [getElem!_pos _ j (by simpa using hj), Array.getElem_replicate]
  exact related_zero

private theorem buckets_set {a b : Array G1} (h : BucketsRelated a b)
    {i : Nat} (hi : i < 1 <<< 8) {p q : G1} (hpq : Related p q) :
    BucketsRelated (a.setIfInBounds i p) (b.setIfInBounds i q) := by
  refine ⟨by simpa using h.1, by simpa using h.2.1, ?_⟩
  intro j hj
  have hja : j < a.size := by simpa only [h.1] using hj
  have hjb : j < b.size := by simpa only [h.2.1] using hj
  rw [getElem!_pos _ j (by simpa using hja), getElem!_pos _ j (by simpa using hjb)]
  by_cases hij : i = j
  · subst i
    rw [Array.getElem_setIfInBounds_self, Array.getElem_setIfInBounds_self]
    exact hpq
  · rw [Array.getElem_setIfInBounds_ne hja hij, Array.getElem_setIfInBounds_ne hjb hij]
    simpa only [getElem!_pos a j hja, getElem!_pos b j hjb] using h.2.2 j hj

private theorem buckets_related (points points' : Array G1) (scalars : Array Fr)
    (n k : Nat) (hp : ∀ j, j < n → Related points[j]! points'[j]!) :
    BucketsRelated (G1.msmBuckets points scalars n k)
      (G1.msmBuckets points' scalars n k) := by
  unfold G1.msmBuckets
  apply List.foldl_rel buckets_zero
  intro j hj a b hab
  have hjn : j < n := by have := List.mem_range'_1.mp hj; omega
  split
  · have hwlt : G1.windowVal scalars[j]! k < 1 <<< 8 := by
      have := Nat.and_le_right (n := scalars[j]!.val >>> (k * 8)) (m := 1 <<< 8 - 1)
      unfold G1.windowVal
      omega
    exact buckets_set hab hwlt (related_add (hab.2.2 _ hwlt) (hp j hjn))
  · exact hab

private theorem running_related {a b : Array G1} (h : BucketsRelated a b) :
    Related (G1.msmRunning a).1 (G1.msmRunning b).1 := by
  have hr :
      Related (G1.msmRunning a).1 (G1.msmRunning b).1 ∧
      Related (G1.msmRunning a).2 (G1.msmRunning b).2 := by
    unfold G1.msmRunning
    apply List.foldl_rel (r := fun x y : MProd G1 G1 =>
      Related x.1 y.1 ∧ Related x.2 y.2) ⟨related_zero, related_zero⟩
    intro j hj x y hxy
    have hjn : j < 1 <<< 8 - 1 := by have := List.mem_range'_1.mp hj; omega
    have hb := h.2.2 (1 <<< 8 - 1 - j) (by omega)
    exact ⟨related_add hxy.1 (related_add hxy.2 hb), related_add hxy.2 hb⟩
  exact hr.1

private theorem window_related (points points' : Array G1) (scalars : Array Fr)
    (n nW : Nat) (hp : ∀ j, j < n → Related points[j]! points'[j]!)
    {a b : G1} (hab : Related a b) (kk : Nat) :
    Related (G1.msmWindowStep points scalars n nW a kk)
      (G1.msmWindowStep points' scalars n nW b kk) := by
  have hr := running_related (buckets_related points points' scalars n (nW - 1 - kk) hp)
  unfold G1.msmWindowStep
  split
  · apply related_add (List.foldl_rel hab (fun _ _ _ _ h => related_double h)) hr
  · exact related_add hab hr

private theorem msm_related (points points' : Array G1) (scalars : Array Fr)
    (hsize : points.size = points'.size)
    (hp : ∀ j, j < (if points.size ≤ scalars.size then points.size else scalars.size) →
      Related points[j]! points'[j]!) : Related (G1.msm points scalars) (G1.msm points' scalars) := by
  rw [G1.msm_eq_msmModel, G1.msm_eq_msmModel]
  unfold G1.msmModel
  rw [← hsize]
  dsimp only
  by_cases h0 : (if points.size ≤ scalars.size then points.size else scalars.size) = 0
  · simp only [h0, if_true]
    exact related_zero
  · simp only [h0, if_false]
    by_cases h1 : G1.msmMaxBits scalars
        (if points.size ≤ scalars.size then points.size else scalars.size) = 0
    · simp only [h1, if_true]
      exact related_zero
    · simp only [h1, if_false]
      apply List.foldl_rel related_zero
      intro kk _ a b hab
      exact window_related points points' scalars _ _ hp hab kk

private def normalize (p : G1) : G1 := if p.isInfinity then G1.zero else p

private theorem normalize_valid {p : G1} (hp : G1Valid p) : G1.Valid (normalize p) := by
  unfold normalize
  split
  · exact G1.valid_zero
  · exact g1_groupValid_of_noninfinity hp (by assumption)

private theorem normalize_related {p : G1} (hp : G1Valid p) : Related p (normalize p) := by
  unfold normalize
  split
  · rename_i hz
    exact ⟨hp, g1Valid_zero, (g1_toPoint_of_infinity hz).trans G1.toPoint_zero.symm⟩
  · exact ⟨hp, hp, rfl⟩

theorem g1_msm_spec (points : Array G1) (scalars : Array Fr)
    (hval : ∀ j, j < (if points.size ≤ scalars.size then points.size else scalars.size) →
      G1Valid points[j]!) :
    G1Valid (G1.msm points scalars) ∧
      G1.toPoint (G1.msm points scalars) =
        ∑ j ∈ Finset.range (if points.size ≤ scalars.size then points.size else scalars.size),
          scalars[j]!.val • G1.toPoint points[j]! := by
  let n := if points.size ≤ scalars.size then points.size else scalars.size
  have hn : n ≤ points.size := by dsimp [n]; split <;> omega
  have hget : ∀ j, j < n → (points.map normalize)[j]! = normalize points[j]! := by
    intro j hj
    have hjp := Nat.lt_of_lt_of_le hj hn
    rw [getElem!_pos _ j (by simpa using hjp), Array.getElem_map,
      getElem!_pos points j hjp]
  have hrel := msm_related points (points.map normalize) scalars (by simp)
    (fun j hj => by rw [hget j hj]; exact normalize_related (hval j hj))
  have hnval : ∀ j, j < (if (points.map normalize).size ≤ scalars.size then
      (points.map normalize).size else scalars.size) →
      G1.Valid (points.map normalize)[j]! := by
    intro j hj
    have hjn : j < n := by simpa only [Array.size_map] using hj
    rw [hget j hjn]
    exact normalize_valid (hval j hjn)
  obtain ⟨_, hspec⟩ := G1.toPoint_msm (points.map normalize) scalars hnval
  refine ⟨hrel.1, ?_⟩
  rw [hrel.2.2, hspec, Array.size_map]
  apply Finset.sum_congr rfl
  intro j hj
  have hjn : j < n := Finset.mem_range.mp hj
  rw [hget j hjn, ← (normalize_related (hval j hjn)).2.2]

theorem g1Valid_msm (points : Array G1) (scalars : Array Fr)
    (hval : ∀ j, j < (if points.size ≤ scalars.size then points.size else scalars.size) →
      G1Valid points[j]!) : G1Valid (G1.msm points scalars) :=
  (g1_msm_spec points scalars hval).1

theorem g1_msm_congr (points points' : Array G1) (scalars : Array Fr)
    (hsize : points.size = points'.size)
    (hval : ∀ j, j < (if points.size ≤ scalars.size then points.size else scalars.size) →
      G1Valid points[j]!)
    (hinf : ∀ j, j < (if points.size ≤ scalars.size then points.size else scalars.size) →
      points[j]!.isInfinity = points'[j]!.isInfinity)
    (haff : ∀ j, j < (if points.size ≤ scalars.size then points.size else scalars.size) →
      points[j]!.toAffine = points'[j]!.toAffine) :
    G1Valid (G1.msm points scalars) ∧ G1Valid (G1.msm points' scalars) ∧
      (G1.msm points scalars).isInfinity = (G1.msm points' scalars).isInfinity ∧
      (G1.msm points scalars).toAffine = (G1.msm points' scalars).toAffine := by
  have hrel := msm_related points points' scalars hsize (fun j hj =>
    ⟨hval j hj, g1Valid_transport (hinf j hj).symm (haff j hj).symm (hval j hj),
      g1_toPoint_eq_of_matches (hinf j hj) (haff j hj)⟩)
  exact ⟨hrel.1, hrel.2.1, (g1_toPoint_eq_iff hrel.1 hrel.2.1).mp hrel.2.2⟩

theorem g1_msm_rep (raw : Array silver_crypto_simd.blst.blst_p1) (points : Array G1)
    (scalars : Array Fr) (hsize : raw.size = points.size)
    (hrep : ∀ j (hj : j < raw.size), G1Rep raw[j] points[j]!)
    (hval : ∀ j, j < points.size → G1Valid points[j]!) :
    G1Valid (G1.msm points scalars) ∧
      G1Rep (g1Jacobian (G1.msm (raw.map g1ReadJacobian) scalars))
        (G1.msm points scalars) := by
  have hn : (if points.size ≤ scalars.size then points.size else scalars.size) ≤
      points.size := by split <;> omega
  have hget : ∀ j (hj : j < raw.size),
      (raw.map g1ReadJacobian)[j]! = g1ReadJacobian raw[j] := by
    intro j hj
    rw [getElem!_pos _ j (by simpa using hj), Array.getElem_map]
  obtain ⟨hp, hr, hinf, haff⟩ := g1_msm_congr points (raw.map g1ReadJacobian) scalars
    (by simpa using hsize.symm)
    (fun j hj => hval j (Nat.lt_of_lt_of_le hj hn))
    (fun j hj => by
      have hjr : j < raw.size := by have := Nat.lt_of_lt_of_le hj hn; omega
      rw [hget j hjr]
      exact (hrep j hjr).2.1.symm)
    (fun j hj => by
      have hjr : j < raw.size := by have := Nat.lt_of_lt_of_le hj hn; omega
      rw [hget j hjr]
      exact (hrep j hjr).2.2.symm)
  refine ⟨hp, g1Jacobian_reduced _, ?_, ?_⟩
  · simpa only [g1ReadJacobian_g1Jacobian] using hinf.symm
  · simpa only [g1ReadJacobian_g1Jacobian] using haff.symm

end LeanBlsSimd.Kzg
