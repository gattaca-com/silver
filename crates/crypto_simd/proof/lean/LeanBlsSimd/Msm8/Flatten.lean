import LeanBlsSimd.Msm8.WindowEntry

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.WindowSums

theorem sum_list_indices {A G : Type} [Inhabited A] [AddCommMonoid G]
    (xs : List A) (f : A → G) :
    (∑ j ∈ Finset.range xs.length, f xs[j]!) = (xs.map f).sum := by
  have he : List.ofFn (fun j : Fin xs.length => f xs[j.val]!) = xs.map f := by
    apply List.ext_getElem
    · simp
    · intro i hi hi'
      simp
  rw [← he, List.sum_ofFn, Fin.sum_univ_eq_sum_range (fun j => f xs[j]!) xs.length]

theorem sum_list_padded {A G : Type} [Inhabited A] [AddCommMonoid G]
    (xs : List A) (f : A → G) (count : ℕ) (hc : xs.length ≤ count) :
    (∑ j ∈ Finset.range count, if j < xs.length then f xs[j]! else 0) = (xs.map f).sum := by
  have he := Finset.sum_subset (f := fun j => if j < xs.length then f xs[j]! else 0)
    (Finset.range_mono hc) (by
      intro j _ hj
      simp only [Finset.mem_range, not_lt] at hj
      simp [show ¬j < xs.length by omega])
  rw [← he]
  calc
    _ = ∑ j ∈ Finset.range xs.length, f xs[j]! := by
      apply Finset.sum_congr rfl
      intro j hj
      simp only [Finset.mem_range] at hj
      simp only [hj, if_true]
    _ = _ := sum_list_indices xs f

theorem sum_range_blocks {G : Type} [AddCommMonoid G] (f : ℕ → G) (groups : ℕ) :
    (∑ g ∈ Finset.range groups, ∑ l : Fin 8, f (g * 8 + l.val)) =
      ∑ w ∈ Finset.range (groups * 8), f w := by
  induction groups with
  | zero => simp
  | succ n ih =>
    rw [Finset.sum_range_succ, ih, Fin.sum_univ_eq_sum_range (fun l => f (n * 8 + l)) 8]
    simpa only [Nat.succ_mul] using (Finset.sum_range_add f (n * 8) 8).symm

theorem weighted_groups_flatten {G : Type} [AddCommMonoid G]
    (f : ℕ → G) (bits groups : ℕ) :
    (∑ l : Fin 8, 2 ^ (l.val * bits) •
      ∑ g ∈ Finset.range groups, 2 ^ (g * (8 * bits)) • f (g * 8 + l.val)) =
      ∑ w ∈ Finset.range (groups * 8), 2 ^ (w * bits) • f w := by
  simp_rw [Finset.smul_sum, smul_smul, ← pow_add]
  have hexp (l g : ℕ) : l * bits + g * (8 * bits) = (g * 8 + l) * bits := by ring
  simp_rw [hexp]
  rw [Finset.sum_comm]
  exact sum_range_blocks (fun w => 2 ^ (w * bits) • f w) groups

theorem weighted_groups_trim {G : Type} [AddCommMonoid G]
    (f : ℕ → G) (bits windows : ℕ) (hw : 1 ≤ windows)
    (hz : ∀ w, windows ≤ w → f w = 0) :
    (∑ l : Fin 8, 2 ^ (l.val * bits) •
      ∑ g ∈ Finset.range ((windows - 1) / 8 + 1),
        2 ^ (g * (8 * bits)) • f (g * 8 + l.val)) =
      ∑ w ∈ Finset.range windows, 2 ^ (w * bits) • f w := by
  rw [weighted_groups_flatten]
  symm
  apply Finset.sum_subset (Finset.range_mono (show windows ≤ ((windows - 1) / 8 + 1) * 8 by omega))
  intro w _ hwin
  have he := hz w (by simp only [Finset.mem_range] at hwin; omega)
  simp only [he, smul_zero]

end LeanBlsSimd.WindowSums
namespace LeanBlsSimd.WindowSums
open BucketsRefines EthCryptographySpecs Bls

def signedPoint (points : ℕ → G1Spec.E.Point) (reference : U32) : G1Spec.E.Point :=
  if 2 ^ 31 ≤ reference.val then -points (reference.val % 2 ^ 31)
    else points (reference.val % 2 ^ 31)

def bucketGroup (points : ℕ → G1Spec.E.Point) (references : List U32) : G1Spec.E.Point :=
  (references.map (signedPoint points)).sum

def windowBucketWeight (state : msm8.buckets.Buckets) (contents : BucketLists)
    (points : ℕ → G1Spec.E.Point) (window : ℕ) : G1Spec.E.Point :=
  ∑ b ∈ Finset.range (2 ^ (state.window_bits.val - 1)),
    (b + 1) • bucketGroup points (windowReferences state contents window (b + 1))

theorem packed_entryPoint (state : msm8.buckets.Buckets) (base capacity : ℕ → ℕ)
    (contents : BucketLists)
    (hp : Packed state (state.windows.val * 2 ^ (state.window_bits.val - 1)) base capacity contents)
    (points : ℕ → G1Spec.E.Point) (group bucket cursor : ℕ) (l : Fin 8)
    (hb : 1 ≤ bucket) (hbm : bucket ≤ 2 ^ (state.window_bits.val - 1)) :
    entryPoint state points group bucket cursor l =
      if cursor < (windowReferences state contents (group * 8 + l.val) bucket).length then
        signedPoint points (windowReferences state contents (group * 8 + l.val) bucket)[cursor]! else 0 := by
  unfold entryPoint
  rw [packed_bucketLength state base capacity contents hp _ bucket hb hbm]
  split
  · rename_i hj
    rw [packed_referenceAt state base capacity contents hp _ bucket cursor hb hbm, if_pos hj]
    simp only [signedPoint, clearSign_val]
  · rfl

theorem packed_entry_sum (state : msm8.buckets.Buckets) (base capacity : ℕ → ℕ)
    (contents : BucketLists)
    (hp : Packed state (state.windows.val * 2 ^ (state.window_bits.val - 1)) base capacity contents)
    (points : ℕ → G1Spec.E.Point) (group bucket : ℕ) (l : Fin 8)
    (hb : 1 ≤ bucket) (hbm : bucket ≤ 2 ^ (state.window_bits.val - 1)) :
    (∑ j ∈ Finset.range (longestModel state group bucket).val, entryPoint state points group bucket j l) =
      bucketGroup points (windowReferences state contents (group * 8 + l.val) bucket) := by
  simp_rw [packed_entryPoint state base capacity contents hp points group bucket _ l hb hbm]
  apply sum_list_padded
  rw [← packed_bucketLength state base capacity contents hp _ bucket hb hbm]
  exact longest_ge_lane state group bucket l

theorem windowWeight_entryPoint (state : msm8.buckets.Buckets) (base capacity : ℕ → ℕ)
    (contents : BucketLists)
    (hp : Packed state (state.windows.val * 2 ^ (state.window_bits.val - 1)) base capacity contents)
    (points : ℕ → G1Spec.E.Point) (group : ℕ) (l : Fin 8) :
    windowWeight state (entryPoint state points) group l =
      windowBucketWeight state contents points (group * 8 + l.val) := by
  unfold windowWeight windowBucketWeight
  apply Finset.sum_congr rfl
  intro b hb
  simp only [Finset.mem_range] at hb
  rw [packed_entry_sum state base capacity contents hp points group (b + 1) l (by omega) (by omega)]

theorem windowBucketWeight_zero (state : msm8.buckets.Buckets) (contents : BucketLists)
    (points : ℕ → G1Spec.E.Point) (window : ℕ) (hw : state.windows.val ≤ window) :
    windowBucketWeight state contents points window = 0 := by
  simp [windowBucketWeight, windowReferences, show ¬window < state.windows.val by omega, bucketGroup]

theorem packed_windowBucketWeight (state : msm8.buckets.Buckets) (base capacity : ℕ → ℕ)
    (contents : BucketLists)
    (hp : Packed state (state.windows.val * 2 ^ (state.window_bits.val - 1)) base capacity contents)
    (points : ℕ → G1Spec.E.Point) (window : ℕ) (hw : window < state.windows.val) :
    windowBucketWeight state contents points window =
      ∑ b ∈ Finset.range (2 ^ (state.window_bits.val - 1)),
        (b + 1) • bucketGroup points (bucketSlice state (listIndex state.window_bits.val window (b + 1))) := by
  unfold windowBucketWeight
  apply Finset.sum_congr rfl
  intro b hb
  simp only [Finset.mem_range] at hb
  rw [packed_recovers state _ base capacity contents hp _ (listIndex_lt _ _ _ _ hw (by omega) (by omega))]
  simp only [windowReferences, hw, if_true]

theorem packed_nested_sum_flatten (state : msm8.buckets.Buckets) (base capacity : ℕ → ℕ)
    (contents : BucketLists)
    (hp : Packed state (state.windows.val * 2 ^ (state.window_bits.val - 1)) base capacity contents)
    (points : ℕ → G1Spec.E.Point) (hw : 1 ≤ state.windows.val) :
    (∑ l : Fin 8, 2 ^ (l.val * state.window_bits.val) •
      ∑ g ∈ Finset.range ((state.windows.val - 1) / 8 + 1),
        2 ^ (g * (8 * state.window_bits.val)) • windowWeight state (entryPoint state points) g l) =
    ∑ window ∈ Finset.range state.windows.val, 2 ^ (window * state.window_bits.val) •
      ∑ b ∈ Finset.range (2 ^ (state.window_bits.val - 1)),
        (b + 1) • bucketGroup points (bucketSlice state (listIndex state.window_bits.val window (b + 1))) := by
  simp_rw [windowWeight_entryPoint state base capacity contents hp points]
  rw [weighted_groups_trim _ _ _ hw (windowBucketWeight_zero state contents points)]
  apply Finset.sum_congr rfl
  intro window hwindow
  rw [packed_windowBucketWeight state base capacity contents hp points window (Finset.mem_range.mp hwindow)]

end LeanBlsSimd.WindowSums
namespace LeanBlsSimd.WindowSums
open BucketsRefines EthCryptographySpecs Bls

theorem packed_present_reference (state : msm8.buckets.Buckets) (base capacity : ℕ → ℕ)
    (contents : BucketLists)
    (hp : Packed state (state.windows.val * 2 ^ (state.window_bits.val - 1)) base capacity contents)
    (window bucket cursor : ℕ) (hb : 1 ≤ bucket) (hbm : bucket ≤ 2 ^ (state.window_bits.val - 1))
    (hj : cursor < (bucketLength state window bucket).val) :
    ∃ i, i < state.windows.val * 2 ^ (state.window_bits.val - 1) ∧
      referenceAt state window bucket cursor ∈ contents i := by
  have hw : window < state.windows.val := by
    by_contra h
    simp only [bucketLength, h, if_false, UScalar.ofNatCore_val_eq] at hj
    omega
  refine ⟨listIndex state.window_bits.val window bucket, listIndex_lt _ _ _ _ hw hb hbm, ?_⟩
  rw [packed_bucketLength state base capacity contents hp window bucket hb hbm] at hj
  rw [packed_referenceAt state base capacity contents hp window bucket cursor hb hbm, if_pos hj]
  simp only [windowReferences, hw, if_true] at hj ⊢
  rw [getElem!_pos (contents (listIndex state.window_bits.val window bucket)) cursor hj]
  exact List.getElem_mem hj

theorem shape_group_bound (state : msm8.buckets.Buckets) (hshape : BucketShape state) :
    (state.windows.val - 1) / 8 * 8 + 7 < 2 ^ UScalarTy.Usize.numBits := by
  have hp : 0 < 2 ^ (state.window_bits.val - 1) := by positivity
  have hw : state.windows.val < 2 ^ 32 := by
    have h := hshape.total_bound
    nlinarith
  have := two_pow_32_le_usize
  omega

theorem packed_sum_correct (state : msm8.buckets.Buckets) (store : msm8.store.PointStore)
    (base capacity : ℕ → ℕ) (contents : BucketLists)
    (hp : Packed state (state.windows.val * 2 ^ (state.window_bits.val - 1)) base capacity contents)
    (hshape : BucketShape state) (hwin : 1 ≤ state.windows.val)
    (points : ℕ → G1Spec.E.Point) (hzero : 1 < store.rows.val.length)
    (href : ∀ i, i < state.windows.val * 2 ^ (state.window_bits.val - 1) →
      ∀ r ∈ contents i, 2 * (r.val % 2 ^ 31) + 1 < store.rows.val.length)
    (hrow : ∀ i, i < state.windows.val * 2 ^ (state.window_bits.val - 1) →
      ∀ r ∈ contents i, Msm8.RowRep (pointRows store) (r.val % 2 ^ 31) (points (r.val % 2 ^ 31))) :
    ∃ out, msm8.buckets.Buckets.sum state store = ok (toG1x8 out) ∧
      out.PointRep 0
        (∑ window ∈ Finset.range state.windows.val, 2 ^ (window * state.window_bits.val) •
          ∑ b ∈ Finset.range (2 ^ (state.window_bits.val - 1)),
            (b + 1) • bucketGroup points
              (bucketSlice state (listIndex state.window_bits.val window (b + 1)))) := by
  obtain ⟨out, hout, hrep⟩ := concrete_sum_correct state store hshape hwin (shape_group_bound state hshape)
    (fun group _ => packed_groupLoads state store base capacity contents hp hzero href group)
    (entryPoint state points) (by
      intro group _ bucket hb hbm cursor _ lane
      apply loadedEntry_rep state store points group bucket cursor lane
      intro hj
      obtain ⟨i, hi, hr⟩ := packed_present_reference state base capacity contents hp
        (group * 8 + lane.val) bucket cursor hb hbm hj
      simpa only [clearSign_val] using hrow i hi _ hr)
  refine ⟨out, hout, ?_⟩
  rw [packed_nested_sum_flatten state base capacity contents hp points hwin] at hrep
  exact hrep

end LeanBlsSimd.WindowSums
