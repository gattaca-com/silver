import LeanBlsSimd.Msm8.AffineInput

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.Msm8
open EthCryptographySpecs Bls
local instance prepareAffineInhabited0 : Inhabited blst.blst_p1_affine := ⟨Kzg.g1Affine G1.zero⟩

/-- The reset and two pushes in the generated nonempty MSM branch. -/
def prepareStore (store : msm8.store.PointStore)
    (points : Slice blst.blst_p1_affine) (first second : Slice Bool) (windows : Usize) :
    Result msm8.store.PointStore := do
  let n := Slice.len points
  let i2 ← 2#usize * n
  let i4 ← windows * n
  let i5 ← i2 + i4
  let ps ← msm8.store.PointStore.reset store i5
  let ps1 ← msm8.store.PointStore.push_blst ps points first false
  msm8.store.PointStore.push_blst ps1 points second true

theorem prepare_store_calls (store : msm8.store.PointStore)
    (points : Slice blst.blst_p1_affine) (first second : Slice Bool) (windows : Usize)
    (hf : first.val.length = points.val.length) (hs : second.val.length = points.val.length)
    (hp : ∀ j, j < points.val.length → Kzg.G1AffineValid points.val[j]!)
    (hfinite : ∀ j, j < points.val.length → (Kzg.g1ReadAffine points.val[j]!).isInfinity ≠ true)
    (hbound : 2 * (2 * points.val.length + windows.val * points.val.length) < 2 ^ 32) :
    ∃ capacity : Usize, ∃ reset pushed out : msm8.store.PointStore,
      capacity.val = 2 * points.val.length + windows.val * points.val.length ∧
      msm8.store.PointStore.reset store capacity = ok reset ∧
      msm8.store.PointStore.push_blst reset points first false = ok pushed ∧
      msm8.store.PointStore.push_blst pushed points second true = ok out ∧
      reset.len.val = 0 ∧ pushed.len.val = points.val.length ∧
      out.len.val = 2 * points.val.length ∧
      out.rows.val.length = max store.rows.val.length (2 * capacity.val) ∧
      (∀ i, i < points.val.length → RowRep (pointRows out) i
        (transformedPoint points.val[i]! false first.val[i]!)) ∧
      (∀ i, i < points.val.length → RowRep (pointRows out) (points.val.length + i)
        (transformedPoint points.val[i]! true second.val[i]!)) := by
  have hsize := two_pow_32_le_usize
  have hcap : 2 * points.val.length + windows.val * points.val.length <
      2 ^ UScalarTy.Usize.numBits := by omega
  let capacity : Usize := UScalar.ofNatCore _ hcap
  have hcapacity : capacity.val = 2 * points.val.length + windows.val * points.val.length := rfl
  obtain ⟨reset, hreset, hrows, hzero⟩ := pointStore_reset_raw store capacity (by omega)
  have hrlen : reset.rows.val.length = max store.rows.val.length (2 * capacity.val) := by
    rw [hrows]
    simp only [List.length_append, List.length_replicate]
    omega
  have hrzero : reset.len.val = 0 := by rw [hzero]; rfl
  have hrroom : 2 * points.val.length ≤ reset.rows.val.length / 2 := by omega
  have hfirst31 : reset.len.val + points.val.length < 2 ^ 31 := by omega
  have hfirstcap : reset.len.val + points.val.length ≤ reset.rows.val.length / 2 := by omega
  obtain ⟨pushed, hpush, hlen, hrep⟩ := push_blst_rep reset points first false hf hfirst31 hfirstcap hp hfinite
  obtain ⟨pushed', hpush', _, _, hsize1⟩ := push_blst_flat_refines reset points first false hf hfirst31 hfirstcap
  have he := Result.ok.inj (hpush'.symm.trans hpush)
  subst pushed'
  have hpushed : pushed.len.val = points.val.length := by omega
  have hsecond31 : pushed.len.val + points.val.length < 2 ^ 31 := by omega
  have hsecondcap : pushed.len.val + points.val.length ≤ pushed.rows.val.length / 2 := by omega
  obtain ⟨out, hout, hlen2, hrep2⟩ := push_blst_rep pushed points second true hs hsecond31 hsecondcap hp hfinite
  obtain ⟨out', hout', _, _, hsize2⟩ := push_blst_flat_refines pushed points second true hs hsecond31 hsecondcap
  have he := Result.ok.inj (hout'.symm.trans hout)
  subst out'
  refine ⟨capacity, reset, pushed, out, hcapacity, hreset, hpush, hout, hrzero, hpushed, by omega,
    by omega, ?_, ?_⟩
  · intro i hi
    have hframe := push_blst_frame pushed out points second true hs hsecond31 hsecondcap hout i (by omega)
    unfold RowRep
    rw [hframe]
    have h := hrep i hi
    simpa only [hrzero, Nat.zero_add] using h
  · intro i hi
    simpa only [hpushed] using hrep2 i hi

end LeanBlsSimd.Msm8

namespace LeanBlsSimd.Msm8
open EthCryptographySpecs Bls
local instance prepareAffineInhabited1 : Inhabited blst.blst_p1_affine := ⟨Kzg.g1Affine G1.zero⟩

theorem prepareStore_of_calls (store reset pushed out : msm8.store.PointStore)
    (points : Slice blst.blst_p1_affine) (first second : Slice Bool) (windows capacity : Usize)
    (hcapacity : capacity.val = 2 * points.val.length + windows.val * points.val.length)
    (hbound : 2 * (2 * points.val.length + windows.val * points.val.length) < 2 ^ 32)
    (hreset : msm8.store.PointStore.reset store capacity = ok reset)
    (hpush : msm8.store.PointStore.push_blst reset points first false = ok pushed)
    (hout : msm8.store.PointStore.push_blst pushed points second true = ok out) :
    prepareStore store points first second windows = ok out := by
  have hsize := two_pow_32_le_usize
  have h2 : 2 * points.val.length < 2 ^ UScalarTy.Usize.numBits := by omega
  have hw : windows.val * points.val.length < 2 ^ UScalarTy.Usize.numBits := by omega
  let n2 : Usize := UScalar.ofNatCore _ h2
  let wn : Usize := UScalar.ofNatCore _ hw
  have hmul2 : 2#usize * Slice.len points = ok n2 := by
    rw [mul_ok _ _ (by simpa only [Slice.len, Usize.ofNatCore_val_eq] using h2)]
    rfl
  have hmulw : windows * Slice.len points = ok wn := by
    rw [mul_ok _ _ (by simpa only [Slice.len, Usize.ofNatCore_val_eq] using hw)]
    rfl
  have hsum : n2 + wn = ok capacity := by
    rw [add_ok _ _ (by
      change 2 * points.val.length + windows.val * points.val.length < 2 ^ UScalarTy.Usize.numBits
      omega)]
    apply congrArg Result.ok
    apply UScalar.eq_of_val_eq
    exact hcapacity.symm
  simp only [prepareStore, hmul2, hmulw, hsum, bind_tc_ok, hreset, hpush, hout]

theorem prepare_store_correct (store : msm8.store.PointStore)
    (points : Slice blst.blst_p1_affine) (first second : Slice Bool) (windows : Usize)
    (hf : first.val.length = points.val.length) (hs : second.val.length = points.val.length)
    (hp : ∀ j, j < points.val.length → Kzg.G1AffineValid points.val[j]!)
    (hfinite : ∀ j, j < points.val.length → (Kzg.g1ReadAffine points.val[j]!).isInfinity ≠ true)
    (hn : 1 ≤ points.val.length)
    (hbound : 2 * (2 * points.val.length + windows.val * points.val.length) < 2 ^ 32) :
    ∃ out, prepareStore store points first second windows = ok out ∧
      out.len.val = 2 * points.val.length ∧
      out.rows.val.length = max store.rows.val.length
        (2 * (2 * points.val.length + windows.val * points.val.length)) ∧
      2 * points.val.length + windows.val * points.val.length ≤ out.rows.val.length / 2 ∧
      (∀ i, i < points.val.length → RowRep (pointRows out) i
        (transformedPoint points.val[i]! false first.val[i]!)) ∧
      (∀ i, i < points.val.length → RowRep (pointRows out) (points.val.length + i)
        (transformedPoint points.val[i]! true second.val[i]!)) ∧
      (∀ i, i < 2 * points.val.length → 2 * i + 1 < (pointRows out).length) ∧
      1 < (pointRows out).length := by
  obtain ⟨capacity, reset, pushed, out, hcapacity, hreset, hpush, hout, _, _, hlen, hrows, hfirst, hsecond⟩ :=
    prepare_store_calls store points first second windows hf hs hp hfinite hbound
  have hlength : out.rows.val.length = max store.rows.val.length
      (2 * (2 * points.val.length + windows.val * points.val.length)) := by
    simpa only [hcapacity] using hrows
  refine ⟨out, prepareStore_of_calls store reset pushed out points first second windows capacity
    hcapacity hbound hreset hpush hout, hlen, hlength, by omega, hfirst, hsecond, ?_, ?_⟩
  · intro i hi
    rw [pointRows_length]
    omega
  · rw [pointRows_length]
    omega

theorem prepared_signed_reference_bound (out : msm8.store.PointStore) (n : ℕ)
    (hrows : ∀ i, i < 2 * n → 2 * i + 1 < (pointRows out).length)
    (reference : U32) (href : reference.val % 2 ^ 31 < 2 * n) :
    2 * (reference.val % 2 ^ 31) + 1 < (pointRows out).length :=
  hrows _ href

end LeanBlsSimd.Msm8
