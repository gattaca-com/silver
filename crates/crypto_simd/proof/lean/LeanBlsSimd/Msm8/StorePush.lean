import LeanBlsSimd.Msm8.StoreGather

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section


namespace LeanBlsSimd

theorem storeRows_length (rows : List Limbs) (indices : Vector ℕ 8)
    (xs ys : Vector M512 8) : (storeRows rows indices xs ys).length = rows.length := by
  have h : ∀ (lanes : List (Fin 8)) (rows : List Limbs),
      (lanes.foldl (fun rows j => (rows.set (2 * indices[j]) xs[j]).set
        (2 * indices[j] + 1) ys[j]) rows).length = rows.length := by
    intro lanes
    induction lanes with
    | nil => intro rows; rfl
    | cons j lanes ih =>
      intro rows
      simp only [List.foldl_cons, ih, List.length_set]
  exact h _ _

@[simp] theorem pointRows_length (s : msm8.store.PointStore) :
    (pointRows s).length = s.rows.val.length := by simp [pointRows]

@[simp] theorem blstPointWords_length (points : Slice blst.blst_p1_affine) :
    (blstPointWords points).length = points.val.length := by simp [blstPointWords]

def pushRowsModel (points : List (Vector UInt64 6 × Vector UInt64 6)) (negated : List Bool)
    (endomorphism : Bool) (fromBlst beta : Fp8) (rows : List Limbs) (base offset : ℕ) : List Limbs :=
  if offset < points.length then
    let count := min 8 (points.length - offset)
    let gathered := gatherBatch points negated base offset count emptyGathered
    let converted := convertedBatch gathered fromBlst beta endomorphism
    pushRowsModel points negated endomorphism fromBlst beta
      (storeRows rows gathered.indices (transpose8 converted.1.limbs) (transpose8 converted.2.limbs))
      (base + count) (offset + count)
  else rows
termination_by points.length - offset
decreasing_by omega

theorem push_loop_refines (points : Slice blst.blst_p1_affine) (negated : Slice Bool)
    (endomorphism : Bool) (fromBlst beta : Fp8)
    (hn : negated.val.length = points.val.length) (hp : points.val.length < 2 ^ 31)
    (s : msm8.store.PointStore) (offset : Usize) (ho : offset.val ≤ points.val.length)
    (h31 : s.len.val + (points.val.length - offset.val) < 2 ^ 31)
    (hcap : s.len.val + (points.val.length - offset.val) ≤ s.rows.val.length / 2) :
    ∃ out, msm8.store.PointStore.push_blst_loop0 s.rows s.len points negated endomorphism
        (toFp8 fromBlst) (toFp8 beta) offset = ok (out.rows, out.len) ∧
      pointRows out = pushRowsModel (blstPointWords points) negated.val endomorphism fromBlst beta
        (pointRows s) s.len.val offset.val ∧
      out.len.val = s.len.val + (points.val.length - offset.val) ∧
      out.rows.val.length = s.rows.val.length := by
  induction hd : points.val.length - offset.val using Nat.strong_induction_on generalizing s offset with
  | h d ih =>
    by_cases hlt : offset.val < points.val.length
    · have hcpos : 0 < min 8 (points.val.length - offset.val) := by omega
      have hcsmall : min 8 (points.val.length - offset.val) < 2 ^ UScalarTy.Usize.numBits := by
        have := two_pow_32_le_usize
        omega
      let count : Usize := UScalar.ofNatCore (min 8 (points.val.length - offset.val)) hcsmall
      have hc : count.val = min 8 (points.val.length - offset.val) := by simp [count]
      have hs : s.len.val + points.val.length < 2 ^ UScalarTy.Usize.numBits := by
        have := two_pow_32_le_usize
        omega
      have h32 : s.len.val + count.val ≤ 2 ^ 32 := by omega
      have hcap' : s.len.val + count.val ≤ s.rows.val.length / 2 := by omega
      obtain ⟨middle, next, hnext, hlen, hbody, hrows⟩ := push_batch_body s offset count
        points negated endomorphism fromBlst beta hlt hc hn hs h32 hcap'
      have hlength : middle.rows.val.length = s.rows.val.length := by
        have hh := congrArg List.length hrows
        simpa only [pointRows_length, storeRows_length] using hh
      have hnextle : next.val ≤ points.val.length := by omega
      have hnext31 : middle.len.val + (points.val.length - next.val) < 2 ^ 31 := by omega
      have hnextcap : middle.len.val + (points.val.length - next.val) ≤ middle.rows.val.length / 2 := by
        rw [hlength]; omega
      obtain ⟨out, hout, hmodel, hfinalLen, hfinalSize⟩ :=
        ih (points.val.length - next.val) (by omega) middle next hnextle hnext31 hnextcap rfl
      refine ⟨out, ?_, ?_, by omega, hfinalSize.trans hlength⟩
      · unfold msm8.store.PointStore.push_blst_loop0
        change loop (fun p => msm8.store.PointStore.push_blst_loop0.body points negated
          endomorphism (toFp8 fromBlst) (toFp8 beta) p.1 p.2.1 p.2.2)
          (s.rows, s.len, offset) = _
        rw [loop.eq_1, hbody]
        exact hout
      · rw [hmodel, hrows]
        conv_rhs => rw [pushRowsModel]
        simp only [blstPointWords_length, hlt, if_true]
        rw [hlen, hnext, hc]
    · have heq : offset.val = points.val.length := by omega
      refine ⟨s, ?_, ?_, by omega, rfl⟩
      · unfold msm8.store.PointStore.push_blst_loop0
        rw [loop.eq_1]
        simp [msm8.store.PointStore.push_blst_loop0.body, UScalar.lt_equiv, heq]
      · rw [pushRowsModel]
        simp [heq]


def fromBlstFactor : Fp8 :=
  Fp8.splat_limbs (ofArray ofU64 constants.TWO_POW_448_MOD_P)

def endomorphismFactor : Fp8 :=
  Fp8.splat_limbs (ofArray ofU64 constants.BETA_MONT)

theorem push_blst_refines (s : msm8.store.PointStore)
    (points : Slice blst.blst_p1_affine) (negated : Slice Bool) (endomorphism : Bool)
    (hn : negated.val.length = points.val.length)
    (h31 : s.len.val + points.val.length < 2 ^ 31)
    (hcap : s.len.val + points.val.length ≤ s.rows.val.length / 2) :
    ∃ out, msm8.store.PointStore.push_blst s points negated endomorphism = ok out ∧
      pointRows out = pushRowsModel (blstPointWords points) negated.val endomorphism
        fromBlstFactor endomorphismFactor (pointRows s) s.len.val 0 ∧
      out.len.val = s.len.val + points.val.length ∧ out.rows.val.length = s.rows.val.length := by
  obtain ⟨out, hloop, hrows, hlen, hsize⟩ := push_loop_refines points negated endomorphism
    fromBlstFactor endomorphismFactor hn (by omega) s 0#usize (by simp) (by simpa using h31)
    (by simpa using hcap)
  refine ⟨out, ?_, hrows, by simpa using hlen, hsize⟩
  have hsign : Slice.len negated = Slice.len points := by
    apply UScalar.eq_of_val_eq
    simpa using hn
  have hadd : s.len.val + (Slice.len points).val < 2 ^ UScalarTy.Usize.numBits := by
    have := two_pow_32_le_usize
    simp only [Slice.len_val]
    change s.len.val + points.val.length < _
    omega
  simp only [msm8.store.PointStore.push_blst, hsign, massert, if_true, bind_tc_ok]
  rw [add_ok _ _ hadd]
  simp only [bind_tc_ok, pointStore_capacity_refines, UScalar.le_equiv,
    UScalar.ofNatCore_val_eq, Slice.len_val]
  have hcap' : s.len.val + points.length ≤ s.rows.val.length / 2 := hcap
  simp only [hcap', if_true, bind_tc_ok, Fp8.splat_limbs_refines]
  change (do
    let result ← msm8.store.PointStore.push_blst_loop0 s.rows s.len points negated
      endomorphism (toFp8 fromBlstFactor) (toFp8 endomorphismFactor) 0#usize
    ok ({ rows := result.1, len := result.2 } : msm8.store.PointStore)) = _
  rw [hloop]
  rfl

end LeanBlsSimd
