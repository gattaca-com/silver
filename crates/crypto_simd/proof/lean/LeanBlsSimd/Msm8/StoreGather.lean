import LeanBlsSimd.Msm8.StoreLifecycle

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section


namespace LeanBlsSimd

def natIndex (n : ℕ) : U32 := ⟨BitVec.ofNat 32 n⟩

theorem cast_natIndex (n : Usize) : UScalar.cast .U32 n = natIndex n.val := by
  apply UScalar.eq_of_val_eq
  rw [UScalar.cast_val_eq]
  rfl

def batchSource (offset count lane : ℕ) : ℕ := offset + min lane (count - 1)

def blstPointWords (points : Slice blst.blst_p1_affine) :
    List (Vector UInt64 6 × Vector UInt64 6) :=
  points.val.map fun p => (ofArray ofU64 p.x.l, ofArray ofU64 p.y.l)

structure GatheredBatch where
  xs : Vector Limbs 8
  ys : Vector Limbs 8
  indices : Vector ℕ 8
  negate : U8

def encodeGathered (b : GatheredBatch) :=
  (toArray (n := 8#usize) (fun v => toArray (n := 8#usize) toU64 v) b.xs,
   toArray (n := 8#usize) (fun v => toArray (n := 8#usize) toU64 v) b.ys,
   toArray (n := 8#usize) natIndex b.indices, b.negate)

def gatherStep (points : List (Vector UInt64 6 × Vector UInt64 6)) (negated : List Bool)
    (base offset count : ℕ) (b : GatheredBatch) (j : Fin 8) : GatheredBatch :=
  let k := batchSource offset count j
  { xs := b.xs.set j (unpack52 points[k]!.1)
    ys := b.ys.set j (unpack52 points[k]!.2)
    indices := b.indices.set j (base + k - offset)
    negate := b.negate ||| ⟨(UScalar.cast_fromBool .U8 negated[k]!).bv.shiftLeft j⟩ }

theorem batchSource_lt (offset count lane n : ℕ) (hc : 0 < count) (hb : offset + count ≤ n) :
    batchSource offset count lane < n := by
  unfold batchSource
  have := Nat.min_le_right lane (count - 1)
  omega

theorem slice_index_eq {α : Type} (s : Slice α) (i : Usize) (hi : i.val < s.val.length) :
    Slice.index_usize s i = ok s.val[i.val] := by
  simp [Slice.index_usize, hi]


theorem push_gather_body (i offset count lane : Usize)
    (points : Slice blst.blst_p1_affine) (negated : Slice Bool)
    (b : GatheredBatch) (j : Fin 8) (hj : lane.val = j.val)
    (hc : 0 < count.val) (hb : offset.val + count.val ≤ points.val.length)
    (hn : negated.val.length = points.val.length)
    (hs : i.val + points.val.length < 2 ^ UScalarTy.Usize.numBits) :
    ∃ next, next.val = j.val + 1 ∧
      msm8.store.PointStore.push_blst_loop0_loop0.body i points negated offset count
        (encodeGathered b).1 (encodeGathered b).2.1 (encodeGathered b).2.2.1
        b.negate lane =
      ok (cont ((encodeGathered (gatherStep (blstPointWords points) negated.val
        i.val offset.val count.val b j)).1,
        (encodeGathered (gatherStep (blstPointWords points) negated.val
        i.val offset.val count.val b j)).2.1,
        (encodeGathered (gatherStep (blstPointWords points) negated.val
        i.val offset.val count.val b j)).2.2.1,
        (gatherStep (blstPointWords points) negated.val i.val offset.val count.val b j).negate,
        next)) := by
  have hl : lane.val < (8#usize).val := by simp [hj]
  have hk := batchSource_lt offset.val count.val lane.val points.val.length hc hb
  let k : Usize := UScalar.ofNatCore (batchSource offset.val count.val lane.val) (by omega)
  have hkv : k.val = batchSource offset.val count.val lane.val := by simp [k]
  have hkat : offset.val ≤ k.val := by simp [hkv, batchSource]
  have hchoice : (if lane < count then offset + lane else do
        let t ← offset + count
        t - 1#usize) = ok k := by
    by_cases hlc : lane.val < count.val
    · simp only [UScalar.lt_equiv, hlc, if_true]
      rw [add_ok offset lane (by omega)]
      congr 1
      apply UScalar.eq_of_val_eq
      simp [k, batchSource, Nat.min_eq_left (show lane.val ≤ count.val - 1 by omega)]
    · simp only [UScalar.lt_equiv, hlc, if_false]
      rw [add_ok offset count (by omega)]
      simp only [bind_tc_ok]
      rw [sub_ok _ 1#usize (by simp; omega)]
      congr 1
      apply UScalar.eq_of_val_eq
      simp [k, batchSource, Nat.min_eq_right (show count.val - 1 ≤ lane.val by omega)]
      omega
  have hadd : lane.val + (1#usize).val < 2 ^ UScalarTy.Usize.numBits := by
    have := two_pow_32_le_usize
    change lane.val + 1 < _
    omega
  let next : Usize := UScalar.ofNatCore (lane.val + 1) hadd
  have hnxt : lane + 1#usize = ok next := by rw [add_ok _ _ hadd]; rfl
  let ik : Usize := UScalar.ofNatCore (i.val + k.val) (by omega)
  have hik : i + k = ok ik := by rw [add_ok i k (by omega)]
  let ix : Usize := UScalar.ofNatCore (i.val + k.val - offset.val)
    (by have := Nat.sub_le (i.val+k.val) offset.val; omega)
  have hix : ik - offset = ok ix := by
    rw [sub_ok ik offset (by simp [ik]; omega)]
    rfl
  refine ⟨next, by simp [next, hj], ?_⟩
  simp only [msm8.store.PointStore.push_blst_loop0_loop0.body, fp8.LANES,
    UScalar.lt_equiv, hl, if_true]
  simp only [UScalar.lt_equiv] at hchoice
  rw [hchoice]
  simp only [bind_tc_ok, slice_index_eq points k (by omega), unpack52_refines,
    update_eq _ lane _ hl, slice_index_eq negated k (by omega), lift,
    shiftLeft_ok (ty := .U8) _ lane (by change lane.val < 8; exact hl), hik, hix,
    cast_natIndex, hnxt]
  have hpoint : (blstPointWords points)[k.val]! =
      (ofArray ofU64 points.val[k.val].x.l, ofArray ofU64 points.val[k.val].y.l) := by
    simp [blstPointWords, show k.val < points.val.length by omega]
    exact ⟨rfl, rfl⟩
  have hsign : negated.val[k.val]! = negated.val[k.val] := by
    simp [show k.val < negated.val.length by omega]
  simp only [encodeGathered, gatherStep]
  have hkmodel : batchSource offset.val count.val j.val = k.val := by simp [hkv, hj]
  simp only [hkmodel, hpoint, hsign]
  apply congrArg (fun p => ok (cont p))
  apply Prod.ext
  · exact toArray_set_of_eq (n := 8#usize) (fun v => toArray (n := 8#usize) toU64 v)
      b.xs rfl lane j.val j.isLt _ _ hj rfl
  · apply Prod.ext
    · exact toArray_set_of_eq (n := 8#usize) (fun v => toArray (n := 8#usize) toU64 v)
        b.ys rfl lane j.val j.isLt _ _ hj rfl
    · apply Prod.ext
      · apply toArray_set_of_eq (n := 8#usize) natIndex b.indices rfl lane j.val j.isLt _ _ hj
        simp [ix]
      · simp [hj]


def gatherBatch (points : List (Vector UInt64 6 × Vector UInt64 6)) (negated : List Bool)
    (base offset count : ℕ) (b : GatheredBatch) : GatheredBatch :=
  (List.finRange 8).foldl (gatherStep points negated base offset count) b

theorem push_gather_refines (i offset count : Usize)
    (points : Slice blst.blst_p1_affine) (negated : Slice Bool) (b : GatheredBatch)
    (hc : 0 < count.val) (hb : offset.val + count.val ≤ points.val.length)
    (hn : negated.val.length = points.val.length)
    (hs : i.val + points.val.length < 2 ^ UScalarTy.Usize.numBits) :
    msm8.store.PointStore.push_blst_loop0_loop0 i points negated offset count
      (encodeGathered b).1 (encodeGathered b).2.1 (encodeGathered b).2.2.1 b.negate 0#usize =
      ok (encodeGathered (gatherBatch (blstPointWords points) negated.val i.val offset.val count.val b)) := by
  unfold msm8.store.PointStore.push_blst_loop0_loop0
  rw [loop_up_inv (n := 8)
    (fun p => msm8.store.PointStore.push_blst_loop0_loop0.body i points negated offset count
      p.1 p.2.1 p.2.2.1 p.2.2.2.1 p.2.2.2.2)
    (fun (b : GatheredBatch) (c : Usize) => ((encodeGathered b).1,
      (encodeGathered b).2.1, (encodeGathered b).2.2.1, b.negate, c))
    (gatherStep (blstPointWords points) negated.val i.val offset.val count.val)
    encodeGathered (fun _ => True) (fun _ _ _ => trivial)
    (fun b c h _ => by
      simp [msm8.store.PointStore.push_blst_loop0_loop0.body, fp8.LANES, UScalar.lt_equiv, h]
      rfl)
    (fun b c j h _ => push_gather_body i offset count c points negated b j h hc hb hn hs)
    b 0#usize (by simp) trivial]
  rfl


theorem gatherBatch_xs (points : List (Vector UInt64 6 × Vector UInt64 6))
    (negated : List Bool) (base offset count : ℕ) (b : GatheredBatch) :
    (gatherBatch points negated base offset count b).xs =
      Vector.ofFn (fun j : Fin 8 => unpack52 points[batchSource offset count j]!.1) := by
  have h : ∀ (lanes : List (Fin 8)) (b : GatheredBatch),
      (lanes.foldl (gatherStep points negated base offset count) b).xs =
        lanes.foldl (fun v j => v.set j (unpack52 points[batchSource offset count j]!.1)) b.xs := by
    intro lanes
    induction lanes with
    | nil => intro b; rfl
    | cons j lanes ih =>
      intro b
      simpa only [List.foldl_cons, gatherStep] using
        ih (gatherStep points negated base offset count b j)
  rw [gatherBatch, h, foldl_set_ofFn]

theorem gatherBatch_ys (points : List (Vector UInt64 6 × Vector UInt64 6))
    (negated : List Bool) (base offset count : ℕ) (b : GatheredBatch) :
    (gatherBatch points negated base offset count b).ys =
      Vector.ofFn (fun j : Fin 8 => unpack52 points[batchSource offset count j]!.2) := by
  have h : ∀ (lanes : List (Fin 8)) (b : GatheredBatch),
      (lanes.foldl (gatherStep points negated base offset count) b).ys =
        lanes.foldl (fun v j => v.set j (unpack52 points[batchSource offset count j]!.2)) b.ys := by
    intro lanes
    induction lanes with
    | nil => intro b; rfl
    | cons j lanes ih =>
      intro b
      simpa only [List.foldl_cons, gatherStep] using
        ih (gatherStep points negated base offset count b j)
  rw [gatherBatch, h, foldl_set_ofFn]

theorem gatherBatch_indices (points : List (Vector UInt64 6 × Vector UInt64 6))
    (negated : List Bool) (base offset count : ℕ) (b : GatheredBatch) :
    (gatherBatch points negated base offset count b).indices =
      Vector.ofFn (fun j : Fin 8 => base + batchSource offset count j - offset) := by
  have h : ∀ (lanes : List (Fin 8)) (b : GatheredBatch),
      (lanes.foldl (gatherStep points negated base offset count) b).indices =
        lanes.foldl (fun v j => v.set j (base + batchSource offset count j - offset)) b.indices := by
    intro lanes
    induction lanes with
    | nil => intro b; rfl
    | cons j lanes ih =>
      intro b
      simpa only [List.foldl_cons, gatherStep] using
        ih (gatherStep points negated base offset count b j)
  rw [gatherBatch, h, foldl_set_ofFn]



def emptyGathered : GatheredBatch :=
  ⟨Vector.replicate 8 (Vector.replicate LIMBS 0),
    Vector.replicate 8 (Vector.replicate LIMBS 0), Vector.replicate 8 0, 0#u8⟩

theorem encode_emptyGathered : encodeGathered emptyGathered =
    (Array.repeat 8#usize (Array.repeat 8#usize 0#u64),
     Array.repeat 8#usize (Array.repeat 8#usize 0#u64),
     Array.repeat 8#usize 0#u32, 0#u8) := rfl

def convertedBatch (b : GatheredBatch) (fromBlst beta : Fp8) (endomorphism : Bool) : Fp8 × Fp8 :=
  let x := (Fp8.load b.xs).mul fromBlst
  let y := (Fp8.load b.ys).mul fromBlst
  (if endomorphism then x.mul beta else x, Fp8.select (ofU8 b.negate) y y.neg)

theorem batch_count_refines (points : Slice blst.blst_p1_affine) (offset count : Usize)
    (ho : offset.val ≤ points.val.length)
    (hc : count.val = min 8 (points.val.length - offset.val)) :
    (do let remaining ← Slice.len points - offset
        if remaining < fp8.LANES then Slice.len points - offset else ok fp8.LANES) = ok count := by
  have hsub := sub_ok (Slice.len points) offset ho
  rw [hsub]
  simp only [bind_tc_ok, fp8.LANES, UScalar.lt_equiv, UScalar.ofNatCore_val_eq, Slice.len_val]
  by_cases h : points.val.length - offset.val < 8
  · simp only [h, if_true]
    congr 1
    apply UScalar.eq_of_val_eq
    simp only [UScalar.ofNatCore_val_eq, hc]
    change points.val.length - offset.val = min 8 (points.val.length - offset.val)
    omega
  · simp only [h, if_false]
    congr 1
    apply UScalar.eq_of_val_eq
    simp only [hc]
    change 8 = min 8 (points.val.length - offset.val)
    omega

@[simp] theorem natIndex_val (n : ℕ) (hn : n < 2 ^ 32) : (natIndex n).val = n :=
  u32_ofNat_val n hn

theorem gathered_indices (points : Slice blst.blst_p1_affine) (negated : Slice Bool)
    (base offset count : ℕ) (b : GatheredBatch) :
    (gatherBatch (blstPointWords points) negated.val base offset count b).indices =
      Vector.ofFn (fun j : Fin 8 => base + min j.val (count - 1)) := by
  rw [gatherBatch_indices]
  apply Vector.ext
  intro j hj
  simp only [Vector.getElem_ofFn, batchSource]
  omega

theorem pointIndices_encodeGathered (b : GatheredBatch)
    (hb : ∀ j : Fin 8, b.indices[j] < 2 ^ 32) :
    pointIndices (encodeGathered b).2.2.1 = b.indices := by
  apply Vector.ext
  intro j hj
  simp [pointIndices, encodeGathered, getElem_ofArray]
  exact natIndex_val _ (hb ⟨j,hj⟩)


theorem loadGathered_x (b : GatheredBatch) :
    fp8.Fp8.load (encodeGathered b).1 = ok (toFp8 (Fp8.load b.xs)) := by
  simp [Fp8.load_refines, encodeGathered, LIMBS]
  exact congrArg (fun v : Vector Limbs 8 => toFp8 (Fp8.load v))
    (ofArray_toArray_ofArray_ofU64 (k := 8#usize) (n := 8#usize) b.xs rfl rfl rfl rfl)

theorem loadGathered_y (b : GatheredBatch) :
    fp8.Fp8.load (encodeGathered b).2.1 = ok (toFp8 (Fp8.load b.ys)) := by
  simp [Fp8.load_refines, encodeGathered, LIMBS]
  exact congrArg (fun v : Vector Limbs 8 => toFp8 (Fp8.load v))
    (ofArray_toArray_ofArray_ofU64 (k := 8#usize) (n := 8#usize) b.ys rfl rfl rfl rfl)

theorem push_batch_generated (s : msm8.store.PointStore) (offset count : Usize)
    (points : Slice blst.blst_p1_affine) (negated : Slice Bool)
    (endomorphism : Bool) (fromBlst beta : Fp8) (batch : GatheredBatch)
    (ho : offset.val < points.val.length)
    (hc : count.val = min 8 (points.val.length - offset.val))
    (hg : msm8.store.PointStore.push_blst_loop0_loop0 s.len points negated offset count
      (Array.repeat 8#usize (Array.repeat 8#usize 0#u64))
      (Array.repeat 8#usize (Array.repeat 8#usize 0#u64))
      (Array.repeat 8#usize 0#u32) 0#u8 0#usize = ok (encodeGathered batch)) :
    msm8.store.PointStore.push_blst_loop0.body points negated endomorphism
      (toFp8 fromBlst) (toFp8 beta) s.rows s.len offset = (do
        let stored ← msm8.store.PointStore.store_points s (encodeGathered batch).2.2.1
          (toFp8 (convertedBatch batch fromBlst beta endomorphism).1)
          (toFp8 (convertedBatch batch fromBlst beta endomorphism).2)
        let newlen ← stored.len + count
        let next ← offset + count
        ok (cont (stored.rows, newlen, next))) := by
  have hcount := batch_count_refines points offset count (Nat.le_of_lt ho) hc
  simp only [msm8.store.PointStore.push_blst_loop0.body, Slice.len_val, UScalar.lt_equiv,
    ho, if_true]
  simp only [UScalar.lt_equiv] at hcount
  rw [← bind_assoc_eq, hcount]
  simp only [bind_tc_ok]
  rw [hg]
  simp only [bind_tc_ok]
  change (do
    let fx ← fp8.Fp8.load (encodeGathered batch).1
    let x ← fp8.Fp8.mul fx (toFp8 fromBlst)
    let x1 ← (if endomorphism then fp8.Fp8.mul x (toFp8 beta) else ok x : Result fp8.Fp8)
    let fy ← fp8.Fp8.load (encodeGathered batch).2.1
    let y ← fp8.Fp8.mul fy (toFp8 fromBlst)
    let ny ← fp8.Fp8.neg y
    let sy ← fp8.Fp8.select batch.negate y ny
    let self ← msm8.store.PointStore.store_points s (encodeGathered batch).2.2.1 x1 sy
    let n ← self.len + count
    let k ← offset + count
    ok (cont (self.rows, n, k))) = _
  have hxload := loadGathered_x batch
  have hyload := loadGathered_y batch
  simp only [hxload, hyload, bind_tc_ok, Fp8.mul_refines,
    ofFp8_toFp8, Fp8.neg_refines, Fp8.select_refines]
  have hx : (if endomorphism then
      ok (toFp8 (((Fp8.load batch.xs).mul fromBlst).mul beta))
    else ok (toFp8 ((Fp8.load batch.xs).mul fromBlst))) = ok (toFp8 (convertedBatch batch fromBlst beta endomorphism).1) := by
    cases endomorphism <;> rfl
  rw [hx]
  simp only [bind_tc_ok]
  rfl

theorem transpose_encoded_fp8 (x : Fp8) :
    transpose8 (ofArray id (toFp8 x)) = transpose8 x.limbs := by
  exact congrArg transpose8 (ofArray_toArray_id (n := 8#usize) x.limbs rfl rfl)

theorem store_points_model_refines (s : msm8.store.PointStore) (indices : Array U32 8#usize)
    (x y : Fp8) (hb : indicesInBounds s indices) :
    ∃ out, msm8.store.PointStore.store_points s indices (toFp8 x) (toFp8 y) = ok out ∧
      pointRows out = storeRows (pointRows s) (pointIndices indices)
        (transpose8 x.limbs) (transpose8 y.limbs) ∧ out.len = s.len := by
  obtain ⟨out, ho, hr, hl⟩ := store_points_refines s indices (toFp8 x) (toFp8 y) hb
  refine ⟨out, ho, ?_, hl⟩
  rw [transpose_encoded_fp8 x, transpose_encoded_fp8 y] at hr
  exact hr

theorem push_batch_body (s : msm8.store.PointStore) (offset count : Usize)
    (points : Slice blst.blst_p1_affine) (negated : Slice Bool)
    (endomorphism : Bool) (fromBlst beta : Fp8)
    (ho : offset.val < points.val.length)
    (hc : count.val = min 8 (points.val.length - offset.val))
    (hn : negated.val.length = points.val.length)
    (hs : s.len.val + points.val.length < 2 ^ UScalarTy.Usize.numBits)
    (h32 : s.len.val + count.val ≤ 2 ^ 32)
    (hcap : s.len.val + count.val ≤ s.rows.val.length / 2) :
    let gathered := gatherBatch (blstPointWords points) negated.val
      s.len.val offset.val count.val emptyGathered
    let converted := convertedBatch gathered fromBlst beta endomorphism
    ∃ out next, next.val = offset.val + count.val ∧ out.len.val = s.len.val + count.val ∧
      msm8.store.PointStore.push_blst_loop0.body points negated endomorphism
        (toFp8 fromBlst) (toFp8 beta) s.rows s.len offset =
        ok (cont (out.rows, out.len, next)) ∧
      pointRows out = storeRows (pointRows s) gathered.indices
        (transpose8 converted.1.limbs) (transpose8 converted.2.limbs) := by
  dsimp only
  let gathered := gatherBatch (blstPointWords points) negated.val
    s.len.val offset.val count.val emptyGathered
  let converted := convertedBatch gathered fromBlst beta endomorphism
  have hcpos : 0 < count.val := by omega
  have hcbound : offset.val + count.val ≤ points.val.length := by omega
  have hidx : ∀ j : Fin 8, gathered.indices[j] < s.len.val + count.val := by
    intro j
    have h := gathered_indices points negated s.len.val offset.val count.val emptyGathered
    have he : gathered.indices[j] = s.len.val + min j.val (count.val - 1) := by
      simp [gathered, h]
    rw [he]
    have := Nat.min_le_right j.val (count.val - 1)
    omega
  have hpi := pointIndices_encodeGathered gathered (fun j => lt_of_lt_of_le (hidx j) h32)
  have hb : indicesInBounds s (encodeGathered gathered).2.2.1 := by
    intro j
    rw [hpi]
    have := hidx j
    omega
  obtain ⟨stored, hstored, hrows, hlen⟩ := store_points_model_refines s
    (encodeGathered gathered).2.2.1 converted.1 converted.2 hb
  have hlenbound : s.len.val + count.val < 2 ^ UScalarTy.Usize.numBits := by
    have := vec_length_bound s.rows
    have := Nat.div_le_self s.rows.val.length 2
    omega
  have hoffbound : offset.val + count.val < 2 ^ UScalarTy.Usize.numBits := by omega
  let newlen : Usize := UScalar.ofNatCore (s.len.val + count.val) hlenbound
  let next : Usize := UScalar.ofNatCore (offset.val + count.val) hoffbound
  have hnewlen : stored.len + count = ok newlen := by
    rw [hlen, add_ok s.len count hlenbound]
  have hnext : offset + count = ok next := by rw [add_ok offset count hoffbound]
  refine ⟨{ stored with len := newlen }, next, by simp [next], by simp [newlen], ?_, ?_⟩
  · have hg := push_gather_refines s.len offset count points negated emptyGathered
      hcpos hcbound hn hs
    have hzero := encode_emptyGathered
    have hg' : msm8.store.PointStore.push_blst_loop0_loop0 s.len points negated offset count
        (Array.repeat 8#usize (Array.repeat 8#usize 0#u64))
        (Array.repeat 8#usize (Array.repeat 8#usize 0#u64))
        (Array.repeat 8#usize 0#u32) 0#u8 0#usize = ok (encodeGathered gathered) := by
      simpa only [hzero] using hg
    rw [push_batch_generated s offset count points negated endomorphism fromBlst beta
      gathered ho hc hg']
    rw [hstored]
    simp [hnewlen, hnext]
  · rw [hpi] at hrows
    exact hrows

end LeanBlsSimd
