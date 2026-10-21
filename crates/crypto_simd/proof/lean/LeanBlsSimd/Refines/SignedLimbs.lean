import LeanBlsSimd.Refines.Basic
import LeanBlsSimd.Refines.Loop
import LeanBlsSimd.Proofs.Vector

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd

namespace LeanBlsSimd

def fromLanes {n : ℕ} (lanes : Fin 8 → Vector UInt64 n) : Vector M512 n :=
  .ofFn fun j => .ofFn fun l => (lanes l)[j]

@[simp] theorem laneOf_fromLanes {n : ℕ} (lanes : Fin 8 → Vector UInt64 n) (l : Fin 8) :
    laneOf (fromLanes lanes) l = lanes l := by
  ext j hj
  simp [fromLanes]

@[simp] theorem fromLanes_laneOf {n : ℕ} (v : Vector M512 n) : fromLanes (laneOf v) = v := by
  ext j hj l hl
  simp [fromLanes]

@[simp] theorem getElem_fromLanes {n : ℕ} (lanes : Fin 8 → Vector UInt64 n) (k : ℕ) (hk : k < n)
    (l : ℕ) (hl : l < 8) : (fromLanes lanes)[k][l] = (lanes ⟨l, hl⟩)[k] := by
  simp [fromLanes]

theorem fromLanes_eq_iff {n : ℕ} (lanes : Fin 8 → Vector UInt64 n) (v : Vector M512 n) :
    fromLanes lanes = v ↔ ∀ l, lanes l = laneOf v l := by
  constructor
  · rintro rfl; simp
  · intro h; rw [← fromLanes_laneOf v]; congr 1; funext l; exact h l

theorem repeat_eq_toArray_id {α : Type} {n : Usize} {m : ℕ} (x : α) (h : n.val = m) :
    Array.repeat n x = toArray id (Vector.replicate m x) h := by
  simp [toArray_replicate]

namespace SignedLimbs

open core.ops.range core.iter.range

def normaliseBody {n : Usize} (mask : M512) (iter : Range Usize) (s : Array M512 n) :
    Result (ControlFlow (Range Usize × Array M512 n) (Array M512 n)) := do
  let (o, iter1) ← IteratorRange.next StepUsize iter
  match o with
  | none => ok (done s)
  | some j =>
    let i ← j + 1#usize
    let mi ← Array.index_usize s i
    let mi1 ← Array.index_usize s j
    let mi2 ← core.core_arch.x86.avx512f._mm512_srai_epi64 52#u32 mi1
    let mi3 ← core.core_arch.x86.avx512f._mm512_add_epi64 mi mi2
    let s1 ← Array.update s i mi3
    let mi4 ← Array.index_usize s1 j
    let mi5 ← core.core_arch.x86.avx512f._mm512_and_si512 mi4 mask
    let a ← Array.update s1 j mi5
    ok (cont (iter1, a))

theorem normalise_loop_refines {n : Usize} (stop : Usize)
    (hstop : stop.val = n.val - 1) (hn : n.val < 2 ^ 32) (a : Array M512 n) :
    loop (fun (iter, s) => normaliseBody (Simd.splat (.ofNat MASK52)) iter s)
      ({ start := 0#usize, «end» := stop }, a) =
      ok (toArray id (fromLanes fun l => normalise (laneOf (ofArray id a) l))) := by
  let step := fun (v : Vector M512 n.val) (j : Fin (n.val - 1)) =>
    let v := v.set (j.val + 1)
      (_mm512_add_epi64 v[j.val + 1] (_mm512_srai_epi64 52 v[j.val]))
    v.set j.val (_mm512_and_si512 v[j.val] (Simd.splat (.ofNat MASK52)))
  conv_lhs => rw [show a = toArray id (ofArray id a) from (toArray_ofArray (fun _ => rfl) a _ _).symm]
  refine loop_range (n := n.val - 1) _ stop hstop (toArray (n := n) id) step
    (toArray (n := n) id) (ofArray id a) _ ?_ ?_ ?_
  · intro r m he hs hnext
    simp_body normaliseBody hnext
  · intro r r' m j he hs he' hs' hnext
    have hj : r.start.val < n.val - 1 := by rw [hs]; exact j.isLt
    have hjn : r.start.val < n.val := by omega
    simp_body normaliseBody hnext
    simp (disch := (simp only [UScalar.ofNatCore_val_eq]; omega)) only
      [usize_add_ok, bind_tc_ok, index_usize_eq _ _ hjn, update_eq _ _ _ hjn,
      index_usize_eq, update_eq,
      core.core_arch.x86.avx512f._mm512_srai_epi64,
      core.core_arch.x86.avx512f._mm512_add_epi64,
      core.core_arch.x86.avx512f._mm512_and_si512, UScalar.ofNatCore_val_eq]
    refine congrArg (fun s => ok (cont (r', s))) ?_
    apply Subtype.ext
    simp [step, hs, List.map_set, Vector.toList_set]
  · apply congrArg (toArray (n := n) id)
    rw [eq_comm, fromLanes_eq_iff]
    intro l
    unfold normalise
    refine List.foldl_hom (fun v => laneOf v l) ?_
    intro v j
    simp [step, carryStep, laneOf_set, getElem_laneOf, srai, MASK52,
      Simd.splat, _mm512_set1_epi64, _mm512_add_epi64, _mm512_srai_epi64,
      _mm512_and_si512]
    rfl

def addRawBody {n : Usize} (iter : Range Usize) (a b s : Array M512 n) :
    Result (ControlFlow (Range Usize × Array M512 n × Array M512 n × Array M512 n)
      (Array M512 n)) := do
  let (o, iter1) ← IteratorRange.next StepUsize iter
  match o with
  | none => ok (done s)
  | some _j =>
    let mi ← Array.index_usize a _j
    let mi1 ← Array.index_usize b _j
    let mi2 ← core.core_arch.x86.avx512f._mm512_add_epi64 mi mi1
    let result ← Array.update s _j mi2
    ok (cont (iter1, a, b, result))

theorem add_raw_loop_refines {n : Usize} (a b : Array M512 n) :
    loop (fun (iter, a, b, s) => addRawBody iter a b s)
      ({ start := 0#usize, «end» := n }, a, b, Array.repeat n Simd.zero) =
      ok (toArray id (Vector.ofFn fun j : Fin n.val =>
        _mm512_add_epi64 (ofArray id a)[j] (ofArray id b)[j])) := by
  rw [repeat_eq_toArray_id Simd.zero rfl]
  refine loop_range (n := n.val) _ n rfl
    (fun v => (a, b, toArray (n := n) id v))
    (fun v j => v.set j (_mm512_add_epi64 (ofArray id a)[j] (ofArray id b)[j]))
    (toArray (n := n) id) (Vector.replicate n.val Simd.zero) _ ?_ ?_ ?_
  · intro r m he hs hnext
    simp_body addRawBody hnext
  · intro r r' m j he hs he' hs' hnext
    have hj : r.start.val < n.val := by rw [hs]; exact j.isLt
    simp_body addRawBody hnext
    simp only [index_usize_eq _ _ hj, bind_tc_ok, update_eq _ _ _ hj,
      core.core_arch.x86.avx512f._mm512_add_epi64]
    refine congrArg (fun s => ok (cont (r', a, b, s))) ?_
    apply Subtype.ext
    simp [hs, List.map_set, Vector.toList_set]
  · simp [foldl_set_ofFn]

def subRawBody {n : Usize} (iter : Range Usize) (a b offset s : Array M512 n) :
    Result (ControlFlow (Range Usize × Array M512 n × Array M512 n × Array M512 n ×
      Array M512 n) (Array M512 n)) := do
  let (o, iter1) ← IteratorRange.next StepUsize iter
  match o with
  | none => ok (done s)
  | some _j =>
    let mi ← Array.index_usize a _j
    let mi1 ← Array.index_usize offset _j
    let mi2 ← core.core_arch.x86.avx512f._mm512_add_epi64 mi mi1
    let mi3 ← Array.index_usize b _j
    let mi4 ← core.core_arch.x86.avx512f._mm512_sub_epi64 mi2 mi3
    let result ← Array.update s _j mi4
    ok (cont (iter1, a, b, offset, result))

theorem sub_raw_loop_refines {n : Usize} (a b offset : Array M512 n) :
    loop (fun (iter, a, b, offset, s) => subRawBody iter a b offset s)
      ({ start := 0#usize, «end» := n }, a, b, offset, Array.repeat n Simd.zero) =
      ok (toArray id (Vector.ofFn fun j : Fin n.val =>
        _mm512_sub_epi64 (_mm512_add_epi64 (ofArray id a)[j] (ofArray id offset)[j])
          (ofArray id b)[j])) := by
  rw [repeat_eq_toArray_id Simd.zero rfl]
  refine loop_range (n := n.val) _ n rfl
    (fun v => (a, b, offset, toArray (n := n) id v))
    (fun v j => v.set j (_mm512_sub_epi64
      (_mm512_add_epi64 (ofArray id a)[j] (ofArray id offset)[j]) (ofArray id b)[j]))
    (toArray (n := n) id) (Vector.replicate n.val Simd.zero) _ ?_ ?_ ?_
  · intro r m he hs hnext
    simp_body subRawBody hnext
  · intro r r' m j he hs he' hs' hnext
    have hj : r.start.val < n.val := by rw [hs]; exact j.isLt
    simp_body subRawBody hnext
    simp only [index_usize_eq _ _ hj, bind_tc_ok, update_eq _ _ _ hj,
      core.core_arch.x86.avx512f._mm512_add_epi64,
      core.core_arch.x86.avx512f._mm512_sub_epi64]
    refine congrArg (fun s => ok (cont (r', a, b, offset, s))) ?_
    apply Subtype.ext
    simp [hs, List.map_set, Vector.toList_set]
  · simp [foldl_set_ofFn]

end SignedLimbs
end LeanBlsSimd
