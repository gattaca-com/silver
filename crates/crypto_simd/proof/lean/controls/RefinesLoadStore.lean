import controls.G1Fallback
import LeanBlsSimd.Refines.DecompressG2
import LeanBlsSimd.Refines.G2x8
import LeanBlsSimd.Proofs.Convert
import LeanBlsSimd.Refines.G1Wrapper

/-! Mutation controls for `LeanBlsSimd/Refines/`. Each `fail_if_success` checks that a proof script
rejects a mutation; each plain `example` must pass.

Each mutated definition takes the changed part as a parameter. An `rfl` check identifies its
unmutated instance with the original, and the same proof script succeeds on that instance.
Separate concrete examples refute the mutated claims where described below. -/

namespace LeanBlsSimd

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.bls

-- A mutated proof stops at its first failing step, so the linters flag the steps after it.
set_option linter.unreachableTactic false
set_option linter.unusedSimpArgs false
set_option linter.unusedTactic false

/-! ## `Fp8::load` and `Fp8::store`: the lane order

`load` passes the limbs of lanes 7 down to 0 to `_mm512_set_epi64`, whose last argument is lane 0.
`store` writes element `l` of `lanes(v)` to `out[l]`. A generated `load` that passes the limbs in
the opposite order, or a `store` whose `lanes` reverses the vector, must not refine the model's.
Each mutant takes the intrinsic or `lanes` as a parameter, and each script takes the model's
counterpart as its argument. The same scripts prove that each mutant refines a model with the same
mutation. On `laneIndices` that model differs from the original in lane 0, so the mutated claims
are false, not only unproved. -/

section LoadStore

open core.core_arch.x86

abbrev SetEpi64 := I64 → I64 → I64 → I64 → I64 → I64 → I64 → I64 → Result __m512i

def loadBodyWith (set : SetEpi64) (values : Array (Array U64 8#usize) 8#usize)
    (iter : core.ops.range.Range Usize) (v : Array __m512i 8#usize) :
    Result (ControlFlow (core.ops.range.Range Usize × Array __m512i 8#usize)
      (Array __m512i 8#usize)) := do
  let (o, iter1) ← core.iter.range.IteratorRange.next core.iter.range.StepUsize iter
  match o with
  | none => ok (done v)
  | some j =>
    let a ← Array.index_usize values 7#usize
    let i ← Array.index_usize a j
    let i1 ← lift (UScalar.hcast .I64 i)
    let a1 ← Array.index_usize values 6#usize
    let i2 ← Array.index_usize a1 j
    let i3 ← lift (UScalar.hcast .I64 i2)
    let a2 ← Array.index_usize values 5#usize
    let i4 ← Array.index_usize a2 j
    let i5 ← lift (UScalar.hcast .I64 i4)
    let a3 ← Array.index_usize values 4#usize
    let i6 ← Array.index_usize a3 j
    let i7 ← lift (UScalar.hcast .I64 i6)
    let a4 ← Array.index_usize values 3#usize
    let i8 ← Array.index_usize a4 j
    let i9 ← lift (UScalar.hcast .I64 i8)
    let a5 ← Array.index_usize values 2#usize
    let i10 ← Array.index_usize a5 j
    let i11 ← lift (UScalar.hcast .I64 i10)
    let a6 ← Array.index_usize values 1#usize
    let i12 ← Array.index_usize a6 j
    let i13 ← lift (UScalar.hcast .I64 i12)
    let a7 ← Array.index_usize values 0#usize
    let i14 ← Array.index_usize a7 j
    let i15 ← lift (UScalar.hcast .I64 i14)
    let mi ← set i1 i3 i5 i7 i9 i11 i13 i15
    let a8 ← Array.update v j mi
    ok (cont (iter1, a8))

def loadLoopWith (set : SetEpi64) (iter : core.ops.range.Range Usize)
    (values : Array (Array U64 8#usize) 8#usize) (v : Array __m512i 8#usize) :
    Result (Array __m512i 8#usize) :=
  loop (fun (iter1, v1) => loadBodyWith set values iter1 v1) (iter, v)

def loadWith (set : SetEpi64) (values : Array (Array U64 8#usize) 8#usize) : Result fp8.Fp8 := do
  let mi ← fp8.zero
  let v := Array.repeat 8#usize mi
  let v1 ← loadLoopWith set { start := 0#usize, «end» := constants.LIMBS } values v
  ok v1

example : loadWith avx512f._mm512_set_epi64 = fp8.Fp8.load := rfl

/-- `_mm512_set_epi64` with its arguments in the opposite order, which is `_mm512_setr_epi64`. -/
def setrGen : SetEpi64 := fun e7 e6 e5 e4 e3 e2 e1 e0 =>
  avx512f._mm512_set_epi64 e0 e1 e2 e3 e4 e5 e6 e7

def Fp8.loadWith (set : Int64 → Int64 → Int64 → Int64 → Int64 → Int64 → Int64 → Int64 → M512)
    (values : Vector Limbs 8) : Fp8 :=
  ⟨.ofFn fun j => set values[7][j].toInt64 values[6][j].toInt64
    values[5][j].toInt64 values[4][j].toInt64 values[3][j].toInt64 values[2][j].toInt64
    values[1][j].toInt64 values[0][j].toInt64⟩

example : Fp8.loadWith _mm512_set_epi64 = Fp8.load := rfl

def setrModel : Int64 → Int64 → Int64 → Int64 → Int64 → Int64 → Int64 → Int64 → M512 :=
  fun e7 e6 e5 e4 e3 e2 e1 e0 => _mm512_set_epi64 e0 e1 e2 e3 e4 e5 e6 e7

set_option hygiene false in
/-- The proof of `Fp8.load_refines`, over `loadWith`, against `Fp8.loadWith set`. -/
local macro "load_proof" set:term : tactic => `(tactic| (
  intro values
  unfold loadWith loadLoopWith
  simp only [Simd.zero_refines, bind_tc_ok, LIMBS_refines, bind_ok_eq]
  rw [repeat_eq_toArray_id Simd.zero (show (8#usize).val = LIMBS from rfl)]
  refine loop_range (n := LIMBS) _ 8#usize rfl (toArray id)
    (fun v j => v.set j (Fp8.loadWith $set (ofArray (ofArray ofU64) values)).limbs[j]) (toArray id)
    (Vector.replicate LIMBS Simd.zero) _ ?_ ?_ ?_
  · intro r m he hs hn
    simp_body loadBodyWith hn
  · intro r r' m j he hs he' hs' hn
    have hj : r.start.val < (8#usize).val := by rw [hs]; exact j.isLt
    simp_body loadBodyWith hn
    simp only [index_usize_eq values 7#usize (by decide), index_usize_eq values 6#usize (by decide),
      index_usize_eq values 5#usize (by decide), index_usize_eq values 4#usize (by decide),
      index_usize_eq values 3#usize (by decide), index_usize_eq values 2#usize (by decide),
      index_usize_eq values 1#usize (by decide), index_usize_eq values 0#usize (by decide),
      index_usize_eq _ _ hj, bind_tc_ok, lift, update_eq _ _ _ hj, setrGen,
      avx512f._mm512_set_epi64, ofBitVec_hcast_I64]
    refine congrArg (fun s => ok (cont (r', s))) ?_
    apply Subtype.ext
    simp [hs, List.map_set, Vector.toList_set, Fp8.loadWith, setrModel]
  · simp [Fp8.loadWith, foldl_set_ofFn, toFp8]))

example : ∀ values : Array (Array U64 8#usize) 8#usize,
    loadWith avx512f._mm512_set_epi64 values =
      ok (toFp8 (Fp8.loadWith _mm512_set_epi64 (ofArray (ofArray ofU64) values))) := by
  load_proof _mm512_set_epi64

example : True := by
  fail_if_success
    have : ∀ values : Array (Array U64 8#usize) 8#usize,
        loadWith setrGen values =
          ok (toFp8 (Fp8.loadWith _mm512_set_epi64 (ofArray (ofArray ofU64) values))) := by
      load_proof _mm512_set_epi64
  trivial

theorem loadWith_setr_refines : ∀ values : Array (Array U64 8#usize) 8#usize,
    loadWith setrGen values =
      ok (toFp8 (Fp8.loadWith setrModel (ofArray (ofArray ofU64) values))) := by
  load_proof setrModel

/-- Eight lanes whose limbs all hold the lane's index. -/
def laneIndices : Vector Limbs 8 := .ofFn fun l => .replicate LIMBS l.val.toUInt64

example : ¬ ∀ values : Array (Array U64 8#usize) 8#usize,
    loadWith setrGen values = ok (toFp8 (Fp8.load (ofArray (ofArray ofU64) values))) := by
  intro h
  have e := congrArg ofFp8 (Result.ok.inj
    ((loadWith_setr_refines (toArray (toArray toU64) laneIndices)).symm.trans
      (h (toArray (toArray toU64) laneIndices))))
  simp only [ofFp8_toFp8, ofArray_toArray_ofArray_ofU64] at e
  have e0 := congrArg (fun x : Fp8 => x.limbs[0][0]) e
  revert e0
  decide +kernel

def storeBodyWith (lanes : __m512i → Result (Array U64 8#usize))
    (iter : core.ops.range.Range Usize) (self : fp8.Fp8) (out : Array (Array U64 8#usize) 8#usize) :
    Result (ControlFlow (core.ops.range.Range Usize × fp8.Fp8 × Array (Array U64 8#usize) 8#usize)
      (Array (Array U64 8#usize) 8#usize)) := do
  let (o, iter1) ← core.iter.range.IteratorRange.next core.iter.range.StepUsize iter
  match o with
  | none => ok (done out)
  | some j =>
    let mi ← Array.index_usize self j
    let l ← lanes mi
    let out1 ← fp8.Fp8.store_loop0_loop0 { start := 0#usize, «end» := limbs.LANES } out j l
    ok (cont (iter1, self, out1))

def storeLoopWith (lanes : __m512i → Result (Array U64 8#usize))
    (iter : core.ops.range.Range Usize) (self : fp8.Fp8) (out : Array (Array U64 8#usize) 8#usize) :
    Result (Array (Array U64 8#usize) 8#usize) :=
  loop (fun (iter1, self1, out1) => storeBodyWith lanes iter1 self1 out1) (iter, self, out)

def storeWith (lanes : __m512i → Result (Array U64 8#usize)) (self : fp8.Fp8) :
    Result (Array (Array U64 8#usize) 8#usize) := do
  let a := Array.repeat 8#usize 0#u64
  let out := Array.repeat 8#usize a
  storeLoopWith lanes { start := 0#usize, «end» := constants.LIMBS } self out

example : storeWith fp8.lanes = fp8.Fp8.store := rfl

/-- `fp8::lanes` reading the lanes in the opposite order. -/
def lanesRevGen (v : __m512i) : Result (Array U64 8#usize) := fp8.lanes v.reverse

def Fp8.storeWith (lanes : M512 → Vector UInt64 8) (self : Fp8) : Vector Limbs 8 :=
  (List.finRange LIMBS).foldl (init := .replicate 8 (.replicate LIMBS 0)) fun out (j : Fin LIMBS) =>
    let l := lanes self.limbs[j]
    (List.finRange 8).foldl (init := out) fun out (lane : Fin 8) =>
      out.set lane (out[lane].set j l[lane])

example : Fp8.storeWith Simd.lanes = Fp8.store := rfl

def lanesRevModel (v : M512) : Vector UInt64 8 := Simd.lanes v.reverse

set_option hygiene false in
/-- The proof of `Fp8.store_refines`, over `storeWith`, against `Fp8.storeWith lanes`. -/
local macro "store_proof" lanes:term : tactic => `(tactic| (
  intro self
  unfold storeWith storeLoopWith
  simp only [LIMBS_refines]
  rw [show Array.repeat 8#usize (Array.repeat 8#usize 0#u64) =
    toArray (toArray toU64) (Vector.replicate 8 (Vector.replicate LIMBS 0)) from
    by simp [toArray_replicate]; rfl]
  refine loop_range (n := LIMBS) _ 8#usize rfl (fun out => (self, toArray (toArray toU64) out))
    (fun out (j : Fin LIMBS) =>
      (List.finRange 8).foldl (fun out (lane : Fin 8) =>
        out.set lane (out[lane].set j ($lanes (ofFp8 self).limbs[j])[lane])) out)
    (toArray (toArray toU64)) (Vector.replicate 8 (Vector.replicate LIMBS 0)) _ ?_ ?_ rfl
  · intro r m he hs hn
    simp_body storeBodyWith hn
  · intro r r' m j he hs he' hs' hn
    have hj : r.start.val < (8#usize).val := by rw [hs]; exact j.isLt
    simp_body storeBodyWith hn
    simp only [index_usize_eq _ _ hj, bind_tc_ok, lanesRevGen, Simd.lanes_refines]
    rw [Fp8.store_inner_refines _ _ (by rw [hs]; exact j.isLt)]
    simp [hs, lanesRevModel]))

example : ∀ self : fp8.Fp8,
    storeWith fp8.lanes self =
      ok (toArray (toArray toU64) (Fp8.storeWith Simd.lanes (ofFp8 self))) := by
  store_proof Simd.lanes

example : True := by
  fail_if_success
    have : ∀ self : fp8.Fp8,
        storeWith lanesRevGen self =
          ok (toArray (toArray toU64) (Fp8.storeWith Simd.lanes (ofFp8 self))) := by
      store_proof Simd.lanes
  trivial

theorem storeWith_rev_refines : ∀ self : fp8.Fp8,
    storeWith lanesRevGen self =
      ok (toArray (toArray toU64) (Fp8.storeWith lanesRevModel (ofFp8 self))) := by
  store_proof lanesRevModel

example : ¬ ∀ self : fp8.Fp8,
    storeWith lanesRevGen self = ok (toArray (toArray toU64) (ofFp8 self).store) := by
  intro h
  have e := congrArg (ofArray (ofArray ofU64) (m := 8) (h := rfl)) (Result.ok.inj
    ((storeWith_rev_refines (toFp8 (Fp8.load laneIndices))).symm.trans
      (h (toFp8 (Fp8.load laneIndices)))))
  simp only [ofFp8_toFp8, ofArray_toArray_ofArray_ofU64] at e
  have e0 := congrArg (fun x : Vector Limbs 8 => x[0][0]) e
  revert e0
  decide +kernel

end LoadStore

end LeanBlsSimd
