import LeanBlsSimd.Kzg.Extender.Kernel.Fr8Arithmetic
import LeanBlsSimd.Refines.Transpose
import LeanBlsSimd.Proofs.Convert

open Aeneas Aeneas.Std Result ControlFlow
open EthCryptographySpecs Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel.BytePacking

set_option exponentiation.threshold 1000
set_option maxRecDepth 4000
set_option maxHeartbeats 2000000

def unpack (x : Vector UInt64 4) : Vector UInt64 5 :=
  #v[x[0] &&& UInt64.ofNat MASK52,
    ((x[0] >>> 52) ||| (x[1] <<< 12)) &&& UInt64.ofNat MASK52,
    ((x[1] >>> 40) ||| (x[2] <<< 24)) &&& UInt64.ofNat MASK52,
    ((x[2] >>> 28) ||| (x[3] <<< 36)) &&& UInt64.ofNat MASK52,
    x[3] >>> 16]

def pack (x : Vector UInt64 5) : Vector UInt64 4 :=
  #v[x[0] ||| (x[1] <<< 52), (x[1] >>> 12) ||| (x[2] <<< 40),
    (x[2] >>> 24) ||| (x[3] <<< 28), (x[3] >>> 36) ||| (x[4] <<< 16)]

def val52 (x : Vector UInt64 5) : Nat :=
  x[0].toNat + x[1].toNat * 2^52 + x[2].toNat * 2^104 +
    x[3].toNat * 2^156 + x[4].toNat * 2^208

def valWords (x : Vector UInt64 4) : Nat :=
  x[0].toNat + x[1].toNat * 2^64 + x[2].toNat * 2^128 + x[3].toNat * 2^192

theorem unpack_spec (x : Vector UInt64 4) :
    (∀ j : Fin 5, (unpack x)[j].toNat < 2^52) ∧ val52 (unpack x) = valWords x := by
  have l0 : (unpack x)[0].toNat = x[0].toNat % 2^52 := by
    simpa using toNat_limb_one x[0] 0 (by decide)
  have l1 : (unpack x)[1].toNat =
      (x[0].toNat / 2^52 + x[1].toNat % 2^52 * 2^12) % 2^52 :=
    toNat_limb_two x[0] x[1] 52 (by decide) (by decide)
  have l2 : (unpack x)[2].toNat =
      (x[1].toNat / 2^40 + x[2].toNat % 2^40 * 2^24) % 2^52 :=
    toNat_limb_two x[1] x[2] 40 (by decide) (by decide)
  have l3 : (unpack x)[3].toNat =
      (x[2].toNat / 2^28 + x[3].toNat % 2^28 * 2^36) % 2^52 :=
    toNat_limb_two x[2] x[3] 28 (by decide) (by decide)
  have l4 : (unpack x)[4].toNat = x[3].toNat / 2^16 := by
    simp [unpack, UInt64.toNat_shiftRight, Nat.shiftRight_eq_div_pow]
  have h0 := x[0].toNat_lt
  have h1 := x[1].toNat_lt
  have h2 := x[2].toNat_lt
  have h3 := x[3].toNat_lt
  constructor
  · intro j
    fin_cases j <;> simp only [Fin.getElem_fin] <;>
      (first | rw [l0] | rw [l1] | rw [l2] | rw [l3] | rw [l4]) <;> omega
  · rw [val52, l0, l1, l2, l3, l4, valWords]
    omega

theorem unpack_refines (x : Array U64 4#usize) :
    fr8.unpack52 x = ok (toArray toU64 (unpack (ofArray ofU64 x))) := by
  have hm : fr8.MASK52 = ok (toU64 (UInt64.ofNat MASK52)) := by
    unfold fr8.MASK52
    rw [fr8.LIMB_BITS]
    rfl
  unfold fr8.unpack52
  simp only [hm, index_usize_eq x 0#usize (by decide), index_usize_eq x 1#usize (by decide),
    index_usize_eq x 2#usize (by decide), index_usize_eq x 3#usize (by decide), bind_tc_ok,
    lift]
  simp only [HShiftRight.hShiftRight, HShiftLeft.hShiftLeft, UScalar.shiftRight_IScalar,
    UScalar.shiftLeft_IScalar, UScalar.shiftRight, UScalar.shiftLeft, IScalar.toNat]
  simp only [show (52#i32).val = 52 by rfl, show (12#i32).val = 12 by rfl,
    show (40#i32).val = 40 by rfl, show (24#i32).val = 24 by rfl,
    show (28#i32).val = 28 by rfl, show (36#i32).val = 36 by rfl,
    show (16#i32).val = 16 by rfl]
  norm_num only [UScalarTy.U64_numBits_eq, Int.reduceLT, Nat.reduceLT, ↓reduceIte,
    bind_tc_ok, if_true]
  apply congrArg ok
  apply Subtype.ext
  have hinj : Function.Injective (List.map ofU64) := by
    intro a b h
    have hh := congrArg (List.map toU64) h
    simpa [List.map_map, Function.comp_def] using hh
  apply hinj
  simp [Array.make, toArray, unpack]

def transpose (lanes : Vector (Vector UInt64 5) 8) : Vector M512 5 :=
  Vector.ofFn fun j => Vector.ofFn fun lane => lanes[lane][j]

theorem transpose_refines (values : Array (Array U64 5#usize) 8#usize) :
    fr8.transpose_in values = ok (toArray id (transpose (ofArray (ofArray ofU64) values))) := by
  unfold fr8.transpose_in fr8.transpose_in_loop
  have hz : fr8.zero = ok Simd.zero := rfl
  simp only [hz, bind_tc_ok, fr8.LIMBS]
  rw [repeat_eq_toArray_id Simd.zero (show (5#usize).val = 5 from rfl)]
  refine loop_range (n := 5) _ 5#usize rfl (toArray id)
    (fun v j => v.set j (transpose (ofArray (ofArray ofU64) values))[j]) (toArray id)
    (Vector.replicate 5 Simd.zero) _ ?_ ?_ ?_
  · intro r m he hs hn
    simp_body fr8.transpose_in_loop.body hn
  · intro r r' m j he hs he' hs' hn
    have hj : r.start.val < (5#usize).val := by rw [hs]; exact j.isLt
    simp_body fr8.transpose_in_loop.body hn
    simp only [index_usize_eq values 7#usize (by decide), index_usize_eq values 6#usize (by decide),
      index_usize_eq values 5#usize (by decide), index_usize_eq values 4#usize (by decide),
      index_usize_eq values 3#usize (by decide), index_usize_eq values 2#usize (by decide),
      index_usize_eq values 1#usize (by decide), index_usize_eq values 0#usize (by decide),
      index_usize_eq _ _ hj, bind_tc_ok, lift, update_eq _ _ _ hj,
      core.core_arch.x86.avx512f._mm512_set_epi64, ofBitVec_hcast_I64]
    refine congrArg (fun s => ok (cont (r', s))) ?_
    apply Subtype.ext
    simp only [Aeneas.Std.Array.set_val_eq, hs, toArray_val, List.map_set, Vector.toList_set, transpose,
      Vector.getElem_ofFn, getElem_ofArray, Fin.getElem_fin, List.map_id]
    apply congrArg (m.toList.set j.val)
    ext lane hl
    interval_cases lane <;> simp [_mm512_set_epi64]
  · simp [transpose, foldl_set_ofFn]

def loadedLanes (input : Slice blst.blst_fr) (offset : Usize) : Vector (Vector UInt64 5) 8 :=
  Vector.ofFn fun lane => unpack (ofArray ofU64 input.val[offset.val + lane.val]!.l)

theorem load_loop_refines (input : Slice blst.blst_fr) (offset : Usize)
    (hsize : offset.val + 8 ≤ input.val.length) :
    fr8.Fr8.load_loop { start := 0#usize, «end» := fr8.LANES } input offset
      (Array.repeat 8#usize (Array.repeat 5#usize 0#u64)) =
      ok (toArray (toArray toU64) (loadedLanes input offset)) := by
  unfold fr8.Fr8.load_loop
  rw [fr8.LANES]
  rw [show Array.repeat 8#usize (Array.repeat 5#usize 0#u64) =
      toArray (toArray toU64) (Vector.replicate 8 (Vector.replicate 5 0)) by
    simp [toArray_replicate]
    rfl]
  refine loop_range (n := 8) _ 8#usize rfl (toArray (toArray toU64))
    (fun v lane => v.set lane (loadedLanes input offset)[lane]) (toArray (toArray toU64))
    (Vector.replicate 8 (Vector.replicate 5 0)) _ ?_ ?_ ?_
  · intro r m he hs hn
    simp_body fr8.Fr8.load_loop.body hn
  · intro r r' m lane he hs he' hs' hn
    have hl : r.start.val < 8 := by rw [hs]; exact lane.isLt
    have hadd : offset.val + r.start.val < 2^UScalarTy.Usize.numBits := by
      have hmax := input.property
      simp only [Usize.max, Usize.numBits] at hmax
      omega
    simp_body fr8.Fr8.load_loop.body hn
    rw [add_ok _ _ hadd]
    simp only [bind_tc_ok]
    rw [show Slice.index_usize input (UScalar.ofNatCore (offset.val + r.start.val) hadd) =
        ok input.val[offset.val + r.start.val]! by
      simp [Slice.index_usize, show offset.val + r.start.val < input.val.length by omega]]
    simp only [bind_tc_ok]
    rw [unpack_refines]
    simp only [bind_tc_ok, update_eq _ r.start _ (show r.start.val < (8#usize).val from hl)]
    refine congrArg (fun s => ok (cont (r', s))) ?_
    apply Subtype.ext
    simp [hs, List.map_set, Vector.toList_set, loadedLanes]
  · simp [loadedLanes, foldl_set_ofFn]

theorem load_refines (input : Slice blst.blst_fr) (offset : Usize)
    (hsize : offset.val + 8 ≤ input.val.length) :
    fr8.Fr8.load input offset = ok (toArray id (transpose (loadedLanes input offset))) := by
  simp [fr8.Fr8.load, load_loop_refines input offset hsize, transpose_refines]

theorem get_limb_toArray (v : Vector M512 5) (j : Fin 5) :
    (toArray (n := 5#usize) id v).val[j.val]! = v[j] := by
  simp [getElem!_pos, j.isLt]

theorem laneNat_transpose (lanes : Vector (Vector UInt64 5) 8) (lane : Fin 8) :
    laneNat (toArray id (transpose lanes)) lane = val52 lanes[lane] := by
  rw [laneNat_eq_val, FrModel.val, FrModel.sum_fin_limbs]
  simp [FrModel.ofFr8, FrModel.Fr8.lane, transpose, val52, FrModel.LIMB_BITS, FrModel.LIMBS,
    Function.comp_def]
  rfl

theorem limbs_ofArray (x : Array U64 4#usize) :
    valWords (ofArray ofU64 x) = limbs x.val := by
  obtain ⟨xs, hxs⟩ := x
  change xs.length = 4 at hxs
  cases xs with
  | nil => simp at hxs
  | cons a xs => cases xs with
    | nil => simp at hxs
    | cons b xs => cases xs with
      | nil => simp at hxs
      | cons c xs => cases xs with
        | nil => simp at hxs
        | cons d xs =>
          have : xs = [] := by simpa using hxs
          subst xs
          simp [valWords, limbs, ofArray]
          ring


end LeanBlsSimd.Kzg.Extender.Kernel.BytePacking

namespace LeanBlsSimd.Kzg.Extender.Kernel.TransposePacking

def columns (data : Slice fr8.Fr8) (offset : Usize) : Vector (Vector M512 8) 5 :=
  Vector.ofFn fun j => LeanBlsSimd.transpose8
    (Vector.ofFn fun row => data.val[offset.val + row.val]!.val[j.val]!)

def store (x : Vector (Vector M512 8) 5) : Vector (Vector M512 5) 8 :=
  (List.finRange 5).foldl (init := .replicate 8 (.replicate 5 Simd.zero)) fun out (j : Fin 5) =>
    (List.finRange 8).foldl (init := out) fun out (row : Fin 8) =>
      out.set row (out[row].set j x[j][row])

theorem getElem_store_foldl_inner (v : Vector M512 8) (j : ℕ) (hj : j < 5) (l : Fin 8) :
    ∀ (ls : List (Fin 8)) (out : Vector (Vector M512 5) 8), ls.Nodup →
      (ls.foldl (fun out (row : Fin 8) => out.set row (out[row].set j v[row])) out)[l] =
        if l ∈ ls then out[l].set j v[l] else out[l]
  | [], out, _ => by simp
  | i :: ls, out, hnd => by
    rw [List.foldl_cons, getElem_store_foldl_inner v j hj l ls _ (List.nodup_cons.mp hnd).2]
    have hi := (List.nodup_cons.mp hnd).1
    by_cases hl : l ∈ ls
    · have : i ≠ l := fun h => hi (h ▸ hl)
      simp [hl, Fin.val_ne_of_ne this]
    · by_cases hil : i = l
      · subst hil; simp [hl]
      · simp [hl, Fin.val_ne_of_ne hil, Ne.symm hil]

theorem getElem_store (x : Vector (Vector M512 8) 5) (l : Fin 8) (j : Fin 5) :
    (store x)[l][j] = x[j][l] := by
  have outer : ∀ (js : List (Fin 5)) (out : Vector (Vector M512 5) 8) (j' : ℕ) (hj' : j' < 5),
      (js.foldl (fun out (j : Fin 5) =>
        (List.finRange 8).foldl (fun out (row : Fin 8) =>
          out.set row (out[row].set j x[j][row])) out) out)[l][j'] =
        if j' ∈ js.map (·.val) then x[j'][l] else out[l][j'] := by
    intro js
    induction js with
    | nil => simp
    | cons j js ih =>
      intro out j' hj'
      rw [List.foldl_cons, ih]
      rw [getElem_store_foldl_inner _ _ j.isLt l _ _ (List.nodup_finRange 8)]
      by_cases h : j' ∈ js.map (·.val)
      · simp [h]
      · by_cases hjj : j.val = j'
        · subst hjj; simp
        · simp [h, hjj, Ne.symm hjj]
  simpa [store, j.isLt] using
    outer (List.finRange 5) (Vector.replicate 8 (Vector.replicate 5 Simd.zero)) j.val j.isLt

theorem store_inner_refines (out : Vector (Vector M512 5) 8) (j : Usize) (hj : j.val < 5)
    (rows : Vector M512 8) :
    fr8.Fr8.transpose_loop0_loop0 { start := 0#usize, «end» := fr8.LANES }
        (toArray (toArray id) out) j (toArray id rows) =
      ok (toArray (toArray id) ((List.finRange 8).foldl
        (fun out (row : Fin 8) => out.set row (out[row].set j.val rows[row])) out)) := by
  unfold fr8.Fr8.transpose_loop0_loop0
  rw [fr8.LANES]
  refine loop_range (n := 8) _ 8#usize rfl (toArray (toArray id))
    (fun out (row : Fin 8) => out.set row (out[row].set j.val rows[row])) (toArray (toArray id))
    out _ ?_ ?_ rfl
  · intro r m he hs hn
    simp_body fr8.Fr8.transpose_loop0_loop0.body hn
  · intro r r' m row he hs he' hs' hn
    have hl : r.start.val < (8#usize).val := by rw [hs]; exact row.isLt
    have hj' : j.val < (5#usize).val := hj
    simp_body fr8.Fr8.transpose_loop0_loop0.body hn
    simp only [index_usize_eq _ _ hl, bind_tc_ok, Array.index_mut_usize, update_eq _ _ _ hj']
    refine congrArg (fun s => ok (cont (r', s))) ?_
    apply Subtype.ext
    simp [hs, hj, List.map_set, Vector.toList_set, set_toArray_id]

theorem store_refines (data : Slice fr8.Fr8) (offset : Usize)
    (hsize : offset.val + 8 ≤ data.val.length) :
    fr8.Fr8.transpose_loop0 { start := 0#usize, «end» := fr8.LIMBS } data offset
      (Array.repeat 8#usize (Array.repeat 5#usize Simd.zero)) =
      ok (toArray (toArray id) (store (columns data offset))) := by
  unfold fr8.Fr8.transpose_loop0
  simp only [fr8.LIMBS]
  rw [show Array.repeat 8#usize (Array.repeat 5#usize Simd.zero) =
    toArray (toArray id) (Vector.replicate 8 (Vector.replicate 5 Simd.zero)) from
    by simp [toArray_replicate]]
  refine loop_range (n := 5) _ 5#usize rfl (toArray (toArray id))
    (fun out (j : Fin 5) =>
      (List.finRange 8).foldl (fun out (row : Fin 8) =>
        out.set row (out[row].set j (columns data offset)[j][row])) out)
    (toArray (toArray id)) (Vector.replicate 8 (Vector.replicate 5 Simd.zero)) _ ?_ ?_ rfl
  · intro r m he hs hn
    simp_body fr8.Fr8.transpose_loop0.body hn
  · intro r r' m j he hs he' hs' hn
    have hj : r.start.val < (5#usize).val := by rw [hs]; exact j.isLt
    have hindex (k : Usize) (hk : k.val < 8) :
        ∃ i, offset + k = ok i ∧ i.val = offset.val + k.val ∧
          Slice.index_usize data i = ok data.val[offset.val + k.val]! := by
      have hadd : offset.val + k.val < 2^UScalarTy.Usize.numBits := by
        have hmax := data.property
        simp only [Usize.max, Usize.numBits] at hmax
        omega
      refine ⟨UScalar.ofNatCore _ hadd, add_ok _ _ hadd, rfl, ?_⟩
      simp [Slice.index_usize, show offset.val + k.val < data.val.length by omega]
    obtain ⟨i1, hi1, hv1, hx1⟩ := hindex 1#usize (by decide)
    obtain ⟨i2, hi2, hv2, hx2⟩ := hindex 2#usize (by decide)
    obtain ⟨i3, hi3, hv3, hx3⟩ := hindex 3#usize (by decide)
    obtain ⟨i4, hi4, hv4, hx4⟩ := hindex 4#usize (by decide)
    obtain ⟨i5, hi5, hv5, hx5⟩ := hindex 5#usize (by decide)
    obtain ⟨i6, hi6, hv6, hx6⟩ := hindex 6#usize (by decide)
    obtain ⟨i7, hi7, hv7, hx7⟩ := hindex 7#usize (by decide)
    have hx0 : Slice.index_usize data offset = ok data.val[offset.val]! := by
      simp [Slice.index_usize, show offset.val < data.val.length by omega]
    simp_body fr8.Fr8.transpose_loop0.body hn
    simp only [hx0, hi1, hi2, hi3, hi4, hi5, hi6, hi7,
      hx1, hx2, hx3, hx4, hx5, hx6, hx7, bind_tc_ok, index_usize_eq _ _ hj]
    rw [transpose8_refines]
    simp only [bind_tc_ok]
    rw [store_inner_refines _ _ hj]
    simp only [bind_tc_ok]
    refine congrArg (fun out => ok (cont (r', toArray (toArray id) out))) ?_
    congr 1
    funext out row
    congr 2
    simp [columns, LeanBlsSimd.transpose8, hs]
    congr 1
    ext lane
    fin_cases lane <;> simp [Array.make]

theorem transpose_refines (data : Slice fr8.Fr8) (offset : Usize)
    (hsize : offset.val + 8 ≤ data.val.length) :
    fr8.Fr8.transpose data offset = ok (toArray (toArray id) (store (columns data offset))) := by
  unfold fr8.Fr8.transpose
  have hz : fr8.zero = ok Simd.zero := rfl
  simp only [hz, bind_tc_ok, store_refines data offset hsize]
  simp only [index_usize_eq (n := 8#usize) _ 0#usize (by decide), index_usize_eq (n := 8#usize) _ 1#usize (by decide),
    index_usize_eq (n := 8#usize) _ 2#usize (by decide), index_usize_eq (n := 8#usize) _ 3#usize (by decide),
    index_usize_eq (n := 8#usize) _ 4#usize (by decide), index_usize_eq (n := 8#usize) _ 5#usize (by decide),
    index_usize_eq (n := 8#usize) _ 6#usize (by decide), index_usize_eq (n := 8#usize) _ 7#usize (by decide), bind_tc_ok]
  apply congrArg ok
  apply Subtype.ext
  apply List.ext_getElem
  · simp
  · intro i hi hi'
    have h : i < 8 := by simpa using hi'
    interval_cases i <;> simp [Array.make]

end LeanBlsSimd.Kzg.Extender.Kernel.TransposePacking
