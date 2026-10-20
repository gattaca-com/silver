import LeanBlsSimd.Refines.Transpose

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.kzg

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
