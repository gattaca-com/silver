import LeanBlsSimd.Refines.Fp8

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd

/-- Exchange the row and lane coordinates of eight SIMD registers. -/
def transpose8 (rows : Vector M512 8) : Vector M512 8 :=
  Vector.ofFn fun row => Vector.ofFn fun lane => rows[lane][row]

private theorem shuffle0 (a b : M512) :
    _mm512_permutex2var_epi64 a (_mm512_set_epi64 14 6 12 4 10 2 8 0) b =
      #v[a[0], b[0], a[2], b[2], a[4], b[4], a[6], b[6]] := by
  ext i hi
  interval_cases i <;> norm_num [_mm512_permutex2var_epi64, _mm512_set_epi64] <;> rfl

private theorem shuffle1 (a b : M512) :
    _mm512_permutex2var_epi64 a (_mm512_set_epi64 15 7 13 5 11 3 9 1) b =
      #v[a[1], b[1], a[3], b[3], a[5], b[5], a[7], b[7]] := by
  ext i hi
  interval_cases i <;> norm_num [_mm512_permutex2var_epi64, _mm512_set_epi64] <;> rfl

private theorem shuffle2 (a b : M512) :
    _mm512_permutex2var_epi64 a (_mm512_set_epi64 13 12 5 4 9 8 1 0) b =
      #v[a[0], a[1], b[0], b[1], a[4], a[5], b[4], b[5]] := by
  ext i hi
  interval_cases i <;> norm_num [_mm512_permutex2var_epi64, _mm512_set_epi64] <;> rfl

private theorem shuffle3 (a b : M512) :
    _mm512_permutex2var_epi64 a (_mm512_set_epi64 15 14 7 6 11 10 3 2) b =
      #v[a[2], a[3], b[2], b[3], a[6], a[7], b[6], b[7]] := by
  ext i hi
  interval_cases i <;> norm_num [_mm512_permutex2var_epi64, _mm512_set_epi64] <;> rfl

private theorem shuffle4 (a b : M512) :
    _mm512_permutex2var_epi64 a (_mm512_set_epi64 11 10 9 8 3 2 1 0) b =
      #v[a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]] := by
  ext i hi
  interval_cases i <;> norm_num [_mm512_permutex2var_epi64, _mm512_set_epi64] <;> rfl

private theorem shuffle5 (a b : M512) :
    _mm512_permutex2var_epi64 a (_mm512_set_epi64 15 14 13 12 7 6 5 4) b =
      #v[a[4], a[5], a[6], a[7], b[4], b[5], b[6], b[7]] := by
  ext i hi
  interval_cases i <;> norm_num [_mm512_permutex2var_epi64, _mm512_set_epi64] <;> rfl

private theorem ofFn_eight {α : Type} (f : Fin 8 → α) :
    Vector.ofFn f = #v[f 0, f 1, f 2, f 3, f 4, f 5, f 6, f 7] := by
  apply Vector.ext
  intro i hi
  interval_cases i <;> simp

theorem transpose8_refines (rows : Array M512 8#usize) :
    fp8.transpose8 rows = ok (toArray id (transpose8 (ofArray id rows))) := by
  unfold fp8.transpose8
  simp [fp8.index_vector,
    index_usize_eq (n := 8#usize) _ 0#usize (by decide), index_usize_eq (n := 8#usize) _ 1#usize (by decide),
    index_usize_eq (n := 8#usize) _ 2#usize (by decide), index_usize_eq (n := 8#usize) _ 3#usize (by decide),
    index_usize_eq (n := 8#usize) _ 4#usize (by decide), index_usize_eq (n := 8#usize) _ 5#usize (by decide),
    index_usize_eq (n := 8#usize) _ 6#usize (by decide), index_usize_eq (n := 8#usize) _ 7#usize (by decide),
    core.core_arch.x86.avx512f._mm512_set_epi64,
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64,
    bind_tc_ok, Array.make, shuffle0, shuffle1, shuffle2, shuffle3, shuffle4, shuffle5]
  apply Subtype.ext
  simp [toArray, transpose8, ofFn_eight]

theorem transpose8_lanes (rows : Array M512 8#usize) :
    ∃ out, fp8.transpose8 rows = ok out ∧
      ∀ row lane : Fin 8, (out.val[row.val]!)[lane] = (rows.val[lane.val]!)[row] := by
  refine ⟨toArray id (transpose8 (ofArray id rows)), transpose8_refines rows, ?_⟩
  intro row lane
  simp [transpose8, getElem!_pos, row.isLt, lane.isLt, rows.property]

end LeanBlsSimd
