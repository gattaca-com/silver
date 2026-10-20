import LeanBlsSimd.Refines.Transpose

open Aeneas Aeneas.Std Result
open silver_crypto_simd

namespace LeanBlsSimd.Controls.Transpose

/- The copied network exposes its first shuffle index. The equality below pins every
other operation to the extraction; the witness distinguishes row/lane coordinates. -/

def transposeWithFirstIndex (first : I64)
  (r : Array core.core_arch.x86.__m512i 8#usize) :
  Result (Array core.core_arch.x86.__m512i 8#usize)
  := do
  let low ←
    bls.fp8.index_vector
      (Array.make 8#usize [
        first, 8#i64, 2#i64, 10#i64, 4#i64, 12#i64, 6#i64, 14#i64
        ] (by rfl))
  let high ←
    bls.fp8.index_vector
      (Array.make 8#usize [
        1#i64, 9#i64, 3#i64, 11#i64, 5#i64, 13#i64, 7#i64, 15#i64
        ] (by rfl))
  let mi ← Array.index_usize r 0#usize
  let mi1 ← Array.index_usize r 1#usize
  let mi2 ← core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi low mi1
  let mi3 ← core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi high mi1
  let mi4 ← Array.index_usize r 2#usize
  let mi5 ← Array.index_usize r 3#usize
  let mi6 ← core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi4 low mi5
  let mi7 ← core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi4 high mi5
  let mi8 ← Array.index_usize r 4#usize
  let mi9 ← Array.index_usize r 5#usize
  let mi10 ← core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi8 low mi9
  let mi11 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi8 high mi9
  let mi12 ← Array.index_usize r 6#usize
  let mi13 ← Array.index_usize r 7#usize
  let mi14 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi12 low mi13
  let mi15 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi12 high mi13
  let low1 ←
    bls.fp8.index_vector
      (Array.make 8#usize [
        0#i64, 1#i64, 8#i64, 9#i64, 4#i64, 5#i64, 12#i64, 13#i64
        ] (by rfl))
  let high1 ←
    bls.fp8.index_vector
      (Array.make 8#usize [
        2#i64, 3#i64, 10#i64, 11#i64, 6#i64, 7#i64, 14#i64, 15#i64
        ] (by rfl))
  let mi16 ←
    Array.index_usize
      (Array.make 8#usize [ mi2, mi3, mi6, mi7, mi10, mi11, mi14, mi15 ] (by rfl))
      0#usize
  let mi17 ←
    Array.index_usize
      (Array.make 8#usize [ mi2, mi3, mi6, mi7, mi10, mi11, mi14, mi15 ] (by rfl))
      2#usize
  let mi18 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi16 low1 mi17
  let mi19 ←
    Array.index_usize
      (Array.make 8#usize [ mi2, mi3, mi6, mi7, mi10, mi11, mi14, mi15 ] (by rfl))
      1#usize
  let mi20 ←
    Array.index_usize
      (Array.make 8#usize [ mi2, mi3, mi6, mi7, mi10, mi11, mi14, mi15 ] (by rfl))
      3#usize
  let mi21 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi19 low1 mi20
  let mi22 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi16 high1 mi17
  let mi23 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi19 high1 mi20
  let mi24 ←
    Array.index_usize
      (Array.make 8#usize [ mi2, mi3, mi6, mi7, mi10, mi11, mi14, mi15 ] (by rfl))
      4#usize
  let mi25 ←
    Array.index_usize
      (Array.make 8#usize [ mi2, mi3, mi6, mi7, mi10, mi11, mi14, mi15 ] (by rfl))
      6#usize
  let mi26 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi24 low1 mi25
  let mi27 ←
    Array.index_usize
      (Array.make 8#usize [ mi2, mi3, mi6, mi7, mi10, mi11, mi14, mi15 ] (by rfl))
      5#usize
  let mi28 ←
    Array.index_usize
      (Array.make 8#usize [ mi2, mi3, mi6, mi7, mi10, mi11, mi14, mi15 ] (by rfl))
      7#usize
  let mi29 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi27 low1 mi28
  let mi30 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi24 high1 mi25
  let mi31 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi27 high1 mi28
  let low2 ←
    bls.fp8.index_vector
      (Array.make 8#usize [
        0#i64, 1#i64, 2#i64, 3#i64, 8#i64, 9#i64, 10#i64, 11#i64
        ] (by rfl))
  let high2 ←
    bls.fp8.index_vector
      (Array.make 8#usize [
        4#i64, 5#i64, 6#i64, 7#i64, 12#i64, 13#i64, 14#i64, 15#i64
        ] (by rfl))
  let mi32 ←
    Array.index_usize
      (Array.make 8#usize [ mi18, mi21, mi22, mi23, mi26, mi29, mi30, mi31 ] (by rfl))
      0#usize
  let mi33 ←
    Array.index_usize
      (Array.make 8#usize [ mi18, mi21, mi22, mi23, mi26, mi29, mi30, mi31 ] (by rfl))
      4#usize
  let mi34 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi32 low2 mi33
  let mi35 ←
    Array.index_usize
      (Array.make 8#usize [ mi18, mi21, mi22, mi23, mi26, mi29, mi30, mi31 ] (by rfl))
      1#usize
  let mi36 ←
    Array.index_usize
      (Array.make 8#usize [ mi18, mi21, mi22, mi23, mi26, mi29, mi30, mi31 ] (by rfl))
      5#usize
  let mi37 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi35 low2 mi36
  let mi38 ←
    Array.index_usize
      (Array.make 8#usize [ mi18, mi21, mi22, mi23, mi26, mi29, mi30, mi31 ] (by rfl))
      2#usize
  let mi39 ←
    Array.index_usize
      (Array.make 8#usize [ mi18, mi21, mi22, mi23, mi26, mi29, mi30, mi31 ] (by rfl))
      6#usize
  let mi40 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi38 low2 mi39
  let mi41 ←
    Array.index_usize
      (Array.make 8#usize [ mi18, mi21, mi22, mi23, mi26, mi29, mi30, mi31 ] (by rfl))
      3#usize
  let mi42 ←
    Array.index_usize
      (Array.make 8#usize [ mi18, mi21, mi22, mi23, mi26, mi29, mi30, mi31 ] (by rfl))
      7#usize
  let mi43 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi41 low2 mi42
  let mi44 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi32 high2 mi33
  let mi45 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi35 high2 mi36
  let mi46 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi38 high2 mi39
  let mi47 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi41 high2 mi42
  ok (Array.make 8#usize [ mi34, mi37, mi40, mi43, mi44, mi45, mi46, mi47 ] (by rfl))


example : transposeWithFirstIndex 0#i64 = bls.fp8.transpose8 := rfl

def grid : Array M512 8#usize :=
  toArray id (Vector.ofFn fun row : Fin 8 =>
    Vector.ofFn fun lane : Fin 8 => UInt64.ofNat (8*row.val+lane.val))

def firstLane (result : Result (Array M512 8#usize)) : UInt64 :=
  match result with
  | .ok rows => (rows.val[0]!)[0]
  | _ => 0

theorem original_transpose_first_lane : firstLane (bls.fp8.transpose8 grid) = 0 := by
  decide +kernel

theorem wrong_transpose_index_changes_first_lane :
    firstLane (transposeWithFirstIndex 1#i64 grid) ≠ firstLane (bls.fp8.transpose8 grid) := by
  decide +kernel

end LeanBlsSimd.Controls.Transpose

#print axioms LeanBlsSimd.Controls.Transpose.original_transpose_first_lane
#print axioms LeanBlsSimd.Controls.Transpose.wrong_transpose_index_changes_first_lane
