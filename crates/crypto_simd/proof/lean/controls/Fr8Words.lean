import LeanBlsSimd.Kzg.Extender.Kernel.Fr8Words

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Controls.WordPacking

open Kernel Kernel.BytePacking

def limbsWithShift (shift : Std.U32)
  (self : kzg.fr8.u256x8.U256x8) :
  Result (Array core.core_arch.x86.__m512i 5#usize)
  := do
  let i ← kzg.fr8.MASK52
  let mask ← kzg.fr8.splat i
  let mi ← Array.index_usize self 0#usize
  let mi1 ← core.core_arch.x86.avx512f._mm512_and_si512 mi mask
  let mi2 ← core.core_arch.x86.avx512f._mm512_srli_epi64 52#u32 mi
  let mi3 ← Array.index_usize self 1#usize
  let mi4 ← core.core_arch.x86.avx512f._mm512_slli_epi64 shift mi3
  let mi5 ← core.core_arch.x86.avx512f._mm512_add_epi64 mi2 mi4
  let mi6 ← core.core_arch.x86.avx512f._mm512_and_si512 mi5 mask
  let mi7 ← core.core_arch.x86.avx512f._mm512_srli_epi64 40#u32 mi3
  let mi8 ← Array.index_usize self 2#usize
  let mi9 ← core.core_arch.x86.avx512f._mm512_slli_epi64 24#u32 mi8
  let mi10 ← core.core_arch.x86.avx512f._mm512_add_epi64 mi7 mi9
  let mi11 ← core.core_arch.x86.avx512f._mm512_and_si512 mi10 mask
  let mi12 ← core.core_arch.x86.avx512f._mm512_srli_epi64 28#u32 mi8
  let mi13 ← Array.index_usize self 3#usize
  let mi14 ← core.core_arch.x86.avx512f._mm512_slli_epi64 36#u32 mi13
  let mi15 ← core.core_arch.x86.avx512f._mm512_add_epi64 mi12 mi14
  let mi16 ← core.core_arch.x86.avx512f._mm512_and_si512 mi15 mask
  let mi17 ← core.core_arch.x86.avx512f._mm512_srli_epi64 16#u32 mi13
  ok (Array.make 5#usize [ mi1, mi6, mi11, mi16, mi17 ] (by rfl))


def blocksWithIndex (index : Std.I64)
  (blocks : Array core.core_arch.x86.__m512i 4#usize) :
  Result kzg.fr8.u256x8.U256x8
  := do
  let low_words ←
    bls.fp8.index_vector
      (Array.make 8#usize [
        index, 7#i64, 11#i64, 15#i64, 2#i64, 6#i64, 10#i64, 14#i64
        ] (by rfl))
  let high_words ←
    bls.fp8.index_vector
      (Array.make 8#usize [
        1#i64, 5#i64, 9#i64, 13#i64, 0#i64, 4#i64, 8#i64, 12#i64
        ] (by rfl))
  let mi ← Array.index_usize blocks 0#usize
  let mi1 ← Array.index_usize blocks 1#usize
  let mi2 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi low_words mi1
  let mi3 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi high_words mi1
  let mi4 ← Array.index_usize blocks 2#usize
  let mi5 ← Array.index_usize blocks 3#usize
  let mi6 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi4 low_words mi5
  let mi7 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi4 high_words mi5
  let first_halves ←
    bls.fp8.index_vector
      (Array.make 8#usize [
        0#i64, 1#i64, 2#i64, 3#i64, 8#i64, 9#i64, 10#i64, 11#i64
        ] (by rfl))
  let second_halves ←
    bls.fp8.index_vector
      (Array.make 8#usize [
        4#i64, 5#i64, 6#i64, 7#i64, 12#i64, 13#i64, 14#i64, 15#i64
        ] (by rfl))
  let mi8 ←
    Array.index_usize (Array.make 4#usize [ mi2, mi3, mi6, mi7 ] (by rfl)) 0#usize
  let mi9 ←
    Array.index_usize (Array.make 4#usize [ mi2, mi3, mi6, mi7 ] (by rfl)) 2#usize
  let mi10 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi8 first_halves mi9
  let mi11 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi8 second_halves mi9
  let mi12 ←
    Array.index_usize (Array.make 4#usize [ mi2, mi3, mi6, mi7 ] (by rfl)) 1#usize
  let mi13 ←
    Array.index_usize (Array.make 4#usize [ mi2, mi3, mi6, mi7 ] (by rfl)) 3#usize
  let mi14 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi12 first_halves mi13
  let mi15 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi12 second_halves
      mi13
  ok (Array.make 4#usize [ mi10, mi11, mi14, mi15 ] (by rfl))


def encodeBlocksWithIndex (index : Std.I64)
  (self : kzg.fr8.u256x8.U256x8) :
  Result (Array core.core_arch.x86.__m512i 4#usize)
  := do
  let first_halves ←
    bls.fp8.index_vector
      (Array.make 8#usize [
        0#i64, 1#i64, 2#i64, 3#i64, 8#i64, 9#i64, 10#i64, 11#i64
        ] (by rfl))
  let second_halves ←
    bls.fp8.index_vector
      (Array.make 8#usize [
        4#i64, 5#i64, 6#i64, 7#i64, 12#i64, 13#i64, 14#i64, 15#i64
        ] (by rfl))
  let mi ← Array.index_usize self 0#usize
  let mi1 ← Array.index_usize self 1#usize
  let mi2 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi first_halves mi1
  let mi3 ← Array.index_usize self 2#usize
  let mi4 ← Array.index_usize self 3#usize
  let mi5 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi3 first_halves mi4
  let mi6 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi second_halves mi1
  let mi7 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi3 second_halves mi4
  let even_block ←
    bls.fp8.index_vector
      (Array.make 8#usize [
        index, 8#i64, 4#i64, 0#i64, 13#i64, 9#i64, 5#i64, 1#i64
        ] (by rfl))
  let odd_block ←
    bls.fp8.index_vector
      (Array.make 8#usize [
        14#i64, 10#i64, 6#i64, 2#i64, 15#i64, 11#i64, 7#i64, 3#i64
        ] (by rfl))
  let mi8 ←
    Array.index_usize (Array.make 4#usize [ mi2, mi5, mi6, mi7 ] (by rfl)) 0#usize
  let mi9 ←
    Array.index_usize (Array.make 4#usize [ mi2, mi5, mi6, mi7 ] (by rfl)) 1#usize
  let mi10 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi8 even_block mi9
  let mi11 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi8 odd_block mi9
  let mi12 ←
    Array.index_usize (Array.make 4#usize [ mi2, mi5, mi6, mi7 ] (by rfl)) 2#usize
  let mi13 ←
    Array.index_usize (Array.make 4#usize [ mi2, mi5, mi6, mi7 ] (by rfl)) 3#usize
  let mi14 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi12 even_block mi13
  let mi15 ←
    core.core_arch.x86.avx512f._mm512_permutex2var_epi64 mi12 odd_block mi13
  ok (Array.make 4#usize [ mi10, mi11, mi14, mi15 ] (by rfl))


theorem limbsWithShift_matches : limbsWithShift 12#u32 = fr8.u256x8.U256x8.limbs := rfl

theorem blocksWithIndex_matches : blocksWithIndex 3#i64 = fr8.u256x8.U256x8.from_blocks := rfl

theorem encodeBlocksWithIndex_matches : encodeBlocksWithIndex 12#i64 = fr8.u256x8.U256x8.blocks := rfl

private def shiftInput : Vector M512 4 :=
  #v[Vector.replicate 8 0, Vector.replicate 8 1, Vector.replicate 8 0, Vector.replicate 8 0]

private def permutationInput : Vector M512 4 :=
  Vector.ofFn fun block => Vector.ofFn fun lane => UInt64.ofNat (8 * block.val + lane.val)

private def observedWord {n : Usize} (word : Nat) (result : Result (Array M512 n)) : UInt64 :=
  match result with
  | .ok out => (out.val[word]!)[0]
  | _ => 0

theorem wrong_shift_rejected :
    limbsWithShift 13#u32 (toArray id shiftInput) ≠
      ok (toArray id (transpose (Vector.ofFn fun lane => unpack (wordLane shiftInput lane)))) := by
  intro h
  have observed := congrArg (observedWord 1) h
  have rejected : observedWord 1 (limbsWithShift 13#u32 (toArray id shiftInput)) ≠
      observedWord (n := 5#usize) 1 (ok (toArray id
        (transpose (Vector.ofFn fun lane => unpack (wordLane shiftInput lane))))) := by
    decide +kernel
  exact rejected observed

theorem wrong_permutation_rejected :
    blocksWithIndex 2#i64 (toArray id permutationInput) ≠
      ok (toArray id (fromBlocks permutationInput)) := by
  intro h
  have observed := congrArg (observedWord 0) h
  have rejected : observedWord 0 (blocksWithIndex 2#i64 (toArray id permutationInput)) ≠
      observedWord (n := 4#usize) 0 (ok (toArray id (fromBlocks permutationInput))) := by
    decide +kernel
  exact rejected observed

theorem wrong_encode_permutation_rejected :
    encodeBlocksWithIndex 13#i64 (toArray id permutationInput) ≠
      ok (toArray id (wordBlocks permutationInput)) := by
  intro h
  have observed := congrArg (observedWord 0) h
  have rejected : observedWord 0 (encodeBlocksWithIndex 13#i64 (toArray id permutationInput)) ≠
      observedWord (n := 4#usize) 0 (ok (toArray id (wordBlocks permutationInput))) := by
    decide +kernel
  exact rejected observed

end LeanBlsSimd.Kzg.Extender.Controls.WordPacking
