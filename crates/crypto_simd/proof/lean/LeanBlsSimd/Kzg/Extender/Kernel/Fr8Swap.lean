import LeanBlsSimd.Refines.Fr8Core
import Init.Data.BitVec.Bitblast

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel.BytePacking

def swapWord (word : UInt64) : UInt64 :=
  let halves := (word <<< 32) + (word >>> 32)
  let pairs := ((halves &&& 0x0000ffff0000ffff) <<< 16) +
    ((halves >>> 16) &&& 0x0000ffff0000ffff)
  ((pairs &&& 0x00ff00ff00ff00ff) <<< 8) + ((pairs >>> 8) &&& 0x00ff00ff00ff00ff)

private def swapBits (word : BitVec 64) : BitVec 64 :=
  let halves := (word <<< (32 : Nat)) + (word >>> (32 : Nat))
  let pairs := ((halves &&& (0x0000ffff0000ffff : BitVec 64)) <<< (16 : Nat)) +
    ((halves >>> (16 : Nat)) &&& (0x0000ffff0000ffff : BitVec 64))
  ((pairs &&& (0x00ff00ff00ff00ff : BitVec 64)) <<< (8 : Nat)) +
    ((pairs >>> (8 : Nat)) &&& (0x00ff00ff00ff00ff : BitVec 64))

private theorem swap32_add_or (x : BitVec 64) :
    (x <<< 32) + (x >>> 32) = (x <<< 32) ||| (x >>> 32) := by
  apply BitVec.add_eq_or_of_and_eq_zero
  ext i hi
  interval_cases i <;> simp

private theorem swap16_add_or (x : BitVec 64) :
    ((x &&& (0x0000ffff0000ffff : BitVec 64)) <<< (16 : Nat)) +
        ((x >>> (16 : Nat)) &&& (0x0000ffff0000ffff : BitVec 64)) =
      ((x &&& (0x0000ffff0000ffff : BitVec 64)) <<< (16 : Nat)) |||
        ((x >>> (16 : Nat)) &&& (0x0000ffff0000ffff : BitVec 64)) := by
  apply BitVec.add_eq_or_of_and_eq_zero
  ext i hi
  interval_cases i <;> simp

private theorem swap8_add_or (x : BitVec 64) :
    ((x &&& (0x00ff00ff00ff00ff : BitVec 64)) <<< (8 : Nat)) +
        ((x >>> (8 : Nat)) &&& (0x00ff00ff00ff00ff : BitVec 64)) =
      ((x &&& (0x00ff00ff00ff00ff : BitVec 64)) <<< (8 : Nat)) |||
        ((x >>> (8 : Nat)) &&& (0x00ff00ff00ff00ff : BitVec 64)) := by
  apply BitVec.add_eq_or_of_and_eq_zero
  ext i hi
  interval_cases i <;> simp

theorem swapWord_testBit (word : UInt64) (i : Nat) (hi : i < 64) :
    (swapWord word).toNat.testBit i = word.toNat.testBit (8 * (7 - i / 8) + i % 8) := by
  change (swapBits word.toBitVec).getLsbD i = word.toBitVec.getLsbD _
  dsimp only [swapBits]
  rw [swap32_add_or, swap16_add_or, swap8_add_or]
  interval_cases i <;> simp

theorem swap_bytes_refines (x : M512) :
    fr8.u256x8.swap_bytes x = ok (Vector.ofFn fun lane => swapWord x[lane]) := by
  unfold fr8.u256x8.swap_bytes
  simp only [core.core_arch.x86.avx512f._mm512_slli_epi64,
    core.core_arch.x86.avx512f._mm512_srli_epi64,
    core.core_arch.x86.avx512f._mm512_and_si512,
    core.core_arch.x86.avx512f._mm512_add_epi64, FrModel.Simd.splat_refines, bind_tc_ok]
  apply congrArg ok
  apply Vector.ext
  intro lane hl
  simp only [swapWord, _mm512_slli_epi64, _mm512_srli_epi64, _mm512_and_si512,
    _mm512_add_epi64, FrModel.Simd.splat, _mm512_set1_epi64,
    Fin.getElem_fin, Vector.getElem_ofFn, Vector.getElem_replicate]
  rfl

end LeanBlsSimd.Kzg.Extender.Kernel.BytePacking
