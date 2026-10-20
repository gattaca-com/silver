import LeanBlsSimd.Kzg.Extender.Kernel.Fr8Swap

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Controls.ByteSwap

open Kernel Kernel.BytePacking

private def swapWithMask (mask : Std.U64)
  (x : core.core_arch.x86.__m512i) : Result core.core_arch.x86.__m512i := do
  let mi ← core.core_arch.x86.avx512f._mm512_slli_epi64 32#u32 x
  let mi1 ← core.core_arch.x86.avx512f._mm512_srli_epi64 32#u32 x
  let x1 ← core.core_arch.x86.avx512f._mm512_add_epi64 mi mi1
  let low_16 ← kzg.fr8.splat 281470681808895#u64
  let mi2 ← core.core_arch.x86.avx512f._mm512_and_si512 x1 low_16
  let mi3 ← core.core_arch.x86.avx512f._mm512_slli_epi64 16#u32 mi2
  let mi4 ← core.core_arch.x86.avx512f._mm512_srli_epi64 16#u32 x1
  let mi5 ← core.core_arch.x86.avx512f._mm512_and_si512 mi4 low_16
  let x2 ← core.core_arch.x86.avx512f._mm512_add_epi64 mi3 mi5
  let low_8 ← kzg.fr8.splat mask
  let mi6 ← core.core_arch.x86.avx512f._mm512_and_si512 x2 low_8
  let mi7 ← core.core_arch.x86.avx512f._mm512_slli_epi64 8#u32 mi6
  let mi8 ← core.core_arch.x86.avx512f._mm512_srli_epi64 8#u32 x2
  let mi9 ← core.core_arch.x86.avx512f._mm512_and_si512 mi8 low_8
  core.core_arch.x86.avx512f._mm512_add_epi64 mi7 mi9

example : swapWithMask 0x00ff00ff00ff00ff#u64 = fr8.u256x8.swap_bytes := rfl

example : swapWord 0x0102030405060708 = 0x0807060504030201 := by decide +kernel

private def sample : M512 := Vector.replicate 8 0x0102030405060708

private def firstLane (result : Result M512) : UInt64 :=
  match result with
  | .ok out => out[0]
  | _ => 0

example : firstLane (swapWithMask 0x00ff00ff00ff00ff#u64 sample) =
    0x0807060504030201 := by decide +kernel

example : swapWithMask 0x00f700ff00ff00ff#u64 sample ≠
    ok (Vector.replicate 8 0x0807060504030201) := by
  intro h
  have observed := congrArg firstLane h
  have rejected : firstLane (swapWithMask 0x00f700ff00ff00ff#u64 sample) ≠
      0x0807060504030201 := by decide +kernel
  exact rejected observed

example : True := by
  fail_if_success
    have : firstLane (swapWithMask 0x00f700ff00ff00ff#u64 sample) =
        0x0807060504030201 := by decide +kernel
  trivial

#print axioms swap_bytes_refines
#print axioms swapWord_testBit

end LeanBlsSimd.Kzg.Extender.Controls.ByteSwap
