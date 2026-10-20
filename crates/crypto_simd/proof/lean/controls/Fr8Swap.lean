import LeanBlsSimd.Kzg.Extender.Kernel.Fr8Swap

namespace LeanBlsSimd.Kzg.Extender.Controls.ByteSwap

open Kernel.BytePacking

private def swapWithMask (mask : UInt64) (word : UInt64) : UInt64 :=
  let halves := (word <<< 32) + (word >>> 32)
  let pairs := ((halves &&& 0x0000ffff0000ffff) <<< 16) +
    ((halves >>> 16) &&& 0x0000ffff0000ffff)
  ((pairs &&& mask) <<< 8) + ((pairs >>> 8) &&& mask)

example : swapWithMask 0x00ff00ff00ff00ff = swapWord := rfl

example : swapWord 0x0102030405060708 = 0x0807060504030201 := by decide +kernel

example : swapWithMask 0x00f700ff00ff00ff 0x0102030405060708 ≠
    swapWord 0x0102030405060708 := by decide +kernel

example : True := by
  fail_if_success
    have : swapWithMask 0x00f700ff00ff00ff 0x0102030405060708 =
        0x0807060504030201 := by decide +kernel
  trivial

#print axioms swap_bytes_refines
#print axioms swapWord_testBit

end LeanBlsSimd.Kzg.Extender.Controls.ByteSwap
