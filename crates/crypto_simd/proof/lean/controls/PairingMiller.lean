import LeanBlsSimd.Pairing.LaneMiller

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.bls
open LeanBlsSimd

namespace PairingMillerControl

set_option maxRecDepth 4000

def lazyZero : Fp8 := Fp8.splat_limbs (.ofList P)

theorem lazy_zero_raw_value (l : Fin 8) : val (lazyZero.lane l) = Fp.modulus := by
  rw [lazyZero, Fp8.lane_splat_limbs]
  exact Lane.val_splat_P

theorem lazy_zero_holds (l : Fin 8) : lazyZero.Holds l 0 := by
  constructor
  · rw [lazyZero, Fp8.lane_splat_limbs]
    exact ⟨by decide +kernel, by decide +kernel⟩
  · rw [decode, lazy_zero_raw_value, ZMod.natCast_self, zero_mul]

theorem lazy_zero_mask : fp8.Fp8.is_zero_mask (toFp8 lazyZero) = ok 255#u8 := by
  rw [Fp8.is_zero_mask_refines, ofFp8_toFp8]
  have hm : lazyZero.is_zero_mask = 255 := by
    apply UInt8.toNat_inj.mp
    apply Nat.eq_of_testBit_eq
    intro l
    by_cases hl : l < 8
    · rw [(lazy_zero_holds ⟨l, hl⟩).testBit_is_zero_mask]
      interval_cases l <;> decide
    · rw [Nat.testBit_lt_two_pow (lazyZero.is_zero_mask.toNat_lt.trans_le
        (Nat.pow_le_pow_right (by decide) (by omega)))]
      symm
      exact Nat.testBit_lt_two_pow (lt_of_lt_of_le (by decide : 255 < 2^8)
        (Nat.pow_le_pow_right (by decide) (by omega)))
  rw [hm]
  rfl

theorem lazy_zero_skip : Pairing.LaneLines.maskPresence (~~~ toU8 lazyZero.is_zero_mask) =
    Array.make 2#usize [false, false] (by rfl) := by
  have h := lazy_zero_mask
  rw [Fp8.is_zero_mask_refines, ofFp8_toFp8] at h
  have he : toU8 lazyZero.is_zero_mask = 255#u8 := Result.ok.inj h
  rw [he]
  rfl

end PairingMillerControl
