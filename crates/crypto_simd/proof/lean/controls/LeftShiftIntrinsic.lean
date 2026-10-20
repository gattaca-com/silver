import LeanBlsSimd.Extracted.FunsExternal

namespace LeanBlsSimd.LeftShiftIntrinsic.Controls

theorem lane_preserved (a : M512) (imm : Nat) (lane : Fin 8) :
    (_mm512_slli_epi64 imm a)[lane] = slli imm a[lane] := by
  simp [_mm512_slli_epi64]

theorem large_immediate_zero (a : UInt64) (imm : Nat) (h : 64 ≤ imm) :
    slli imm a = 0 := by
  simp [slli, Nat.not_lt.mpr h]

def distinctLanes : M512 := #v[1, 2, 3, 4, 5, 6, 7, 8]

example : _mm512_slli_epi64 0 distinctLanes = distinctLanes := by decide +kernel

example : _mm512_slli_epi64 1 distinctLanes = #v[2, 4, 6, 8, 10, 12, 14, 16] := by
  decide +kernel

example : slli 63 1 = UInt64.ofNat (2 ^ 63) ∧ slli 63 2 = 0 := by decide +kernel

example : _mm512_slli_epi64 64 distinctLanes = _mm512_setzero_si512 ∧
    _mm512_slli_epi64 65 distinctLanes = _mm512_setzero_si512 ∧
    _mm512_slli_epi64 255 distinctLanes = _mm512_setzero_si512 := by decide +kernel

example : slli 1 (UInt64.ofNat (2 ^ 63 + 1)) = 2 := by decide +kernel

example (a : M512) : core.core_arch.x86.avx512f._mm512_slli_epi64 63#u32 a =
    Aeneas.Std.Result.ok (_mm512_slli_epi64 63 a) := rfl

example : slli 8 0x0102030405060708 ≠ slli 16 0x0102030405060708 := by decide +kernel

example : (_mm512_slli_epi64 1 distinctLanes)[0] ≠ slli 1 distinctLanes[1] := by
  decide +kernel

example : True := by
  fail_if_success
    have : slli 64 1 = 1 := by decide +kernel
  fail_if_success
    have : (slli 1 (UInt64.ofNat (2 ^ 63 + 1))).toNat = 2 ^ 64 + 2 := by decide +kernel
  fail_if_success
    have : _mm512_slli_epi64 1 distinctLanes = #v[4, 6, 8, 10, 12, 14, 16, 2] := by
      decide +kernel
  trivial

#print axioms lane_preserved
#print axioms large_immediate_zero

end LeanBlsSimd.LeftShiftIntrinsic.Controls
