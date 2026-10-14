import LeanBlsSimd.Proofs.Fp2x8

/-! The mask test used by both G1 and G2 callers. -/

namespace LeanBlsSimd

theorem Mmask8.and_one_shiftLeft_ne_zero (m : Mmask8) (l : Fin 8) :
    m &&& (1 : Mmask8) <<< l.val.toUInt8 ≠ 0 ↔ m.toNat.testBit l = true := by
  have hbit (i : Fin 8) : (m &&& (1 : Mmask8) <<< l.val.toUInt8).toNat.testBit i =
      (m.toNat.testBit i && decide (i = l)) := by
    rw [Mmask8.testBit_and, Mmask8.testBit_one_shiftLeft]
  constructor
  · intro h
    by_contra hl
    apply h
    apply Mmask8.eq_zero_of_testBit
    intro i
    rw [hbit]
    by_cases hi : i = l
    · subst hi
      simpa using hl
    · simp [hi]
  · intro h h0
    have := hbit l
    rw [h0, Mmask8.testBit_zero, h] at this
    simp at this

end LeanBlsSimd
