import LeanBlsSimd.Pairing.FinalModel

open EthLib.Cryptography Bls

namespace LeanBlsSimd.Pairing.FinalExponent

set_option maxRecDepth 4000

def Root (x : Fp12Field) : Prop := x = 0 ∨ x ^ phi = 1

theorem Root.mul {x y : Fp12Field} (hx : Root x) (hy : Root y) : Root (x * y) := by
  rcases hx with hx | hx
  · exact Or.inl (by rw [hx, zero_mul])
  rcases hy with hy | hy
  · exact Or.inl (by rw [hy, mul_zero])
  exact Or.inr (by rw [mul_pow, hx, hy, one_mul])

theorem Root.pow {x : Fp12Field} (hx : Root x) (n : Nat) : Root (x ^ n) := by
  rcases hx with hx | hx
  · subst x
    cases n with
    | zero => exact Or.inr (by simp)
    | succ n => exact Or.inl (by simp)
  · apply Or.inr
    rw [← pow_mul, Nat.mul_comm, pow_mul, hx, one_pow]

theorem Good.mul {a b : Bls.Fp12} (ha : Good a) (hb : Good b) : Good (a * b) := by
  change Root (Fp12.toField (a * b))
  rw [map_mul]
  exact Root.mul ha hb

theorem Good.pow {a : Bls.Fp12} (ha : Good a) (n : Nat) : Good (Bls.Fp12.powNat a n) := by
  change Root (Fp12.toField (Bls.Fp12.powNat a n))
  rw [Fp12.toField_powNat]
  exact Root.pow ha n

theorem Good.square {a : Bls.Fp12} (ha : Good a) : Good a.square := by
  change Root (Fp12.toField a.square)
  rw [Fp12.toField_square]
  exact Root.pow ha 2

theorem Good.conjugate {a : Bls.Fp12} (ha : Good a) : Good a.conjugate := by
  change Root (Fp12.toField a.conjugate)
  rw [Cyclotomic.spec_conjugate]
  exact Root.pow ha _

theorem Good.exp {a : Bls.Fp12} (ha : Good a) : Good (exp a) := (ha.pow blsX).conjugate

theorem easy_good (a : Bls.Fp12) : Good (easy a) := by
  unfold Good
  rw [easy_field]
  by_cases h : Fp12.toField a = 0
  · exact Or.inl (by rw [h, Cyclotomic.field_easy_zero])
  · exact Or.inr (Cyclotomic.field_easy_cyclotomic _ h)

end LeanBlsSimd.Pairing.FinalExponent
