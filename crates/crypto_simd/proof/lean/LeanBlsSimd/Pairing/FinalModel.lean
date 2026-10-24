import LeanBlsSimd.Spec.FinalExponentiation
import LeanBlsSimd.Spec.Cyclotomic.Field

open EthLib.Cryptography Bls

namespace LeanBlsSimd.Pairing.FinalExponent

set_option maxRecDepth 8000
set_option maxHeartbeats 2000000
set_option exponentiation.threshold 20000

abbrev p : Nat := Fp.modulus

def phi : Nat := p ^ 4 - p ^ 2 + 1

def Good (a : Bls.Fp12) : Prop := Fp12.toField a = 0 ∨ Fp12.toField a ^ phi = 1

def frobenius (a : Bls.Fp12) : Bls.Fp12 := Bls.Fp12.powNat a p

def exp (a : Bls.Fp12) : Bls.Fp12 := (Bls.Fp12.powNat a blsX).conjugate

def easy (a : Bls.Fp12) : Bls.Fp12 :=
  let t := a.conjugate * a.inverse
  frobenius (frobenius t) * t

/-- The common generated hard-part schedule, instantiated with values or exponents. -/
def hardChain {α : Type} (mul : α → α → α) (square conjugate exp frobenius : α → α) (a : α) : α :=
  let t11 := conjugate (square a)
  let t3 := exp a
  let t4 := square t3
  let t5 := mul t11 t3
  let t12 := exp t5
  let t01 := exp t12
  let t6 := mul (exp t01) t4
  let t41 := exp t6
  let t42 := mul t41 (mul (conjugate t5) a)
  let t13 := frobenius (frobenius (frobenius (mul t12 a)))
  let t61 := frobenius (mul t6 (conjugate a))
  let t31 := frobenius (frobenius (mul t3 t01))
  mul (mul (mul t31 t13) t61) t42

def hard (a : Bls.Fp12) : Bls.Fp12 :=
  hardChain (· * ·) Bls.Fp12.square Bls.Fp12.conjugate exp frobenius a

def optimized (a : Bls.Fp12) : Bls.Fp12 := hard (easy a)

def hardExponent : Nat := hardChain (· + ·) (· * 2) (· * p ^ 6)
  (fun n => n * blsX * p ^ 6) (· * p) 1

def easyExponent : Nat := (p ^ 6 + (p ^ 12 - 2)) * (p * p + 1)

def exponent : Nat := easyExponent * hardExponent

def period : Nat := p ^ 12 - 1

theorem inverse_power (x : Fp12Field) : x⁻¹ = x ^ (p ^ 12 - 2) := by
  by_cases hx : x = 0
  · subst x
    simp only [inv_zero, zero_pow (by decide +kernel : p ^ 12 - 2 ≠ 0)]
  · symm
    apply eq_inv_of_mul_eq_one_left
    rw [← pow_succ, show p ^ 12 - 2 + 1 = p ^ 12 - 1 from by decide +kernel,
      ← Fp12Field.card_eq]
    exact FiniteField.pow_card_sub_one_eq_one x hx

theorem easy_field (a : Bls.Fp12) :
    Fp12.toField (easy a) = Cyclotomic.fieldEasyPart (Fp12.toField a) := by
  simp only [easy, frobenius, Fp12.toField_powNat, map_mul, Fp12.toField_conjugate,
    Fp12.toField_inverse, Cyclotomic.fieldEasyPart, ← pow_mul, pow_two]

theorem easy_power (a : Bls.Fp12) : Fp12.toField (easy a) = Fp12.toField a ^ easyExponent := by
  simp only [easy, frobenius, Fp12.toField_powNat, map_mul, Cyclotomic.spec_conjugate,
    Fp12.toField_inverse, inverse_power, ← pow_add, ← pow_mul, easyExponent]
  congr 1

theorem chain_power {K : Type} [CommMonoid K] (x : K) (p z : Nat) :
    hardChain (· * ·) (· ^ 2) (· ^ (p ^ 6))
      (fun a => (a ^ z) ^ (p ^ 6)) (· ^ p) x =
      x ^ (hardChain (· + ·) (· * 2) (· * p ^ 6) (fun n => n * z * p ^ 6) (· * p) 1) := by
  simp only [hardChain, ← pow_mul, ← pow_add, ← pow_succ, one_mul]

theorem hardChain_map {α β : Type} (f : α → β)
    (mul : α → α → α) (square conjugate exp frobenius : α → α)
    (mul' : β → β → β) (square' conjugate' exp' frobenius' : β → β)
    (hm : ∀ a b, f (mul a b) = mul' (f a) (f b))
    (hs : ∀ a, f (square a) = square' (f a))
    (hc : ∀ a, f (conjugate a) = conjugate' (f a))
    (he : ∀ a, f (exp a) = exp' (f a))
    (hf : ∀ a, f (frobenius a) = frobenius' (f a)) (a : α) :
    f (hardChain mul square conjugate exp frobenius a) =
      hardChain mul' square' conjugate' exp' frobenius' (f a) := by
  simp only [hardChain, hm, hs, hc, he, hf]

theorem exp_field (a : Bls.Fp12) : Fp12.toField (exp a) = (Fp12.toField a ^ blsX) ^ (p ^ 6) := by
  rw [exp, Cyclotomic.spec_conjugate, Fp12.toField_powNat]

theorem hard_power (a : Bls.Fp12) : Fp12.toField (hard a) = Fp12.toField a ^ hardExponent := by
  have h := hardChain_map Fp12.toField (· * ·) Bls.Fp12.square Bls.Fp12.conjugate exp frobenius
    (· * ·) (· ^ 2) (· ^ (p ^ 6)) (fun x => (x ^ blsX) ^ (p ^ 6)) (· ^ p)
    Fp12.toField.map_mul Fp12.toField_square Cyclotomic.spec_conjugate exp_field
    (fun x => Fp12.toField_powNat x p) a
  exact h.trans (chain_power (Fp12.toField a) p blsX)


theorem optimized_power (a : Bls.Fp12) : Fp12.toField (optimized a) = Fp12.toField a ^ exponent := by
  rw [optimized, hard_power, easy_power, ← pow_mul]
  rfl

theorem exponent_certificate : exponent % period = (3 * finalExpExponent) % period := by
  decide +kernel

theorem exponent_positive : 0 < exponent := by decide +kernel

theorem cube_coprime : Nat.Coprime 3 Fr.modulus := by decide +kernel

end LeanBlsSimd.Pairing.FinalExponent
