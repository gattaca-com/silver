import LeanBlsSimd.Proofs.Vector
import LeanBlsSimd.Proofs.SignedLimbs

namespace LeanBlsSimd.Fp8

open EthCryptographySpecs.Bls

private theorem multiple_of_p_lane (c : UInt64) (l : Fin 8) :
    let n0 := 0xeffffffffaaab * c.toNat
    let n1 := 0xfeb153ffffb9f * c.toNat + n0 / 2 ^ 52
    let n2 := 0x6b0f6241eabff * c.toNat + n1 / 2 ^ 52
    let n3 := 0x12bf6730d2a0f * c.toNat + n2 / 2 ^ 52
    let n4 := 0x764774b84f385 * c.toNat + n3 / 2 ^ 52
    let n5 := 0x1ba7b6434bacd * c.toNat + n4 / 2 ^ 52
    let n6 := 0x1ea397fe69a4b * c.toNat + n5 / 2 ^ 52
    let n7 := 0x000000001a011 * c.toNat + n6 / 2 ^ 52
    (multiple_of_p c).lane l = #v[
      UInt64.ofNat n0 &&& UInt64.ofNat MASK52,
      UInt64.ofNat n1 &&& UInt64.ofNat MASK52,
      UInt64.ofNat n2 &&& UInt64.ofNat MASK52,
      UInt64.ofNat n3 &&& UInt64.ofNat MASK52,
      UInt64.ofNat n4 &&& UInt64.ofNat MASK52,
      UInt64.ofNat n5 &&& UInt64.ofNat MASK52,
      UInt64.ofNat n6 &&& UInt64.ofNat MASK52,
      UInt64.ofNat n7 &&& UInt64.ofNat MASK52] := by
  have hf : List.finRange LIMBS = [0, 1, 2, 3, 4, 5, 6, 7] := by decide
  simp only [multiple_of_p, hf, List.foldl_cons, List.foldl_nil, multipleStep]
  ext j hj
  change j < 8 at hj
  interval_cases j <;> simp [lane, Limbs.ofList, P, LIMBS] <;> rfl

private theorem multiple_digit (n : ℕ) :
    (UInt64.ofNat n &&& UInt64.ofNat MASK52).toNat = n % 2 ^ 52 := by
  rw [Lane.toNat_and_mask _ _ (by decide), UInt64.toNat_ofNat']
  exact Nat.mod_mod_of_dvd n (by norm_num)

set_option exponentiation.threshold 1000 in
theorem multiple_of_p_spec (c : UInt64) (hc : c.toNat < 4096) (l : Fin 8) :
    SignedLimbs.Normalized ((multiple_of_p c).lane l) ∧
      val ((multiple_of_p c).lane l) = c.toNat * Fp.modulus := by
  let n0 := 0xeffffffffaaab * c.toNat
  let n1 := 0xfeb153ffffb9f * c.toNat + n0 / 2 ^ 52
  let n2 := 0x6b0f6241eabff * c.toNat + n1 / 2 ^ 52
  let n3 := 0x12bf6730d2a0f * c.toNat + n2 / 2 ^ 52
  let n4 := 0x764774b84f385 * c.toNat + n3 / 2 ^ 52
  let n5 := 0x1ba7b6434bacd * c.toNat + n4 / 2 ^ 52
  let n6 := 0x1ea397fe69a4b * c.toNat + n5 / 2 ^ 52
  let n7 := 0x000000001a011 * c.toNat + n6 / 2 ^ 52
  have he := multiple_of_p_lane c l
  change (multiple_of_p c).lane l = #v[
    UInt64.ofNat n0 &&& UInt64.ofNat MASK52, UInt64.ofNat n1 &&& UInt64.ofNat MASK52,
    UInt64.ofNat n2 &&& UInt64.ofNat MASK52, UInt64.ofNat n3 &&& UInt64.ofNat MASK52,
    UInt64.ofNat n4 &&& UInt64.ofNat MASK52, UInt64.ofNat n5 &&& UInt64.ofNat MASK52,
    UInt64.ofNat n6 &&& UInt64.ofNat MASK52, UInt64.ofNat n7 &&& UInt64.ofNat MASK52] at he
  rw [he]
  constructor
  · intro j
    fin_cases j
    all_goals change (UInt64.ofNat _ &&& UInt64.ofNat MASK52).toNat < 2 ^ 52
    all_goals rw [multiple_digit]; exact Nat.mod_lt _ (by norm_num)
  · rw [val, sum_fin_limbs]
    simp only [val_fin_LIMBS, LIMB_BITS, Nat.reduceMul, pow_zero, mul_one]
    change (UInt64.ofNat n0 &&& UInt64.ofNat MASK52).toNat +
      (UInt64.ofNat n1 &&& UInt64.ofNat MASK52).toNat * 2 ^ 52 +
      (UInt64.ofNat n2 &&& UInt64.ofNat MASK52).toNat * 2 ^ 104 +
      (UInt64.ofNat n3 &&& UInt64.ofNat MASK52).toNat * 2 ^ 156 +
      (UInt64.ofNat n4 &&& UInt64.ofNat MASK52).toNat * 2 ^ 208 +
      (UInt64.ofNat n5 &&& UInt64.ofNat MASK52).toNat * 2 ^ 260 +
      (UInt64.ofNat n6 &&& UInt64.ofNat MASK52).toNat * 2 ^ 312 +
      (UInt64.ofNat n7 &&& UInt64.ofNat MASK52).toNat * 2 ^ 364 = _
    simp only [multiple_digit]
    dsimp [n0, n1, n2, n3, n4, n5, n6, n7]
    norm_num [Fp.modulus] at *
    omega

end LeanBlsSimd.Fp8
