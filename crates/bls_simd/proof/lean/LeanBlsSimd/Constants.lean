import EthCryptographySpecs.Bls.Pairing
import EthCryptographySpecs.Proofs.Bls.FpZMod
import Mathlib.NumberTheory.LegendreSymbol.Basic
import Mathlib.Tactic.LinearCombination

/-!
# Constants of `silver_bls_simd`

The tables of `crates/bls_simd/src/constants.rs`, transcribed verbatim, and each proved equal to
its derivation from p, R = 2^416 and z.

p, r and |z| are the definitions of `ethereum/cryptography-specs`: `Fp.modulus`, `Fr.modulus` and
`blsX`. Every computation runs in Lean's kernel (`decide +kernel`) on `ℕ` with explicit `% p`.
Facts about Fp are stated in `ZMod Fp.modulus`, which the spec identifies with `Fp` (`Fp.toZMod`).
Facts about Fp2 hold in every commutative ring where `p = 0` and `ι ^ 2 = -1`, so they apply to any
model of Fp2, `Fp2Field` among them. Only the non-residue facts use the primality of p.
-/

namespace LeanBlsSimd

open EthCryptographySpecs EthCryptographySpecs.Bls

/-! ## Parameters -/

/-- The BLS12-381 parameter, whose absolute value the spec calls `blsX`. -/
def z : ℤ := -blsX

def LIMBS : ℕ := 8

def LIMB_BITS : ℕ := 52

def MASK52 : ℕ := (1 <<< LIMB_BITS) - 1

def R : ℕ := 2 ^ (LIMBS * LIMB_BITS)

theorem r_eq : (Fr.modulus : ℤ) = z ^ 4 - z ^ 2 + 1 := by decide +kernel

theorem p_eq : 3 * ((Fp.modulus : ℤ) - z) = (z - 1) ^ 2 * Fr.modulus := by decide +kernel

theorem p_lt : Fp.modulus < 2 ^ 381 := by decide +kernel

theorem four_mul_p_lt_R : 4 * Fp.modulus < R := by decide +kernel

theorem p_mod_four : Fp.modulus % 4 = 3 := by decide +kernel

theorem p_mod_three : Fp.modulus % 3 = 1 := by decide +kernel

/-! ## Tables -/

def P : List ℕ := [
  0xeffffffffaaab,
  0xfeb153ffffb9f,
  0x6b0f6241eabff,
  0x12bf6730d2a0f,
  0x764774b84f385,
  0x1ba7b6434bacd,
  0x1ea397fe69a4b,
  0x000000001a011,
]

def P_U64 : List ℕ := [
  0xb9feffffffffaaab,
  0x1eabfffeb153ffff,
  0x6730d2a0f6b0f624,
  0x64774b84f38512bf,
  0x4b1ba7b6434bacd7,
  0x1a0111ea397fe69a,
]

def P_INV52 : ℕ := 0x3fffcfffcfffd

def R_MOD_P : List ℕ := [
  0x6480ea8e9b9af,
  0x65766c8fe444f,
  0x8b540fea96f7d,
  0x3b2ee82efd422,
  0xa6723e5f0ade5,
  0xff6eb6fdd4230,
  0xe06ef23c24a25,
  0x0000000014c8e,
]

def R2_MOD_P : List ℕ := [
  0xa5bf4cb89af51,
  0x3afbba7ca31a2,
  0x2646160ec71f1,
  0xa84d710465903,
  0x3480a4a188311,
  0x98e5907ad91f5,
  0x2075d74507266,
  0x0000000008746,
]

def TWO_POW_384_MOD_P : List ℕ := [
  0x900000002fffd,
  0x0bc40c0002760,
  0x3c758baebf400,
  0x57455f4898575,
  0xd77ce58537052,
  0x071a97a256ec6,
  0xec3fa80e4935c,
  0x0000000015f65,
]

def ONE_PLAIN : List ℕ := [1, 0, 0, 0, 0, 0, 0, 0]

def FOUR_MONT : List ℕ := [
  0xc203aa3a7e6bb,
  0x99c5b63f91e5d,
  0xec2218e49b9f5,
  0xb47d6b297d25b,
  0x36f29b533dd05,
  0xaac3b92d6d85a,
  0x25d100f5559b6,
  0x0000000005208,
]

def HALF_P_MINUS_1 : List ℕ := [
  0xf7fffffffd555,
  0xff58a9ffffdcf,
  0xb587b120f55ff,
  0x895fb39869507,
  0xbb23ba5c279c2,
  0x8dd3db21a5d66,
  0x8f51cbff34d25,
  0x000000000d008,
]

def P_MINUS_3_OVER_4_WINDOWS : List ℕ := [
  10, 10, 10, 14, 15, 15, 15, 15, 15, 15, 15, 11, 15, 7, 14, 14, 15, 15, 15, 15, 4, 5, 12, 10,
  15, 15, 15, 15, 10, 10, 7, 0, 9, 8, 13, 3, 12, 10, 13, 3, 8, 10, 4, 3, 12, 12, 9, 13, 15, 10,
  4, 4, 1, 14, 12, 3, 1, 14, 2, 13, 13, 1, 9, 13, 5, 3, 11, 14, 2, 13, 0, 9, 13, 14, 9, 14, 6,
  12, 2, 9, 6, 10, 9, 15, 15, 5, 14, 8, 10, 7, 4, 4, 0, 8, 6,
]

def Z_BITS : List ℕ := [63, 62, 60, 57, 48, 16]

def PSI_X_MONT : List ℕ := [
  0x18a5500cc654c,
  0x2e1c1e9482fe9,
  0xd5d532d24a460,
  0x023e982695377,
  0x36c99171ef509,
  0x19b0966cc23e1,
  0x44c5fb3cf7304,
  0x000000001227f,
]

def PSI_Y_MONT : List (List ℕ) := [
  [
    0x9c1a677c96161,
    0xf16c8708fcef3,
    0x94977d28093e6,
    0xa06b71c927307,
    0xb4fa740f70cc7,
    0x844ca7b844683,
    0x3f2d89b2709bb,
    0x000000000917d,
  ],
  [
    0x53e598836494a,
    0x0d44ccf702cac,
    0xd677e519e1819,
    0x7253f567ab707,
    0xc14d00a8de6bd,
    0x975b0e8b07449,
    0xdf760e4bf908f,
    0x0000000010e93,
  ],
]

def HALF_MONT : List ℕ := [
  0xaa4075474b22d,
  0xb213e047f1ff7,
  0xfb31b91640dbe,
  0x26f727afe7f18,
  0x0e5cd98bad0b5,
  0x8d8b36a08fe7f,
  0xff89451d47238,
  0x000000001764f,
]

/-! ## Derivations of the limb tables -/

/-- The `n` little-endian `bits`-bit limbs of `x`, dropping bits from `bits * n` up. -/
def limbsOf (bits : ℕ) : ℕ → ℕ → List ℕ
  | 0, _ => []
  | n + 1, x => x % 2 ^ bits :: limbsOf bits n (x / 2 ^ bits)

abbrev limbs52 (x : ℕ) : List ℕ := limbsOf LIMB_BITS LIMBS x

def toMont (x : ℕ) : ℕ := x * R % Fp.modulus

/-- The inverse of 2 modulo p. -/
def half : ℕ := (Fp.modulus + 1) / 2

theorem P_eq : P = limbs52 Fp.modulus := by decide +kernel

theorem P_U64_eq : P_U64 = limbsOf 64 6 Fp.modulus := by decide +kernel

theorem P_INV52_spec :
    (P_INV52 * Fp.modulus + 1) % 2 ^ LIMB_BITS = 0 ∧ P_INV52 < 2 ^ LIMB_BITS := by
  decide +kernel

theorem R_MOD_P_eq : R_MOD_P = limbs52 (toMont 1) := by decide +kernel

theorem R2_MOD_P_eq : R2_MOD_P = limbs52 (R ^ 2 % Fp.modulus) := by decide +kernel

theorem TWO_POW_384_MOD_P_eq : TWO_POW_384_MOD_P = limbs52 (2 ^ 384 % Fp.modulus) := by
  decide +kernel

theorem ONE_PLAIN_eq : ONE_PLAIN = limbs52 1 := by decide +kernel

theorem FOUR_MONT_eq : FOUR_MONT = limbs52 (toMont 4) := by decide +kernel

theorem half_spec : 2 * half % Fp.modulus = 1 := by decide +kernel

theorem HALF_MONT_eq : HALF_MONT = limbs52 (toMont half) := by decide +kernel

theorem HALF_P_MINUS_1_eq : HALF_P_MINUS_1 = limbs52 ((Fp.modulus - 1) / 2) := by decide +kernel

theorem P_MINUS_3_OVER_4_WINDOWS_eq :
    P_MINUS_3_OVER_4_WINDOWS = limbsOf 4 95 ((Fp.modulus - 3) / 4) ∧
      (Fp.modulus - 3) / 4 < 2 ^ (4 * 95) := by
  decide +kernel

/-! ## Powers by square-and-multiply

The spec's `PowMod.powModAux` computes powers in `ℕ` modulo m only. Fp2 powers run `powBy` on
pairs of representatives instead, and `map_powBy` transfers the result to the ring. -/

/-- `b ^ e` under `mul`, by square-and-multiply on the bits of `e`; exact when `e < 2 ^ fuel`. -/
def powBy {α : Type} (mul : α → α → α) (one : α) : ℕ → α → ℕ → α
  | 0, _, _ => one
  | fuel + 1, b, e =>
    if e = 0 then one
    else
      let s := powBy mul one fuel (mul b b) (e / 2)
      if e % 2 = 0 then s else mul s b

theorem map_powBy {α : Type} {M : Type*} [Monoid M] {mul : α → α → α} {one : α} (f : α → M)
    (map_mul : ∀ x y, f (mul x y) = f x * f y) (map_one : f one = 1) :
    ∀ fuel b e, e < 2 ^ fuel → f (powBy mul one fuel b e) = f b ^ e
  | 0, b, e, he => by
    obtain rfl : e = 0 := by simpa using he
    simp [powBy, map_one]
  | fuel + 1, b, e, he => by
    have h2 : 2 ^ (fuel + 1) = 2 ^ fuel * 2 := pow_succ 2 fuel
    have hs : f (powBy mul one fuel (mul b b) (e / 2)) = f b ^ (2 * (e / 2)) := by
      rw [map_powBy f map_mul map_one fuel _ _ (by omega), map_mul, ← sq, pow_mul]
    unfold powBy
    split_ifs with h0 hodd
    · simp [h0, map_one]
    · rw [hs]
      congr 1
      omega
    · rw [map_mul, hs, ← pow_succ]
      congr 1
      omega

/-! ## Facts in Fp -/

theorem thirtytwo_pow_ne_one : (32 : ZMod Fp.modulus) ^ ((Fp.modulus - 1) / 3) ≠ 1 := by
  have h := (PowMod.natCast_pow_eq_one_iff Fp.modulus 381 32 ((Fp.modulus - 1) / 3)
    (by decide +kernel)).not.mpr (by decide +kernel)
  rwa [Nat.cast_ofNat] at h

/-- Euler's criterion for cubes, in the direction that rules a cube out. -/
theorem not_cube_of_pow_ne_one {a : ZMod Fp.modulus} (ha : a ≠ 0)
    (h : a ^ ((Fp.modulus - 1) / 3) ≠ 1) (x : ZMod Fp.modulus) : x ^ 3 ≠ a := by
  rintro rfl
  apply h
  rw [← pow_mul, show 3 * ((Fp.modulus - 1) / 3) = Fp.modulus - 1 by decide +kernel]
  exact ZMod.pow_card_sub_one_eq_one fun hx => ha (by rw [hx, zero_pow three_ne_zero])

/-- `x ^ 3 + 4 (1 + i)` therefore never vanishes in Fp2: a root's norm would cube to 32. -/
theorem thirtytwo_not_cube : ∀ x : ZMod Fp.modulus, x ^ 3 ≠ 32 :=
  not_cube_of_pow_ne_one (by decide +kernel) thirtytwo_pow_ne_one

/-- X² + 1 is therefore irreducible over Fp, and Fp2 = Fp[i] is a field. -/
theorem neg_one_not_square : ∀ x : ZMod Fp.modulus, x ^ 2 ≠ -1 := fun x hx =>
  ZMod.exists_sq_eq_neg_one_iff.mp ⟨x, by rw [← hx, sq]⟩ p_mod_four

/-- The cube root of unity ζ of the Scott argument for G2: the norm of ψ's x multiplier,
N(c_x) = `psiX ^ 2`, as `norm_cx` proves. -/
def beta : ℕ :=
  0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac

theorem beta_cube : (beta : ZMod Fp.modulus) ^ 3 = 1 := by
  rw [← Nat.cast_pow, ← ZMod.natCast_mod, show beta ^ 3 % Fp.modulus = 1 by decide +kernel,
    Nat.cast_one]

theorem beta_ne_one : (beta : ZMod Fp.modulus) ≠ 1 := by decide +kernel

/-! ## Facts in Fp2

A pair `(a, b)` of representatives stands for `a + b ι`. -/

def mulFp2 (x y : ℕ × ℕ) : ℕ × ℕ :=
  ((x.1 * y.1 + (Fp.modulus - x.2 * y.2 % Fp.modulus)) % Fp.modulus,
    (x.1 * y.2 + x.2 * y.1) % Fp.modulus)

section Fp2

variable {A : Type*} [CommRing A]

def toFp2 (ι : A) (x : ℕ × ℕ) : A := x.1 + x.2 * ι

theorem natCast_mod_p (hp : (Fp.modulus : A) = 0) (n : ℕ) : ((n % Fp.modulus : ℕ) : A) = n := by
  conv_rhs => rw [← Nat.mod_add_div n Fp.modulus]
  push_cast
  rw [hp, zero_mul, add_zero]

theorem toFp2_mulFp2 (hp : (Fp.modulus : A) = 0) {ι : A} (hι : ι ^ 2 = -1) (x y : ℕ × ℕ) :
    toFp2 ι (mulFp2 x y) = toFp2 ι x * toFp2 ι y := by
  have hle : x.2 * y.2 % Fp.modulus ≤ Fp.modulus := (Nat.mod_lt _ (by decide +kernel)).le
  simp only [toFp2, mulFp2, natCast_mod_p hp]
  push_cast [Nat.cast_sub hle, natCast_mod_p hp]
  linear_combination (-(x.2 : A) * y.2) * hι + hp

theorem toFp2_powBy (hp : (Fp.modulus : A) = 0) {ι : A} (hι : ι ^ 2 = -1) (b : ℕ × ℕ) (e : ℕ)
    (he : e < 2 ^ 381) : toFp2 ι (powBy mulFp2 (1, 0) 381 b e) = toFp2 ι b ^ e :=
  map_powBy (toFp2 ι) (toFp2_mulFp2 hp hι) (by simp [toFp2]) 381 b e he

/-- ψ's x multiplier is `psiX * ι`. -/
def psiX : ℕ :=
  0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad

/-- ψ's y multiplier, as `(re, im)`. -/
def psiY : ℕ × ℕ :=
  (0x135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2,
   0x06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09)

theorem PSI_X_MONT_eq : PSI_X_MONT = limbs52 (toMont psiX) := by decide +kernel

theorem PSI_Y_MONT_eq : PSI_Y_MONT = [limbs52 (toMont psiY.1), limbs52 (toMont psiY.2)] := by
  decide +kernel

theorem psiX_cube (hp : (Fp.modulus : A) = 0) {ι : A} (hι : ι ^ 2 = -1) :
    ((psiX : A) * ι) ^ 3 = ι := by
  have h := congrArg (toFp2 ι)
    (show powBy mulFp2 (1, 0) 381 (0, psiX) 3 = (0, 1) by decide +kernel)
  rw [toFp2_powBy hp hι _ _ (by decide +kernel)] at h
  simpa [toFp2] using h

theorem psiY_sq (hp : (Fp.modulus : A) = 0) {ι : A} (hι : ι ^ 2 = -1) :
    ((psiY.1 : A) + psiY.2 * ι) ^ 2 = ι := by
  have h := congrArg (toFp2 ι) (show mulFp2 psiY psiY = (0, 1) by decide +kernel)
  rw [toFp2_mulFp2 hp hι, ← sq] at h
  simpa [toFp2] using h

theorem psiX_mul_pow (hp : (Fp.modulus : A) = 0) {ι : A} (hι : ι ^ 2 = -1) :
    (psiX : A) * ι * (1 + ι) ^ ((Fp.modulus - 1) / 3) = 1 := by
  have h := congrArg (toFp2 ι)
    (show mulFp2 (0, psiX) (powBy mulFp2 (1, 0) 381 (1, 1) ((Fp.modulus - 1) / 3)) = (1, 0) by
      decide +kernel)
  rw [toFp2_mulFp2 hp hι, toFp2_powBy hp hι _ _ (by decide +kernel)] at h
  simpa [toFp2] using h

theorem psiY_mul_pow (hp : (Fp.modulus : A) = 0) {ι : A} (hι : ι ^ 2 = -1) :
    ((psiY.1 : A) + psiY.2 * ι) * (1 + ι) ^ ((Fp.modulus - 1) / 2) = 1 := by
  have h := congrArg (toFp2 ι)
    (show mulFp2 psiY (powBy mulFp2 (1, 0) 381 (1, 1) ((Fp.modulus - 1) / 2)) = (1, 0) by
      decide +kernel)
  rw [toFp2_mulFp2 hp hι, toFp2_powBy hp hι _ _ (by decide +kernel)] at h
  simpa [toFp2] using h

end Fp2

/-! ## The [|z|] chain

`times_minus_z` of `g2x8.rs` doubles once per bit below `Z_BITS[0]`, high to low, and adds the
chain's base after each listed bit. Multiples below are of a point `T` of order `ℓ`. -/

inductive Step
  | double
  | add

def chainSteps : List Step :=
  (List.range Z_BITS[0]!).reverse.flatMap fun bit =>
    if bit ∈ Z_BITS then [.double, .add] else [.double]

/-- The multiple of the base reached from `k` times the base. -/
def Step.run : List Step → ℕ → ℕ
  | [], k => k
  | .double :: steps, k => run steps (2 * k)
  | .add :: steps, k => run steps (k + 1)

theorem chain_eq_blsX : Step.run chainSteps 1 = blsX := by decide +kernel

/-- Whether the chain on base `[b]T`, started at `[k]T`, meets an undecided case: `O` as a
step's input or as the result, or an addition of two points with equal x, which are `±[b]T`.
A doubling input with y = 0 has order 2, which odd `ℓ` excludes. -/
def meetsException (ℓ b : ℕ) : List Step → ℕ → Bool
  | [], k => k % ℓ == 0
  | .double :: steps, k => k % ℓ == 0 || meetsException ℓ b steps (2 * k)
  | .add :: steps, k =>
    k % ℓ == 0 || b % ℓ == 0 || k % ℓ == b % ℓ || (k + b) % ℓ == 0 ||
      meetsException ℓ b steps (k + b)

/-- The chain of `times_minus_z`: base `T`, started at `T`. -/
def g2MeetsException (ℓ : ℕ) : Bool := meetsException ℓ 1 chainSteps 1

theorem blsX_lt_two_pow_64 : blsX < 2 ^ 64 := by decide +kernel

theorem blsX_lt_r : blsX < Fr.modulus := by decide +kernel

theorem blsX_sq_lt_r : blsX ^ 2 < Fr.modulus := by decide +kernel

theorem r_odd : Fr.modulus % 2 = 1 := by decide +kernel

theorem r_avoids_exceptions : g2MeetsException Fr.modulus = false := by decide +kernel

/-- The small prime factors of the G2 cofactor, as in `H2_SMALL_PRIMES` of `tests.rs`. -/
theorem g2_small_orders :
    [13, 23, 2713, 11953, 262069].map g2MeetsException = [true, false, false, false, false] := by
  decide +kernel

end LeanBlsSimd
