import LeanBlsSimd.Spec.G2Curve
import EthLib.Cryptography.Bls.Compress
import EthLib.Cryptography.Proofs.Bls.Compress

/-!
# Square roots in Fp2: the spec's and the kernel's

The spec's `Fp2.sqrt` takes a root s of the norm, then tries (a₀ + s)/2 and (a₀ − s)/2 as the
square of the root's real part. The kernel's `Fp2x8::sqrt` computes one candidate with two Fp
exponentiations and accepts it, or it times i. Both are sound and complete: `Fp2.sqrt_sound`,
`Fp2.sqrt_complete`, `Kernel.sqrt_fst_sq` and `Kernel.sqrt_snd_iff`. So wherever one finds a root,
the other finds the same root up to sign. The shared sign rule (`Kernel.isLargerRoot_toField`)
then picks the same one: `Kernel.sqrt_agrees` and `Kernel.sqrt_fails`.

EthLib proves soundness, completeness and sign negation on the spec type.
This file restates them over `Fp2Field` through `Fp2.toField`.

`Kernel` restates one lane of the kernel's root and sign step over the field.
-/

namespace LeanBlsSimd

open EthLib.Cryptography EthLib.Cryptography.Bls

private theorem two_ne_zero_zmod : (2 : ZMod Fp.modulus) ≠ 0 := by decide +kernel

private theorem mk_sq (c d : ZMod Fp.modulus) :
    (⟨c, d⟩ : Fp2Field) ^ 2 = ⟨c * c - d * d, c * d + d * c⟩ := by
  rw [sq]
  ext
  · simp only [QuadraticAlgebra.re_mul]
    ring
  · simp only [QuadraticAlgebra.im_mul]
    ring

/-! ## The spec's root -/

namespace Fp2

/-- Soundness: a root the spec returns squares to its input. -/
theorem sqrt_sound {a y : Fp2} (h : Fp2.sqrt a = .ok y) : toField y ^ 2 = toField a := by
  rw [← map_pow, sq, EthLib.Cryptography.Bls.Fp2.sqrt_ok h]

/-- Completeness: the spec returns a root of every square. -/
theorem sqrt_complete {a : Fp2} (h : IsSquare (toField a)) : ∃ y, Fp2.sqrt a = .ok y := by
  obtain ⟨r, hr⟩ := h
  apply EthLib.Cryptography.Bls.Fp2.sqrt_complete (b := toField.symm r)
  apply toField.injective
  simpa only [map_mul, toField.apply_symm_apply] using hr.symm

/-! ## The sign rule under negation -/

theorem signBit_neg {y : Fp2} (hy : toField y ≠ 0) : Fp2.signBit (-y) = !Fp2.signBit y :=
  EthLib.Cryptography.Bls.Fp2.signBit_neg (toField.map_ne_zero_iff.mp hy)

end Fp2

/-! ## The kernel's root, one lane over the field

`Kernel` mirrors `decompress_g2.rs`, `fp2x8.rs` and `fp8.rs`: `Fp8` methods on `ZMod Fp.modulus`,
`Fp2x8` methods on `Fp2Field`. A lane mask becomes a `Bool`, and `select k a b` becomes
`if k then b else a`. -/

namespace Kernel

/-- `Fp8::half`: the product with `HALF_MONT`, which encodes `half`. -/
def half (a : ZMod Fp.modulus) : ZMod Fp.modulus := a * (LeanBlsSimd.half : ZMod Fp.modulus)

/-- `Fp8::pow_p_minus_3_over_4`. -/
def powPMinus3Over4 (a : ZMod Fp.modulus) : ZMod Fp.modulus := a ^ ((Fp.modulus - 3) / 4)

/-- `Fp8::sqrt_candidate`. -/
def sqrtCandidate (a : ZMod Fp.modulus) : ZMod Fp.modulus := powPMinus3Over4 a * a

/-- `Fp8::is_larger_root_mask`: the canonical value exceeds `HALF_P_MINUS_1`, (p − 1)/2. -/
def isLargerRootFp (a : ZMod Fp.modulus) : Bool := (Fp.modulus - 1) / 2 < a.val

/-- `Fp2x8::is_larger_root_mask`. -/
def isLargerRoot (y : Fp2Field) : Bool :=
  isLargerRootFp y.im || (isLargerRootFp y.re && y.im = 0)

/-- `rhs` of `decompress`: x³ + 4(1 + i), with `four` from `FOUR_MONT`. -/
def rhs (x : Fp2Field) : Fp2Field := x ^ 2 * x + ⟨4, 4⟩

/-- The spec's rhs, x³ + b′ as `G2.uncompress` computes it, is `rhs` on `Fp2Field`. -/
theorem rhs_toField (x : Fp2) :
    Fp2.toField (x * x * x + G2.bTwist) = rhs (Fp2.toField x) := by
  rw [map_add, map_mul, map_mul, Fp2.toField_bTwist, rhs, sq]
  rfl

/-- `t` of `Fp2x8::sqrt`. -/
def sqrtT (x : Fp2Field) : ZMod Fp.modulus :=
  let n := sqrtCandidate (x.re ^ 2 + x.im ^ 2)
  let plus := x.re + n
  half (if plus = 0 then x.re - n else plus)

/-- `candidate` of `Fp2x8::sqrt`. -/
def rootCandidate (x : Fp2Field) : Fp2Field :=
  let t := sqrtT x
  let r := powPMinus3Over4 t
  ⟨t * r, half x.im * r⟩

/-- `Fp2x8::sqrt`: a candidate, and a Boolean that is true exactly when the candidate is a root. -/
def sqrt (x : Fp2Field) : Fp2Field × Bool :=
  let candidate := rootCandidate x
  let square := candidate ^ 2
  let squaresToSelf := decide (square = x)
  let squaresToNeg := decide (square = -x)
  (if squaresToNeg then candidate * QuadraticAlgebra.omega else candidate,
    squaresToSelf || squaresToNeg)

/-- The sign step of `decompress`: `flip` picks `-root` where the root's sign test disagrees
with the encoding's flag. -/
def selectRoot (root : Fp2Field) (largerRoot : Bool) : Fp2Field :=
  if isLargerRoot root ^^ largerRoot then -root else root

theorem isLargerRootFp_eq (v : Fp) : isLargerRootFp v = Fp.signBit v := by
  have hlt := v.isLt
  have hodd : Fp.modulus % 2 = 1 := by decide
  unfold isLargerRootFp Fp.signBit
  show decide ((Fp.modulus - 1) / 2 < v.val) = decide (v.val > Fp.modulus - v.val)
  exact decide_eq_decide.mpr (by omega)

/-- The kernel's sign test is the spec's `Fp2.signBit`. -/
theorem isLargerRoot_toField (y : Fp2) : isLargerRoot (Fp2.toField y) = Fp2.signBit y := by
  have hre : isLargerRootFp (Fp2.toField y).re = Fp.signBit y.c0 := isLargerRootFp_eq y.c0
  have him : isLargerRootFp (Fp2.toField y).im = Fp.signBit y.c1 := isLargerRootFp_eq y.c1
  unfold isLargerRoot Fp2.signBit
  rw [hre, him]
  by_cases h1 : (Fp2.toField y).im = 0
  · have hz : y.c1.isZero = true := Fp.isZero_iff.mpr h1
    have hs : Fp.signBit y.c1 = false := by
      unfold Fp.signBit
      rw [show y.c1.val = 0 from congrArg Fin.val h1]
      decide
    rw [ite_eq_right (by simp [hz]), hs, decide_eq_true h1, Bool.false_or, Bool.and_true]
  · have hz : ¬ y.c1.isZero = true := fun h => h1 (Fp.isZero_iff.mp h)
    rw [ite_eq_left (by simp [hz]), decide_eq_false h1, Bool.and_false, Bool.or_false]

/-- Where two roots of one value meet the sign step, the kernel's step picks the spec's. -/
theorem selectRoot_eq {root : Fp2Field} {yPos : Fp2} (h : root ^ 2 = Fp2.toField yPos ^ 2)
    (ySign : Bool) :
    selectRoot root ySign = Fp2.toField (if Fp2.signBit yPos = ySign then yPos else -yPos) := by
  by_cases h0 : Fp2.toField yPos = 0
  · have hr : root = 0 := by
      rw [h0, zero_pow two_ne_zero] at h
      exact pow_eq_zero_iff two_ne_zero |>.mp h
    unfold selectRoot
    split_ifs <;> simp [hr, h0]
  · rcases sq_eq_sq_iff_eq_or_eq_neg.mp h with rfl | rfl
    · unfold selectRoot
      rw [isLargerRoot_toField]
      cases Fp2.signBit yPos <;> cases ySign <;> simp
    · unfold selectRoot
      rw [← Fp2.toField_neg, isLargerRoot_toField, Fp2.signBit_neg h0]
      cases Fp2.signBit yPos <;> cases ySign <;> simp [Fp2.toField_neg]

/-! ### The candidate, and why two alignments suffice -/

theorem two_mul_half (a : ZMod Fp.modulus) : 2 * half a = a := by
  have h : (LeanBlsSimd.half : ZMod Fp.modulus) * 2 = 1 := by decide +kernel
  calc 2 * half a = a * ((LeanBlsSimd.half : ZMod Fp.modulus) * 2) := by unfold half; ring
    _ = a := by rw [h, mul_one]

private theorem sqrtCandidate_mul_self (m : ZMod Fp.modulus) :
    sqrtCandidate (m * m) * sqrtCandidate (m * m) = m * m := by
  by_cases hm : m = 0
  · subst hm
    simp [sqrtCandidate]
  unfold sqrtCandidate powPMinus3Over4
  have hk : 4 * ((Fp.modulus - 3) / 4) + 4 = (Fp.modulus - 1) + 2 := by
    have := p_mod_four
    omega
  calc (m * m) ^ ((Fp.modulus - 3) / 4) * (m * m) * ((m * m) ^ ((Fp.modulus - 3) / 4) * (m * m))
      = m ^ (4 * ((Fp.modulus - 3) / 4) + 4) := by ring
    _ = m * m := by rw [hk, pow_add, ZMod.pow_card_sub_one_eq_one hm, one_mul, sq]

private theorem quadraticChar_eq (t : ZMod Fp.modulus) :
    ((quadraticChar (ZMod Fp.modulus) t : ℤ) : ZMod Fp.modulus) =
      powPMinus3Over4 t * powPMinus3Over4 t * t := by
  rw [quadraticChar_eq_pow_of_char_ne_two' (by rw [ZMod.ringChar_zmod_n]; decide) t, ZMod.card]
  unfold powPMinus3Over4
  rw [← pow_add, ← pow_succ]
  congr 1

/-- On a square, the norm's candidate root is a root. -/
private theorem norm_root {x : Fp2Field} (hx : IsSquare x) :
    sqrtCandidate (x.re ^ 2 + x.im ^ 2) * sqrtCandidate (x.re ^ 2 + x.im ^ 2) =
      x.re ^ 2 + x.im ^ 2 := by
  obtain ⟨y, rfl⟩ := hx
  have h : (y * y).re ^ 2 + (y * y).im ^ 2 =
      (y.re * y.re + y.im * y.im) * (y.re * y.re + y.im * y.im) := by
    simp only [QuadraticAlgebra.re_mul, QuadraticAlgebra.im_mul]
    ring
  rw [h]
  exact sqrtCandidate_mul_self _

/-- On a square, the candidate squares to χ(t) times its input. -/
theorem rootCandidate_sq {x : Fp2Field} (hx : IsSquare x) :
    rootCandidate x ^ 2 = (quadraticChar (ZMod Fp.modulus) (sqrtT x) : Fp2Field) * x := by
  have hn := norm_root hx
  set n := sqrtCandidate (x.re ^ 2 + x.im ^ 2) with hn_def
  set T := sqrtT x with hT_def
  set H := half x.im with hH_def
  set r := powPMinus3Over4 T with hr_def
  have hv : 2 * H = x.im := two_mul_half x.im
  obtain ⟨n', hn', hu⟩ : ∃ n', n' * n' = x.re ^ 2 + x.im ^ 2 ∧ 2 * T = x.re + n' := by
    rw [hT_def, sqrtT, ← hn_def]
    split_ifs
    · exact ⟨-n, by rw [neg_mul_neg, hn], by rw [two_mul_half, sub_eq_add_neg]⟩
    · exact ⟨n, hn, two_mul_half _⟩
  have hkey : T * T - H * H = T * x.re := by
    have h4 : (4 : ZMod Fp.modulus) * (T * T - H * H - T * x.re) = 0 := by
      linear_combination (2 * T - x.re + n') * hu - (2 * H + x.im) * hv + hn'
    have h4' : (4 : ZMod Fp.modulus) ≠ 0 := by decide +kernel
    linear_combination (mul_eq_zero.mp h4).resolve_left h4'
  have hχ := quadraticChar_eq T
  rw [show rootCandidate x = ⟨T * r, H * r⟩ from rfl, mk_sq]
  ext
  · simp only [QuadraticAlgebra.re_mul, QuadraticAlgebra.re_intCast,
      QuadraticAlgebra.im_intCast, hχ]
    linear_combination (r * r) * hkey
  · simp only [QuadraticAlgebra.im_mul, QuadraticAlgebra.re_intCast,
      QuadraticAlgebra.im_intCast, hχ]
    linear_combination (r * r * T) * hv

/-- No squareness hypothesis: t = 0 forces Re x = n = 0, hence N(x) = Im(x)² = 0. -/
theorem eq_zero_of_sqrtT_eq_zero {x : Fp2Field} (h : sqrtT x = 0) : x = 0 := by
  set n := sqrtCandidate (x.re ^ 2 + x.im ^ 2) with hn_def
  have h2 : (if x.re + n = 0 then x.re - n else x.re + n) = 0 := by
    rw [← two_mul_half (if x.re + n = 0 then x.re - n else x.re + n)]
    unfold sqrtT at h
    rw [← hn_def] at h
    rw [h, mul_zero]
  split_ifs at h2 with hplus
  · have hre : x.re = 0 := by
      have : 2 * x.re = 0 := by linear_combination hplus + h2
      exact (mul_eq_zero.mp this).resolve_left two_ne_zero_zmod
    have hn0 : n = 0 := by linear_combination hplus - hre
    have hN : x.re ^ 2 + x.im ^ 2 = 0 := by
      rw [hn_def, sqrtCandidate] at hn0
      rcases mul_eq_zero.mp hn0 with h | h
      · exact pow_eq_zero_iff (show (Fp.modulus - 3) / 4 ≠ 0 by decide) |>.mp h
      · exact h
    have him : x.im = 0 := by
      rw [hre] at hN
      exact pow_eq_zero_iff two_ne_zero |>.mp (by simpa using hN)
    ext <;> simp [hre, him]
  · exact absurd h2 hplus

/-- Two alignments suffice, and non-squares never match: the kernel reports a root exactly on
squares. -/
theorem sqrt_snd_iff (x : Fp2Field) : (sqrt x).2 = true ↔ IsSquare x := by
  simp only [sqrt, Bool.or_eq_true, decide_eq_true_eq]
  constructor
  · rintro (h | h)
    · exact ⟨rootCandidate x, by rw [← sq, h]⟩
    · refine ⟨rootCandidate x * QuadraticAlgebra.omega, ?_⟩
      have hω := Fp2Field.omega_sq
      calc x = -(rootCandidate x ^ 2) := by rw [h, neg_neg]
        _ = _ := by linear_combination (-(rootCandidate x ^ 2)) * hω
  · intro hx
    have hc := rootCandidate_sq hx
    by_cases ht : sqrtT x = 0
    · left
      rw [hc, ht, quadraticChar_zero, Int.cast_zero, zero_mul, eq_zero_of_sqrtT_eq_zero ht]
    · rcases quadraticChar_dichotomy ht with h1 | h1
      · left
        rw [hc, h1, Int.cast_one, one_mul]
      · right
        rw [hc, h1, Int.cast_neg, Int.cast_one, neg_one_mul]

/-- The root the kernel reports squares to its input. -/
theorem sqrt_fst_sq {x : Fp2Field} (h : (sqrt x).2 = true) : (sqrt x).1 ^ 2 = x := by
  simp only [sqrt, Bool.or_eq_true, decide_eq_true_eq] at h ⊢
  split_ifs with hneg
  · have hω := Fp2Field.omega_sq
    rw [mul_pow, hneg, hω]
    ring
  · exact h.resolve_right hneg

/-! ### The two algorithms agree -/

/-- Where the spec finds a root, the kernel finds one, and its sign step returns the spec's `y`. -/
theorem sqrt_agrees {a yPos : Fp2} (h : Fp2.sqrt a = .ok yPos) (ySign : Bool) :
    (sqrt (Fp2.toField a)).2 = true ∧
      selectRoot (sqrt (Fp2.toField a)).1 ySign =
        Fp2.toField (if Fp2.signBit yPos = ySign then yPos else -yPos) := by
  have hsq := Fp2.sqrt_sound h
  have hhas : (sqrt (Fp2.toField a)).2 = true :=
    (sqrt_snd_iff _).mpr ⟨Fp2.toField yPos, by rw [← hsq, sq]⟩
  exact ⟨hhas, selectRoot_eq (by rw [sqrt_fst_sq hhas, hsq]) ySign⟩

/-- Where the spec finds no root, neither does the kernel. -/
theorem sqrt_fails {a : Fp2} {e : BlsError} (h : Fp2.sqrt a = .error e) :
    (sqrt (Fp2.toField a)).2 = false := by
  rw [← Bool.not_eq_true, sqrt_snd_iff]
  intro hx
  obtain ⟨y, hy⟩ := Fp2.sqrt_complete hx
  rw [h] at hy
  cases hy

end Kernel

end LeanBlsSimd
