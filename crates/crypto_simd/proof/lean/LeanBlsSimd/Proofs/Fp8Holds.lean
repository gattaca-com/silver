import LeanBlsSimd.Proofs.Convert
import LeanBlsSimd.Proofs.Pow
import LeanBlsSimd.Spec.Sqrt

namespace LeanBlsSimd

open EthCryptographySpecs.Bls

/-! ## Mask bits -/

namespace Mmask8

theorem testBit_toNat (a : Mmask8) (l : ℕ) : a.toNat.testBit l = a.toBitVec.getLsbD l :=
  BitVec.testBit_toNat _

theorem testBit_and (a b : Mmask8) (l : ℕ) :
    (a &&& b).toNat.testBit l = (a.toNat.testBit l && b.toNat.testBit l) := by
  simp only [testBit_toNat, UInt8.toBitVec_and, BitVec.getLsbD_and]

theorem testBit_or (a b : Mmask8) (l : ℕ) :
    (a ||| b).toNat.testBit l = (a.toNat.testBit l || b.toNat.testBit l) := by
  simp only [testBit_toNat, UInt8.toBitVec_or, BitVec.getLsbD_or]

theorem testBit_xor (a b : Mmask8) (l : ℕ) :
    (a ^^^ b).toNat.testBit l = (a.toNat.testBit l ^^ b.toNat.testBit l) := by
  simp only [testBit_toNat, UInt8.toBitVec_xor, BitVec.getLsbD_xor]

theorem testBit_not (a : Mmask8) (l : Fin 8) : (~~~a).toNat.testBit l = !a.toNat.testBit l := by
  simp only [testBit_toNat, UInt8.toBitVec_not, BitVec.getLsbD_not, l.isLt, decide_true,
    Bool.true_and]

theorem testBit_zero (l : ℕ) : (0 : Mmask8).toNat.testBit l = false := by
  simp

theorem testBit_one_shiftLeft (i l : Fin 8) :
    ((1 : Mmask8) <<< i.val.toUInt8).toNat.testBit l = decide (l = i) := by
  revert i l
  decide

theorem testBit_of_eq_zero {k : Mmask8} (h : k = 0) (l : ℕ) : k.toNat.testBit l = false := by
  rw [h, testBit_zero]

theorem eq_zero_of_testBit {k : Mmask8} (h : ∀ l : Fin 8, k.toNat.testBit l = false) : k = 0 := by
  have hk : k.toNat < 2 ^ 8 := k.toNat_lt
  apply UInt8.toNat_inj.mp
  rw [UInt8.toNat_zero]
  apply Nat.eq_of_testBit_eq
  intro i
  rw [Nat.zero_testBit]
  by_cases hi : i < 8
  · exact h ⟨i, hi⟩
  · exact Nat.testBit_lt_two_pow (lt_of_lt_of_le hk (Nat.pow_le_pow_right two_pos (by omega)))

end Mmask8


/-! ## Tables, plain inputs, `canonical` and `select` -/

theorem natCast_half : (half : ZMod Fp.modulus) = 2⁻¹ := by
  have h2 := congrArg (Nat.cast : ℕ → ZMod Fp.modulus) half_spec
  rw [ZMod.natCast_mod, Nat.cast_mul, Nat.cast_one, Nat.cast_ofNat] at h2
  exact eq_inv_of_mul_eq_one_right h2

theorem inv_ofList_FOUR_MONT : Fp8Inv (.ofList FOUR_MONT) := ⟨by decide, by decide +kernel⟩

theorem decode_ofList_FOUR_MONT : decode (.ofList FOUR_MONT) = 4 := by
  have h : val (.ofList FOUR_MONT) = 4 * R % Fp.modulus := by decide +kernel
  rw [decode_of_val h, Nat.cast_ofNat]

theorem inv_ofList_PSI_X_MONT : Fp8Inv (.ofList PSI_X_MONT) := ⟨by decide, by decide +kernel⟩

theorem decode_ofList_PSI_X_MONT : decode (.ofList PSI_X_MONT) = psiX := by
  have h : val (.ofList PSI_X_MONT) = psiX * R % Fp.modulus := by decide +kernel
  rw [decode_of_val h]

theorem inv_ofList_PSI_Y_MONT_0 : Fp8Inv (.ofList PSI_Y_MONT[0]!) := ⟨by decide, by decide +kernel⟩

theorem decode_ofList_PSI_Y_MONT_0 : decode (.ofList PSI_Y_MONT[0]!) = psiY.1 := by
  have h : val (.ofList PSI_Y_MONT[0]!) = psiY.1 * R % Fp.modulus := by decide +kernel
  rw [decode_of_val h]

theorem inv_ofList_PSI_Y_MONT_1 : Fp8Inv (.ofList PSI_Y_MONT[1]!) := ⟨by decide, by decide +kernel⟩

theorem decode_ofList_PSI_Y_MONT_1 : decode (.ofList PSI_Y_MONT[1]!) = psiY.2 := by
  have h : val (.ofList PSI_Y_MONT[1]!) = psiY.2 * R % Fp.modulus := by decide +kernel
  rw [decode_of_val h]

/-- Six words below p unpack to limbs that meet `Fp8Inv`. -/
theorem inv_unpack52 {w : Vector UInt64 6} (h : val64 w < Fp.modulus) : Fp8Inv (unpack52 w) :=
  ⟨(unpack52_spec w).1, by rw [(unpack52_spec w).2]; omega⟩

namespace Fp8

theorem val_canonical_lt {x : Fp8} {l : Fin 8} (hx : Fp8Inv (x.lane l)) :
    val (x.canonical.lane l) < Fp.modulus := by
  rw [(lane_canonical hx).2]
  exact Nat.mod_lt _ Fp.modulus_pos

theorem inv_select (k : Mmask8) {a b : Fp8} {l : Fin 8} (ha : Fp8Inv (a.lane l))
    (hb : Fp8Inv (b.lane l)) : Fp8Inv ((select k a b).lane l) := by
  rw [lane_select]
  split <;> assumption

/-- The sign rule in the spec's form: bit `l` is `Fp.signBit` of the lane's field element. -/
theorem testBit_is_larger_root_mask_signBit {x : Fp8} {l : Fin 8} (hx : Fp8Inv (x.lane l)) :
    x.is_larger_root_mask.toNat.testBit l = Fp.signBit (decode (x.lane l)) := by
  rw [testBit_is_larger_root_mask hx]
  exact Kernel.isLargerRootFp_eq _

/-! ## `Holds` -/

/-- Lane `l` of `x` holds the field element `a`: limbs that meet `Fp8Inv` and decode to `a`. -/
structure Holds (x : Fp8) (l : Fin 8) (a : ZMod Fp.modulus) : Prop where
  inv : Fp8Inv (x.lane l)
  eq : decode (x.lane l) = a

variable {x y : Fp8} {l : Fin 8} {a b : ZMod Fp.modulus}

theorem Holds.of_eq (h : x.Holds l a) (hab : a = b) : x.Holds l b := hab ▸ h

theorem Holds.mul (hx : x.Holds l a) (hy : y.Holds l b) : (x.mul y).Holds l (a * b) :=
  ⟨inv_mul hx.inv hy.inv, by rw [decode_lane_mul hx.inv hy.inv, hx.eq, hy.eq]⟩

theorem Holds.square (hx : x.Holds l a) : x.square.Holds l (a ^ 2) := by
  rw [sq]
  exact hx.mul hx

theorem Holds.add (hx : x.Holds l a) (hy : y.Holds l b) : (x.add y).Holds l (a + b) :=
  ⟨(lane_add hx.inv hy.inv).1, by rw [decode_lane_add hx.inv hy.inv, hx.eq, hy.eq]⟩

theorem Holds.double (hx : x.Holds l a) : x.double.Holds l (2 * a) :=
  ⟨(lane_add hx.inv hx.inv).1, by rw [decode_lane_double hx.inv, hx.eq]⟩

theorem Holds.sub (hx : x.Holds l a) (hy : y.Holds l b) : (x.sub y).Holds l (a - b) :=
  ⟨(lane_sub hx.inv hy.inv).1, by rw [decode_lane_sub hx.inv hy.inv, hx.eq, hy.eq]⟩

theorem Holds.neg (hx : x.Holds l a) : x.neg.Holds l (-a) :=
  ⟨(lane_neg hx.inv).1, by rw [decode_lane_neg hx.inv, hx.eq]⟩

theorem Holds.half (hx : x.Holds l a) : x.half.Holds l (Kernel.half a) :=
  ⟨(lane_half hx.inv).1, by rw [(lane_half hx.inv).2, hx.eq, Kernel.half, natCast_half]⟩

theorem Holds.select (k : Mmask8) (hx : x.Holds l a) (hy : y.Holds l b) :
    (select k x y).Holds l (if k.toNat.testBit l then b else a) := by
  constructor <;> rw [lane_select] <;> split
  exacts [hy.inv, hx.inv, hy.eq, hx.eq]

theorem Holds.pow_p_minus_3_over_4 (hx : x.Holds l a) :
    x.pow_p_minus_3_over_4.Holds l (Kernel.powPMinus3Over4 a) :=
  ⟨(lane_pow_p_minus_3_over_4 hx.inv).1, by
    rw [(lane_pow_p_minus_3_over_4 hx.inv).2, hx.eq, Kernel.powPMinus3Over4]⟩

theorem Holds.sqrt_candidate (hx : x.Holds l a) :
    x.sqrt_candidate.Holds l (Kernel.sqrtCandidate a) :=
  hx.pow_p_minus_3_over_4.mul hx

theorem Holds.testBit_eq_mask (hx : x.Holds l a) (hy : y.Holds l b) :
    (x.eq_mask y).toNat.testBit l = decide (a = b) := by
  rw [Fp8.testBit_eq_mask hx.inv hy.inv, hx.eq, hy.eq]

theorem Holds.testBit_is_zero_mask (hx : x.Holds l a) :
    x.is_zero_mask.toNat.testBit l = decide (a = 0) := by
  rw [Fp8.testBit_is_zero_mask hx.inv, hx.eq]

theorem Holds.testBit_is_larger_root_mask (hx : x.Holds l a) :
    x.is_larger_root_mask.toNat.testBit l = Kernel.isLargerRootFp a := by
  rw [Fp8.testBit_is_larger_root_mask hx.inv, hx.eq]
  rfl

theorem Holds.val64_to_blst_limbs (hx : x.Holds l a) :
    val64 x.to_blst_limbs[l] = (a * 2 ^ 384).val := by
  rw [Fp8.val64_to_blst_limbs hx.inv, hx.eq]

theorem holds_one (l : Fin 8) : one.Holds l 1 := ⟨inv_one l, decode_lane_one l⟩

theorem holds_zero (l : Fin 8) : zero.Holds l 0 := ⟨inv_zero l, decode_lane_zero l⟩

theorem holds_splat_limbs {t : Limbs} (ht : Fp8Inv t) (l : Fin 8) :
    (splat_limbs t).Holds l (decode t) := by
  constructor <;> rw [lane_splat_limbs]
  exact ht

theorem holds_from_plain {values : Vector Limbs 8} {l : Fin 8} (hv : Fp8Inv values[l]) :
    (from_plain values).Holds l (val values[l]) :=
  ⟨(lane_from_plain hv).1, (lane_from_plain hv).2⟩

end Fp8

end LeanBlsSimd
