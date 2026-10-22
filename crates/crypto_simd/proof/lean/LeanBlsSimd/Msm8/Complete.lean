import LeanBlsSimd.Proofs.G1x8
import LeanBlsSimd.Refines.G1x8

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd
open EthCryptographySpecs.Bls
namespace G1x8







theorem infinity_holds (l : Fin 8) : infinity.Holds l G1.zero :=
  ⟨Fp8.holds_one l, Fp8.holds_one l, Fp8.holds_zero l⟩

theorem select_false_holds (k : Mmask8) (a b : G1x8) (l : Fin 8) (P : G1)
    (hk : k.toNat.testBit l = false) (h : a.Holds l P) : (select k a b).Holds l P := by
  rcases h with ⟨hx, hy, hz⟩
  constructor
  all_goals
    constructor <;> simp only [select, Fp8.lane_select, hk, Bool.false_eq_true, ↓reduceIte]
  exacts [hx.inv, hx.eq, hy.inv, hy.eq, hz.inv, hz.eq]

theorem select_true_holds (k : Mmask8) (a b : G1x8) (l : Fin 8) (P : G1)
    (hk : k.toNat.testBit l = true) (h : b.Holds l P) : (select k a b).Holds l P := by
  rcases h with ⟨hx, hy, hz⟩
  constructor
  all_goals
    constructor <;> simp only [select, Fp8.lane_select, hk, ↓reduceIte]
  exacts [hx.inv, hx.eq, hy.inv, hy.eq, hz.inv, hz.eq]

theorem Holds.select {a b : G1x8} {l : Fin 8} {P Q : G1}
    (k : Mmask8) (ha : a.Holds l P) (hb : b.Holds l Q) :
    (select k a b).Holds l (if k.toNat.testBit l then Q else P) := by
  cases hk : k.toNat.testBit l
  · exact select_false_holds k a b l P hk ha
  · exact select_true_holds k a b l Q hk hb




theorem double_complete_correct (self : G1x8) (l : Fin 8) (P : G1)
    (h : self.Holds l P) : self.double_complete.Holds l (G1.double P) := by
  by_cases hz : P.z.isZero = true
  · have hk : self.z.is_zero_mask.toNat.testBit l = true := by
      simpa only [(Holds.z h).testBit_is_zero_mask, decide_eq_true_eq] using G1.isZero_iff.mp hz
    simpa only [double_complete, G1.double, hz, ↓reduceIte] using
      select_true_holds self.z.is_zero_mask self.double.1 self l P hk h
  · have hk : self.z.is_zero_mask.toNat.testBit l = false := by
      simpa only [(Holds.z h).testBit_is_zero_mask, decide_eq_false_iff_not] using G1.isZero_iff.not.mp hz
    exact select_false_holds self.z.is_zero_mask self.double.1 self l (G1.double P) hk
      (double_finite_correct self l P h hz)

theorem coincident_false_holds (self sum : G1x8) (sx sy : Mmask8) (l : Fin 8)
    (R : G1) (hsx : sx.toNat.testBit l = false) (hsum : sum.Holds l R) :
    (self.coincident sum sx sy).Holds l R := by
  apply select_false_holds _ _ _ _ _
  · simp only [Mmask8.testBit_and, hsx, Bool.false_and]
  · apply select_false_holds _ _ _ _ _
    · simp only [Mmask8.testBit_and, hsx, Bool.false_and]
    · exact hsum

theorem coincident_true_holds (self sum : G1x8) (sx sy : Mmask8) (l : Fin 8)
    (P : G1) (h : self.Holds l P) (hz : ¬P.z.isZero = true)
    (hsx : sx.toNat.testBit l = true) :
    (self.coincident sum sx sy).Holds l
      (if sy.toNat.testBit l then G1.double P else G1.zero) := by
  cases hsy : sy.toNat.testBit l
  · apply select_false_holds _ _ _ _ _
    · simp only [Mmask8.testBit_and, hsy, Bool.and_false]
    · apply select_true_holds _ _ _ _ _
      · simp only [Mmask8.testBit_and, Mmask8.testBit_not, hsx, hsy, Bool.not_false,
          Bool.true_and]
      · exact infinity_holds l
  · apply select_true_holds _ _ _ _ _
    · simp only [Mmask8.testBit_and, hsx, hsy, Bool.true_and]
    · exact double_finite_correct self l P h hz

theorem add_mask (self q : G1x8) (l : Fin 8) (P Q : G1)
    (h : self.Holds l P) (hq : q.Holds l Q) :
    (self.add q).2.toNat.testBit l =
      ((decide ((P.x : ZMod Fp.modulus) * ((Q.z : ZMod Fp.modulus) * Q.z) = (Q.x : ZMod Fp.modulus) * ((P.z : ZMod Fp.modulus) * P.z)) ||
        decide ((P.z : ZMod Fp.modulus) = 0)) ||
        decide ((Q.z : ZMod Fp.modulus) = 0)) := by
  have hh := ((Holds.x hq).mul (Holds.z h).square).sub
    ((Holds.x h).mul (Holds.z hq).square)
  simp only [add, Mmask8.testBit_or, hh.testBit_is_zero_mask,
    (Holds.z h).testBit_is_zero_mask, (Holds.z hq).testBit_is_zero_mask]
  simp only [sq, sub_eq_zero, eq_comm]
  rfl

theorem add_complete_correct (self q : G1x8) (l : Fin 8) (P Q : G1)
    (h : self.Holds l P) (hq : q.Holds l Q) (hP : G1.Valid P) (hQ : G1.Valid Q) :
    (self.add_complete q).Holds l (G1.add P Q) := by
  unfold add_complete
  dsimp only
  split
  · rename_i hu
    exact add_correct self q l P Q h hq hP hQ (Mmask8.testBit_of_eq_zero hu l)
  · have hzi := (Holds.z h).testBit_is_zero_mask
    have hqzi := (Holds.z hq).testBit_is_zero_mask
    by_cases hz : (P.z : ZMod Fp.modulus) = 0
    · have hz' := G1.isZero_iff.mpr hz
      rw [G1.add, if_pos hz']
      apply select_true_holds _ _ _ _ _ ?_ hq
      simpa only [hzi, decide_eq_true_eq] using hz
    · have hz' := G1.isZero_iff.not.mpr hz
      have hzi_false : self.z.is_zero_mask.toNat.testBit l = false := by
        simpa only [hzi, decide_eq_false_iff_not] using hz
      apply select_false_holds _ _ _ _ _
      · simpa only [hzi, decide_eq_false_iff_not] using hz
      · by_cases hqz : (Q.z : ZMod Fp.modulus) = 0
        · have hqz' := G1.isZero_iff.mpr hqz
          rw [G1.add, if_neg hz', if_pos hqz']
          apply select_true_holds _ _ _ _ _ ?_ h
          simpa only [hqzi, decide_eq_true_eq] using hqz
        · have hqz' := G1.isZero_iff.not.mpr hqz
          have hqzi_false : q.z.is_zero_mask.toNat.testBit l = false := by
            simpa only [hqzi, decide_eq_false_iff_not] using hqz
          apply select_false_holds _ _ _ _ _
          · simpa only [hqzi, decide_eq_false_iff_not] using hqz
          · let sx := (self.add q).2 &&& ~~~(self.z.is_zero_mask ||| q.z.is_zero_mask)
            have hsx : sx.toNat.testBit l =
                decide ((P.x : ZMod Fp.modulus) * ((Q.z : ZMod Fp.modulus) * Q.z) = (Q.x : ZMod Fp.modulus) * ((P.z : ZMod Fp.modulus) * P.z)) := by
              simp only [sx, Mmask8.testBit_and, Mmask8.testBit_not, Mmask8.testBit_or,
                hzi_false, hqzi_false, add_mask self q l P Q h hq, hz, hqz, decide_false,
                Bool.or_false, Bool.not_false, Bool.and_true]
            have hregular (hh : sx.toNat.testBit l = false) :
                (self.add q).1.Holds l (G1.add P Q) := by
              apply add_correct self q l P Q h hq hP hQ
              simpa only [add_mask self q l P Q h hq, hz, hqz, decide_false,
                Bool.or_false] using hsx ▸ hh
            split
            · rename_i hs
              exact hregular (Mmask8.testBit_of_eq_zero hs l)
            · by_cases heq : (P.x : ZMod Fp.modulus) * ((Q.z : ZMod Fp.modulus) * Q.z) = (Q.x : ZMod Fp.modulus) * ((P.z : ZMod Fp.modulus) * P.z)
              · have hsx' : sx.toNat.testBit l = true := by simpa only [hsx, decide_eq_true_eq] using heq
                have heq' : (P.x * (Q.z * Q.z)).beq (Q.x * (P.z * P.z)) = true :=
                  G1.beq_iff.mpr heq
                have hsy := (((Holds.y h).mul (Holds.z hq)).mul (Holds.z hq).square).testBit_eq_mask
                  (((Holds.y hq).mul (Holds.z h)).mul (Holds.z h).square)
                have hc := coincident_true_holds self (self.add q).1 sx
                  (((self.y.mul q.z).mul q.z.square).eq_mask ((q.y.mul self.z).mul self.z.square))
                  l P h hz' hsx'
                rw [G1.add, if_neg hz', if_neg hqz', if_pos heq']
                convert hc using 1
                simp only [hsy, sq, G1.beq_iff, decide_eq_true_eq]
                rfl
              · apply coincident_false_holds
                · change sx.toNat.testBit l = false
                  simpa only [hsx, decide_eq_false_iff_not] using heq
                · apply hregular
                  simpa only [hsx, decide_eq_false_iff_not] using heq

theorem add_affine_mask (self : G1x8) (qx qy : Fp8) (l : Fin 8) (P : G1) (x : Fp)
    (h : self.Holds l P) (hx : qx.Holds l x) :
    (self.add_affine qx qy).2.toNat.testBit l =
      (decide ((P.x : ZMod Fp.modulus) = (x : ZMod Fp.modulus) * ((P.z : ZMod Fp.modulus) * P.z)) ||
        decide ((P.z : ZMod Fp.modulus) = 0)) := by
  have hh := (hx.mul (Holds.z h).square).sub (Holds.x h)
  simp only [add_affine, Mmask8.testBit_or, hh.testBit_is_zero_mask,
    (Holds.z h).testBit_is_zero_mask]
  let X : ZMod Fp.modulus := x
  let PX : ZMod Fp.modulus := P.x
  let Z : ZMod Fp.modulus := P.z
  change (decide (X * Z ^ 2 - PX = 0) || decide (Z = 0)) =
    (decide (PX = X * (Z * Z)) || decide (Z = 0))
  simp only [sq, sub_eq_zero, eq_comm]

theorem add_affine_complete_correct (self : G1x8) (qx qy : Fp8) (l : Fin 8)
    (P : G1) (x y : Fp) (h : self.Holds l P) (hx : qx.Holds l x) (hy : qy.Holds l y)
    (hP : G1.Valid P) (hQ : G1.Valid ⟨x, y, Fp.one⟩) :
    (self.add_affine_complete qx qy).Holds l (G1.add P ⟨x, y, Fp.one⟩) := by
  unfold add_affine_complete
  dsimp only
  split
  · rename_i hu
    exact add_affine_correct self qx qy l P x y h hx hy hP hQ (Mmask8.testBit_of_eq_zero hu l)
  · have hzi := (Holds.z h).testBit_is_zero_mask
    by_cases hz : (P.z : ZMod Fp.modulus) = 0
    · have hz' := G1.isZero_iff.mpr hz
      rw [G1.add, if_pos hz']
      apply select_true_holds _ _ _ _ _ ?_ ⟨hx, hy, Fp8.holds_one l⟩
      simpa only [hzi, decide_eq_true_eq] using hz
    · have hz' := G1.isZero_iff.not.mpr hz
      have hzi_false : self.z.is_zero_mask.toNat.testBit l = false := by
        simpa only [hzi, decide_eq_false_iff_not] using hz
      apply select_false_holds _ _ _ _ _
      · simpa only [hzi, decide_eq_false_iff_not] using hz
      · let sx := (self.add_affine qx qy).2 &&& ~~~self.z.is_zero_mask
        have hsx : sx.toNat.testBit l =
            decide ((P.x : ZMod Fp.modulus) = (x : ZMod Fp.modulus) * ((P.z : ZMod Fp.modulus) * P.z)) := by
          simp only [sx, Mmask8.testBit_and, Mmask8.testBit_not,
            hzi_false, add_affine_mask self qx qy l P x h hx, hz, decide_false,
            Bool.or_false, Bool.not_false, Bool.and_true]
        have hregular (hh : sx.toNat.testBit l = false) :
            (self.add_affine qx qy).1.Holds l (G1.add P ⟨x, y, Fp.one⟩) := by
          apply add_affine_correct self qx qy l P x y h hx hy hP hQ
          simpa only [add_affine_mask self qx qy l P x h hx, hz, decide_false,
            Bool.or_false] using hsx ▸ hh
        split
        · rename_i hs
          exact hregular (Mmask8.testBit_of_eq_zero hs l)
        · by_cases heq : (P.x : ZMod Fp.modulus) = (x : ZMod Fp.modulus) * ((P.z : ZMod Fp.modulus) * P.z)
          · have hsx' : sx.toNat.testBit l = true := by simpa only [hsx, decide_eq_true_eq] using heq
            have heq' : (P.x * (Fp.one * Fp.one)).beq (x * (P.z * P.z)) = true := by
              apply G1.beq_iff.mpr
              simpa using heq
            have hsy := ((hy.mul (Holds.z h)).mul (Holds.z h).square).testBit_eq_mask (Holds.y h)
            have hc := coincident_true_holds self (self.add_affine qx qy).1 sx
              (((qy.mul self.z).mul self.z.square).eq_mask self.y) l P h hz' hsx'
            rw [G1.add, if_neg hz', if_neg (show ¬Fp.one.isZero = true from by decide), if_pos heq']
            convert hc using 1
            simp only [hsy, sq, G1.beq_iff, decide_eq_true_eq]
            let Y : ZMod Fp.modulus := P.y
            let qY : ZMod Fp.modulus := y
            let Z : ZMod Fp.modulus := P.z
            change (if Y * 1 * (1 * 1) = qY * Z * (Z * Z) then G1.double P else G1.zero) =
              (if qY * Z * (Z * Z) = Y then G1.double P else G1.zero)
            simp only [mul_one, eq_comm]
          · apply coincident_false_holds
            · change sx.toNat.testBit l = false
              simpa only [hsx, decide_eq_false_iff_not] using heq
            · apply hregular
              simpa only [hsx, decide_eq_false_iff_not] using heq

end G1x8
end LeanBlsSimd

namespace LeanBlsSimd.G1x8

theorem infinity_refines : g1x8.G1x8.infinity = ok (toG1x8 infinity) := by
  simp [g1x8.G1x8.infinity, Fp8.one_refines, Fp8.zero_refines, infinity, toG1x8]

theorem select_refines (k : U8) (a b : g1x8.G1x8) :
    g1x8.G1x8.select k a b = ok (toG1x8 (select (ofU8 k) (ofG1x8 a) (ofG1x8 b))) := by
  simp [g1x8.G1x8.select, Fp8.select_refines, select, toG1x8]

theorem double_complete_refines (self : g1x8.G1x8) :
    g1x8.G1x8.double_complete self = ok (toG1x8 (ofG1x8 self).double_complete) := by
  cases hd : (ofG1x8 self).double
  simp [g1x8.G1x8.double_complete, Fp8.is_zero_mask_refines, double_refines,
    select_refines, double_complete, hd]

theorem coincident_refines (self sum : g1x8.G1x8) (sx sy : U8) :
    g1x8.G1x8.coincident self sum sx sy =
      ok (toG1x8 ((ofG1x8 self).coincident (ofG1x8 sum) (ofU8 sx) (ofU8 sy))) := by
  cases hd : (ofG1x8 self).double
  simp [g1x8.G1x8.coincident, infinity_refines, select_refines, double_refines,
    coincident, lift, hd]
  rfl

theorem add_affine_complete_refines (self : g1x8.G1x8) (qx qy : fp8.Fp8) :
    g1x8.G1x8.add_affine_complete self qx qy =
      ok (toG1x8 ((ofG1x8 self).add_affine_complete (ofFp8 qx) (ofFp8 qy))) := by
  simp only [g1x8.G1x8.add_affine_complete, add_affine_refines, bind_tc_ok,
    Function.uncurry_def, Prod.map_fst, Prod.map_snd,
    show (0#u8) = toU8 0 from rfl, toU8_inj, add_affine_complete,
    Fp8.is_zero_mask_refines, Fp8.mul_refines, Fp8.square_refines, Fp8.eq_mask_refines,
    lift, toU8_not, toU8_and, coincident_refines, from_affine_refines, select_refines,
    ofG1x8_toG1x8, ofFp8_toFp8, ofU8_toU8, y_ofG1x8, z_ofG1x8]
  split_ifs <;> simp_all

theorem add_complete_refines (self q : g1x8.G1x8) :
    g1x8.G1x8.add_complete self q =
      ok (toG1x8 ((ofG1x8 self).add_complete (ofG1x8 q))) := by
  simp only [g1x8.G1x8.add_complete, add_refines, bind_tc_ok,
    Function.uncurry_def, Prod.map_fst, Prod.map_snd,
    show (0#u8) = toU8 0 from rfl, toU8_inj, add_complete,
    Fp8.is_zero_mask_refines, Fp8.mul_refines, Fp8.square_refines, Fp8.eq_mask_refines,
    lift, toU8_not, toU8_and, toU8_or, coincident_refines, select_refines,
    ofG1x8_toG1x8, ofFp8_toFp8, ofU8_toU8, y_ofG1x8, z_ofG1x8]
  split_ifs <;> simp_all

end LeanBlsSimd.G1x8
