import LeanBlsSimd.Pairing.FinalInvariant
import LeanBlsSimd.Refines.Basic

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Pairing.FinalExponent

structure Operations (Raw : Type) where
  mul : Raw → Raw → Result Raw
  square : Raw → Result Raw
  conjugate : Raw → Result Raw
  exp : Raw → Result Raw
  frobenius : Raw → Result Raw
  inverse : Raw → Result Raw

def hardRun {Raw : Type} (ops : Operations Raw) (a : Raw) : Result Raw := do
  let f2 ← ops.square a
  let t11 ← ops.conjugate f2
  let t3 ← ops.exp a
  let t4 ← ops.square t3
  let t5 ← ops.mul t11 t3
  let t12 ← ops.exp t5
  let t01 ← ops.exp t12
  let f3 ← ops.exp t01
  let t6 ← ops.mul f3 t4
  let t41 ← ops.exp t6
  let t51 ← ops.conjugate t5
  let f4 ← ops.mul t51 a
  let t42 ← ops.mul t41 f4
  let t52 ← ops.conjugate a
  let f5 ← ops.mul t12 a
  let f6 ← ops.frobenius f5
  let f7 ← ops.frobenius f6
  let t13 ← ops.frobenius f7
  let f8 ← ops.mul t6 t52
  let t61 ← ops.frobenius f8
  let f9 ← ops.mul t3 t01
  let f10 ← ops.frobenius f9
  let t31 ← ops.frobenius f10
  let f11 ← ops.mul t31 t13
  let f12 ← ops.mul f11 t61
  ops.mul f12 t42

def run {Raw : Type} (ops : Operations Raw) (a : Raw) : Result Raw := do
  let t0 ← ops.conjugate a
  let t1 ← ops.inverse a
  let t2 ← ops.mul t0 t1
  let f ← ops.frobenius t2
  let f1 ← ops.frobenius f
  let t21 ← ops.mul f1 t2
  hardRun ops t21

structure Operations.Refines {Raw : Type} (ops : Operations Raw) (rep : Raw → Bls.Fp12 → Prop) : Prop where
  mul : ∀ {x y a b}, rep x a → rep y b → ∃ out, ops.mul x y = ok out ∧ rep out (a * b)
  square : ∀ {x a}, rep x a → Good a → ∃ out, ops.square x = ok out ∧ rep out a.square
  conjugate : ∀ {x a}, rep x a → ∃ out, ops.conjugate x = ok out ∧ rep out a.conjugate
  exp : ∀ {x a}, rep x a → Good a → ∃ out, ops.exp x = ok out ∧ rep out (FinalExponent.exp a)
  frobenius : ∀ {x a}, rep x a → ∃ out, ops.frobenius x = ok out ∧ rep out (FinalExponent.frobenius a)
  inverse : ∀ {x a}, rep x a → ∃ out, ops.inverse x = ok out ∧ rep out a.inverse

theorem hard_run_refines {Raw : Type} {ops : Operations Raw} {rep : Raw → Bls.Fp12 → Prop}
    (h : ops.Refines rep) {x : Raw} {a : Bls.Fp12} (hx : rep x a) (ha : Good a) :
    ∃ out, hardRun ops x = ok out ∧ rep out (hard a) := by
  obtain ⟨f2, hf2, rf2⟩ := h.square hx ha
  obtain ⟨t11, ht11, rt11⟩ := h.conjugate rf2
  obtain ⟨t3, ht3, rt3⟩ := h.exp hx ha
  obtain ⟨t4, ht4, rt4⟩ := h.square rt3 ha.exp
  obtain ⟨t5, ht5, rt5⟩ := h.mul rt11 rt3
  have g5 := ha.square.conjugate.mul ha.exp
  obtain ⟨t12, ht12, rt12⟩ := h.exp rt5 g5
  obtain ⟨t01, ht01, rt01⟩ := h.exp rt12 g5.exp
  obtain ⟨f3, hf3, rf3⟩ := h.exp rt01 g5.exp.exp
  obtain ⟨t6, ht6, rt6⟩ := h.mul rf3 rt4
  obtain ⟨t41, ht41, rt41⟩ := h.exp rt6 (g5.exp.exp.exp.mul ha.exp.square)
  obtain ⟨t51, ht51, rt51⟩ := h.conjugate rt5
  obtain ⟨f4, hf4, rf4⟩ := h.mul rt51 hx
  obtain ⟨t42, ht42, rt42⟩ := h.mul rt41 rf4
  obtain ⟨t52, ht52, rt52⟩ := h.conjugate hx
  obtain ⟨f5, hf5, rf5⟩ := h.mul rt12 hx
  obtain ⟨f6, hf6, rf6⟩ := h.frobenius rf5
  obtain ⟨f7, hf7, rf7⟩ := h.frobenius rf6
  obtain ⟨t13, ht13, rt13⟩ := h.frobenius rf7
  obtain ⟨f8, hf8, rf8⟩ := h.mul rt6 rt52
  obtain ⟨t61, ht61, rt61⟩ := h.frobenius rf8
  obtain ⟨f9, hf9, rf9⟩ := h.mul rt3 rt01
  obtain ⟨f10, hf10, rf10⟩ := h.frobenius rf9
  obtain ⟨t31, ht31, rt31⟩ := h.frobenius rf10
  obtain ⟨f11, hf11, rf11⟩ := h.mul rt31 rt13
  obtain ⟨f12, hf12, rf12⟩ := h.mul rf11 rt61
  obtain ⟨out, hout, rout⟩ := h.mul rf12 rt42
  refine ⟨out, ?_, rout⟩
  simp only [hardRun, hf2, ht11, ht3, ht4, ht5, ht12, ht01, hf3, ht6, ht41,
    ht51, hf4, ht42, ht52, hf5, hf6, hf7, ht13, hf8, ht61, hf9, hf10, ht31,
    hf11, hf12, hout, bind_tc_ok]

theorem run_refines {Raw : Type} {ops : Operations Raw} {rep : Raw → Bls.Fp12 → Prop}
    (h : ops.Refines rep) {x : Raw} {a : Bls.Fp12} (hx : rep x a) :
    ∃ out, run ops x = ok out ∧ rep out (optimized a) := by
  obtain ⟨t0, ht0, rt0⟩ := h.conjugate hx
  obtain ⟨t1, ht1, rt1⟩ := h.inverse hx
  obtain ⟨t2, ht2, rt2⟩ := h.mul rt0 rt1
  obtain ⟨f, hf, rf⟩ := h.frobenius rt2
  obtain ⟨f1, hf1, rf1⟩ := h.frobenius rf
  obtain ⟨t21, ht21, rt21⟩ := h.mul rf1 rt2
  obtain ⟨out, hout, rout⟩ := hard_run_refines h rt21 (easy_good a)
  exact ⟨out, by simp only [run, ht0, ht1, ht2, hf, hf1, ht21, hout, bind_tc_ok], rout⟩

end LeanBlsSimd.Pairing.FinalExponent
