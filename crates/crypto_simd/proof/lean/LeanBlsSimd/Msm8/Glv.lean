import LeanBlsSimd.Refines.Word64
import LeanBlsSimd.Model.Glv
import Mathlib.Tactic

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

open Aeneas Aeneas.Std Result ControlFlow
noncomputable section

namespace LeanBlsSimd.GlvRefines

export Word64 (radix cast128_val mac_bounds wordsValue value wordsValue_set value_set
  cast64_val high_val high_bound wordsValue_bounds value_bounds complement_val add_value sub_value)
open silver_crypto_simd.bls.msm8

theorem inner_step (k : Array U64 4#usize) (p : Array U64 7#usize)
    (i j : Usize) (c : U128) (hi : i.val < 4) (hj : j.val < 3)
    (hc : c.val < radix) :
    ∃ (t : U128) (ij j' : Usize),
      t.val = (k.val[i.val]'(by simpa using hi)).val *
        (glv.Z2_OVER_R.val[j.val]'(by rw [glv.Z2_OVER_R.property]; exact hj)).val +
        (p.val[i.val + j.val]'(by rw [p.property]; change i.val + j.val < 7; omega)).val + c.val ∧
      ij.val = i.val + j.val ∧ j'.val = j.val + 1 ∧
      glv.times_z2_over_r_loop0_loop0.body k i p c j =
        ok (cont (p.set ij (UScalar.cast .U64 t), ⟨t.bv.ushiftRight 64⟩, j')) := by
  let a := k.val[i.val]'(by simpa using hi)
  let b := glv.Z2_OVER_R.val[j.val]'(by rw [glv.Z2_OVER_R.property]; exact hj)
  let old := p.val[i.val + j.val]'(by rw [p.property]; change i.val + j.val < 7; omega)
  have ht := mac_bounds a b old c hc
  let t : U128 := UScalar.ofNatCore (a.val * b.val + old.val + c.val) ht
  let ij : Usize := UScalar.ofNatCore (i.val + j.val)
    (lt_of_lt_of_le (by omega : i.val + j.val < 2 ^ 32) two_pow_32_le_usize)
  let j' : Usize := UScalar.ofNatCore (j.val + 1)
    (lt_of_lt_of_le (by omega : j.val + 1 < 2 ^ 32) two_pow_32_le_usize)
  refine ⟨t, ij, j', rfl, rfl, rfl, ?_⟩
  have hj' : j < 3#usize := by exact hj
  simp only [glv.times_z2_over_r_loop0_loop0.body, hj', if_true]
  rw [index_usize_eq k i (by exact hi), index_usize_eq glv.Z2_OVER_R j (by exact hj)]
  simp only [lift, bind_tc_ok]
  rw [mul_ok _ _ (by rw [cast128_val, cast128_val]; change a.val * b.val < 2 ^ 128; omega)]
  simp only [bind_tc_ok]
  rw [usize_add_ok i j (by omega)]
  simp only [bind_tc_ok]
  change (do
    let old' ← Array.index_usize p ij
    let old'' ← lift (UScalar.cast .U128 old')
    let subtotal ← UScalar.ofNatCore (a.val * b.val) _ + old''
    let total ← subtotal + c
    let lo ← lift (UScalar.cast .U64 total)
    let p' ← Array.update p ij lo
    let c' ← total >>> 64#i32
    let j'' ← j + 1#usize
    ok (cont (p', c', j''))) = _
  rw [index_usize_eq p ij (by change i.val + j.val < 7; omega)]
  simp only [lift, bind_tc_ok]
  rw [add_ok _ _ (by rw [UScalar.ofNatCore_val_eq, cast128_val]; change a.val * b.val + old.val < 2 ^ 128; omega)]
  simp only [bind_tc_ok]
  rw [add_ok _ _ (by rw [UScalar.ofNatCore_val_eq]; exact ht)]
  simp only [bind_tc_ok]
  change (do
    let p' ← Array.update p ij (UScalar.cast .U64 t)
    let c' ← t >>> 64#i32
    let j'' ← j + 1#usize
    ok (cont (p', c', j''))) = _
  rw [update_eq p ij _ (by change i.val + j.val < 7; omega), shiftRight_64_i32]
  simp only [bind_tc_ok]
  rw [usize_add_ok j 1#usize (by change j.val + 1 < 2 ^ 32; omega)]
  rfl

def coefficientTail (j : ℕ) : ℤ := wordsValue (glv.Z2_OVER_R.val.drop j)

theorem coefficientTail_step (j : ℕ) (hj : j < 3) :
    coefficientTail j =
      (glv.Z2_OVER_R.val[j]'(by rw [glv.Z2_OVER_R.property]; exact hj)).val +
      (radix : ℤ) * coefficientTail (j + 1) := by
  unfold coefficientTail
  rw [List.drop_eq_getElem_cons (by rw [glv.Z2_OVER_R.property]; exact hj)]
  rfl

theorem coefficientTail_three : coefficientTail 3 = 0 := by
  simp [coefficientTail, glv.Z2_OVER_R.property, wordsValue]

theorem inner_exact (k : Array U64 4#usize) (p : Array U64 7#usize)
    (i j : Usize) (c : U128) (hi : i.val < 4) (hj : j.val ≤ 3)
    (hc : c.val < radix) :
    ∃ (out : Array U64 7#usize) (carry : U128),
      glv.times_z2_over_r_loop0_loop0 k p i c j = ok (out, carry) ∧
      carry.val < radix ∧
      value out + (carry.val : ℤ) * (radix : ℤ) ^ (i.val + 3) =
        value p + ((k.val[i.val]'(by rw [k.property]; exact hi)).val *
          coefficientTail j.val + (c.val : ℤ)) * (radix : ℤ) ^ (i.val + j.val) ∧
      ∀ q (hq : q < 7), i.val + 3 ≤ q →
        out.val[q]'(by rw [out.property]; exact hq) =
        p.val[q]'(by rw [p.property]; exact hq) := by
  induction hn : 3 - j.val generalizing p j c with
  | zero =>
    have hj3 : j.val = 3 := by omega
    have hjge : ¬j < 3#usize := by change ¬j.val < 3; omega
    refine ⟨p, c, ?_, hc, ?_, fun _ _ _ => rfl⟩
    · rw [glv.times_z2_over_r_loop0_loop0, loop.eq_1]
      simp [glv.times_z2_over_r_loop0_loop0.body, hjge]
    · rw [hj3, coefficientTail_three]
      ring
  | succ n ih =>
    have hjlt : j.val < 3 := by omega
    obtain ⟨t, ij, j', ht, hij, hj', hbody⟩ := inner_step k p i j c hi hjlt hc
    obtain ⟨out, carry, hloop, hcarry, heq, htail⟩ := ih (p.set ij (UScalar.cast .U64 t)) j'
      ⟨t.bv.ushiftRight 64⟩ (by omega) (high_bound t) (by omega)
    refine ⟨out, carry, ?_, hcarry, ?_, ?_⟩
    · rw [glv.times_z2_over_r_loop0_loop0, loop.eq_1]
      simpa only [hbody] using hloop
    · rw [heq, value_set p ij _ (by change ij.val < 7; omega)]
      simp only [hij, cast64_val, high_val, hj', coefficientTail_step j.val hjlt]
      have ht' : (t.val : ℤ) =
          (k.val[i.val]'(by rw [k.property]; exact hi)).val *
          (glv.Z2_OVER_R.val[j.val]'(by rw [glv.Z2_OVER_R.property]; exact hjlt)).val +
          (p.val[i.val + j.val]'(by rw [p.property]; change i.val + j.val < 7; omega)).val + c.val := by
        exact_mod_cast ht
      have hdiv : ((t.val % radix : ℕ) : ℤ) + (radix : ℤ) * (t.val / radix : ℕ) = t.val := by
        exact_mod_cast Nat.mod_add_div t.val radix
      rw [show i.val + (j.val + 1) = i.val + j.val + 1 by omega, pow_succ]
      linear_combination (hdiv + ht') * (radix : ℤ) ^ (i.val + j.val)
    · intro q hq hqi
      rw [htail q hq hqi]
      change (p.val.set ij.val (UScalar.cast .U64 t))[q]'_ = _
      rw [List.getElem_set_ne (by omega)]

def sourceTail (k : Array U64 4#usize) (i : ℕ) : ℤ := wordsValue (k.val.drop i)

theorem sourceTail_step (k : Array U64 4#usize) (i : ℕ) (hi : i < 4) :
    sourceTail k i = (k.val[i]'(by rw [k.property]; exact hi)).val +
      (radix : ℤ) * sourceTail k (i + 1) := by
  unfold sourceTail
  rw [List.drop_eq_getElem_cons (by rw [k.property]; exact hi)]
  rfl

theorem sourceTail_four (k : Array U64 4#usize) : sourceTail k 4 = 0 := by
  simp [sourceTail, k.property, wordsValue]

theorem outer_exact (k : Array U64 4#usize) (p : Array U64 7#usize)
    (i : Usize) (hi : i.val ≤ 4)
    (hz : ∀ q (hq : q < 7), i.val + 3 ≤ q →
      p.val[q]'(by rw [p.property]; exact hq) = 0#u64) :
    ∃ out : Array U64 7#usize,
      glv.times_z2_over_r_loop0 k p i = ok out ∧
      value out = value p + sourceTail k i.val * coefficientTail 0 * (radix : ℤ) ^ i.val := by
  induction hn : 4 - i.val generalizing p i with
  | zero =>
    have hi4 : i.val = 4 := by omega
    have hige : ¬i < 4#usize := by change ¬i.val < 4; omega
    refine ⟨p, ?_, ?_⟩
    · rw [glv.times_z2_over_r_loop0, loop.eq_1]
      simp [glv.times_z2_over_r_loop0.body, hige]
    · rw [hi4, sourceTail_four]
      ring
  | succ n ih =>
    have hilt : i.val < 4 := by omega
    obtain ⟨row, carry, hinner, hc, heq, htail⟩ :=
      inner_exact k p i 0#usize 0#u128 hilt (by decide) (by decide)
    let last : Usize := UScalar.ofNatCore (i.val + 3)
      (lt_of_lt_of_le (by omega : i.val + 3 < 2 ^ 32) two_pow_32_le_usize)
    let next : Usize := UScalar.ofNatCore (i.val + 1)
      (lt_of_lt_of_le (by omega : i.val + 1 < 2 ^ 32) two_pow_32_le_usize)
    have hlast : last.val = i.val + 3 := rfl
    have hnext : next.val = i.val + 1 := rfl
    let p' := row.set last (UScalar.cast .U64 carry)
    have hpz : row.val[last.val]'(by rw [row.property]; change last.val < 7; omega) = 0#u64 := by
      rw [htail last.val (by omega) (by omega)]
      exact hz last.val (by omega) (by omega)
    have hp' : value p' = value p +
        (k.val[i.val]'(by rw [k.property]; exact hilt)).val * coefficientTail 0 * (radix : ℤ) ^ i.val := by
      rw [value_set row last _ (by change last.val < 7; omega), hpz, cast64_val,
        Nat.mod_eq_of_lt hc]
      simp only [hlast]
      simp only [show (0#usize).val = 0 from rfl, show (0#u128).val = 0 from rfl,
        show (0#u64).val = 0 from rfl, Nat.cast_zero, add_zero, sub_zero] at heq ⊢
      exact heq
    have hz' : ∀ q (hq : q < 7), next.val + 3 ≤ q →
        p'.val[q]'(by rw [p'.property]; exact hq) = 0#u64 := by
      intro q hq hqi
      change (row.val.set last.val (UScalar.cast .U64 carry))[q]'_ = _
      rw [List.getElem_set_ne (by omega), htail q hq (by omega)]
      exact hz q hq (by omega)
    obtain ⟨out, hloop, hout⟩ := ih p' next (by omega) hz' (by omega)
    refine ⟨out, ?_, ?_⟩
    · rw [glv.times_z2_over_r_loop0, loop.eq_1]
      have hbody : glv.times_z2_over_r_loop0.body k p i = ok (cont (p', next)) := by
        simp only [glv.times_z2_over_r_loop0.body, show i < 4#usize from hilt,
          if_true, hinner, bind_tc_ok]
        rw [usize_add_ok i 3#usize (by change i.val + 3 < 2 ^ 32; omega)]
        simp only [bind_tc_ok, lift]
        change (do
          let a ← Array.update row last (UScalar.cast .U64 carry)
          let i3 ← i + 1#usize
          ok (cont (a, i3))) = _
        rw [update_eq row last _ (by change last.val < 7; omega)]
        simp only [bind_tc_ok]
        rw [usize_add_ok i 1#usize (by change i.val + 1 < 2 ^ 32; omega)]
        rfl
      simpa only [hbody] using hloop
    · rw [hout, hp', hnext, sourceTail_step k i.val hilt, pow_succ]
      ring

theorem times_z2_over_r_refines (k : Array U64 4#usize) :
    ∃ product : Array U64 7#usize,
      glv.times_z2_over_r k = ok product ∧
      value product = value k * 505667019974147811778249931229775261232 := by
  obtain ⟨product, hp, hv⟩ := outer_exact k (Array.repeat 7#usize 0#u64) 0#usize
    (by decide) (by intro q hq _; change (List.replicate 7 (0#u64))[q]' _ = _; simp only [List.getElem_replicate])
  refine ⟨product, hp, ?_⟩
  simpa [sourceTail, value, Array.repeat, wordsValue,
    show coefficientTail 0 = 505667019974147811778249931229775261232 from by decide +kernel] using hv


def roundedPrefix (product : Array U64 7#usize) : Result (Array U64 2#usize) := do
  let i ← Array.index_usize product 4#usize
  let i1 ← lift (UScalar.cast .U128 i)
  let i2 ← Array.index_usize product 3#usize
  let i3 ← i2 >>> 63#i32
  let i4 ← lift (UScalar.cast .U128 i3)
  let low ← i1 + i4
  let i5 ← lift (UScalar.cast .U64 low)
  let i6 ← Array.index_usize product 5#usize
  let i7 ← low >>> 64#i32
  let i8 ← lift (UScalar.cast .U64 i7)
  let i9 ← i6 + i8
  ok (Array.make 2#usize [i5, i9] (by rfl))

theorem array7_eta (p : Array U64 7#usize) :
    p = Array.make 7#usize [p.val[0], p.val[1], p.val[2], p.val[3], p.val[4], p.val[5], p.val[6]] (by rfl) := by
  apply Subtype.ext
  apply List.ext_getElem
  · exact p.property
  · intro i hi hi'
    have hi7 : i < 7 := by simpa only [p.property] using hi
    interval_cases i <;> rfl

theorem shift63_val (a : U64) : (⟨a.bv.ushiftRight 63⟩ : U64).val = a.val / 2 ^ 63 := by
  change (a.bv >>> (63 : ℕ)).toNat = a.val / 2 ^ 63
  rw [BitVec.toNat_ushiftRight, Nat.shiftRight_eq_div_pow]
  rfl

theorem roundedPrefix_refines (p : Array U64 7#usize)
    (hp : value p + 2 ^ 255 < 2 ^ 384) :
    ∃ c : Array U64 2#usize, roundedPrefix p = ok c ∧
      value c = (value p + 2 ^ 255) / 2 ^ 256 := by
  have he := array7_eta p
  generalize p.val[0] = a at he
  generalize p.val[1] = b at he
  generalize p.val[2] = c at he
  generalize p.val[3] = d at he
  generalize p.val[4] = e at he
  generalize p.val[5] = f at he
  generalize p.val[6] = g at he
  rw [he] at hp ⊢
  clear he p
  have ha := a.hBounds
  have hb := b.hBounds
  have hc := c.hBounds
  have hd := d.hBounds
  have he := e.hBounds
  have hf := f.hBounds
  have hg := g.hBounds
  have hv : value (Array.make 7#usize [a, b, c, d, e, f, g] (by rfl)) =
      a.val + (radix : ℤ) * (b.val + (radix : ℤ) * (c.val + (radix : ℤ) *
      (d.val + (radix : ℤ) * (e.val + (radix : ℤ) * (f.val + (radix : ℤ) * g.val))))) := rfl
  have hlow : e.val + d.val / 2 ^ 63 < 2 ^ 128 := by
    norm_num [UScalarTy.numBits] at hd he ⊢
    omega
  let low : U128 := UScalar.ofNatCore (e.val + d.val / 2 ^ 63) hlow
  have hhigh : f.val + low.val / radix < 2 ^ 64 := by
    rw [hv] at hp
    dsimp [low]
    norm_num [radix, UScalarTy.numBits] at *
    omega
  let high : U64 := UScalar.ofNatCore (f.val + low.val / radix) hhigh
  refine ⟨Array.make 2#usize [UScalar.cast .U64 low, high] (by rfl), ?_, ?_⟩
  · simp only [roundedPrefix]
    rw [index_usize_eq _ 4#usize (by decide), index_usize_eq _ 3#usize (by decide)]
    simp only [Array.make, show (3#usize).val = 3 from rfl,
      show (4#usize).val = 4 from rfl, List.getElem_cons_succ, List.getElem_cons_zero, lift, bind_tc_ok]
    rw [show d >>> 63#i32 = ok (⟨d.bv.ushiftRight 63⟩ : U64) from rfl]
    simp only [bind_tc_ok]
    rw [add_ok _ _ (by rw [cast128_val, cast128_val, shift63_val]; exact hlow)]
    simp only [bind_tc_ok, cast128_val, shift63_val]
    change (do
      let f' ← Array.index_usize (Array.make 7#usize [a, b, c, d, e, f, g] (by rfl)) 5#usize
      let h ← low >>> 64#i32
      let high' ← f' + UScalar.cast .U64 h
      ok (Array.make 2#usize [UScalar.cast .U64 low, high'] (by rfl))) = _
    rw [index_usize_eq _ 5#usize (by decide), shiftRight_64_i32]
    simp only [Array.make, show (5#usize).val = 5 from rfl,
      List.getElem_cons_succ, List.getElem_cons_zero, bind_tc_ok]
    have hcast : (UScalar.cast .U64 (⟨low.bv.ushiftRight 64⟩ : U128)).val = low.val / radix := by
      rw [cast64_val, high_val, Nat.mod_eq_of_lt]
      exact (high_val low) ▸ high_bound low
    rw [add_ok _ _ (by rw [hcast]; exact hhigh)]
    simp only [bind_tc_ok]
    simp only [hcast]
    rfl
  · change (UScalar.cast .U64 low).val + (radix : ℤ) * (high.val + (radix : ℤ) * 0) = _
    rw [cast64_val, hv]
    dsimp [low, high]
    norm_num [radix, UScalarTy.numBits] at *
    omega


theorem rounded_c1_refines (k : Array U64 4#usize) (hk : value k < 2 ^ 255) :
    ∃ (product : Array U64 7#usize) (c : Array U64 2#usize),
      glv.times_z2_over_r k = ok product ∧ roundedPrefix product = ok c ∧
      value c = (value k * 505667019974147811778249931229775261232 + 2 ^ 255) / 2 ^ 256 := by
  obtain ⟨product, hp, hv⟩ := times_z2_over_r_refines k
  have hbound : value product + 2 ^ 255 < 2 ^ 384 := by
    rw [hv]
    norm_num at hk ⊢
    omega
  obtain ⟨c, hc, heq⟩ := roundedPrefix_refines product hbound
  exact ⟨product, c, hp, hc, hv ▸ heq⟩

theorem decompose_prefix (k : Array U64 4#usize) :
    glv.decompose k = (do
      let product ← glv.times_z2_over_r k
      let c1 ← roundedPrefix product
      let b ← glv.at_least_half_r k
      let c2 ← lift (UScalar.cast_fromBool .U64 b)
      let k1 ← glv.signed_difference k c2 c1 glv.LAMBDA
      let i10 ← Array.index_usize c1 0#usize
      let i11 ← Array.index_usize c1 1#usize
      let k2 ← glv.signed_difference
        (Array.make 4#usize [i10, i11, 0#u64, 0#u64] (by rfl)) 0#u64
        (Array.make 2#usize [c2, 0#u64] (by rfl)) glv.Z2
      ok (k1, k2)) := by
  simp only [glv.decompose, roundedPrefix, bind_assoc, bind_tc_ok]


theorem compare_loop_step (k : Array U64 4#usize) (i j : Usize)
    (hi : 0#usize < i) (hj : j.val < 4) (hsub : i - 1#usize = ok j) :
    glv.at_least_half_r_loop k i =
      if (k.val[j.val]'(by rw [k.property]; exact hj)) =
          (glv.HALF_R_UP.val[j.val]'(by rw [glv.HALF_R_UP.property]; exact hj))
      then glv.at_least_half_r_loop k j else ok i := by
  rw [glv.at_least_half_r_loop, loop.eq_1]
  simp only [glv.at_least_half_r_loop.body, hi, if_true, hsub, bind_tc_ok]
  rw [index_usize_eq k j hj, index_usize_eq glv.HALF_R_UP j hj]
  simp only [bind_tc_ok]
  split_ifs <;> rfl

theorem compare_loop_zero (k : Array U64 4#usize) :
    glv.at_least_half_r_loop k 0#usize = ok 0#usize := by
  rw [glv.at_least_half_r_loop, loop.eq_1]
  rfl

theorem at_least_half_r_eval (a b c d : U64) :
    glv.at_least_half_r (Array.make 4#usize [a, b, c, d] (by rfl)) =
    ok (if d = 4176758429732224676#u64 then
      if c = 1845609449319885826#u64 then
        if b = 12240451741123816959#u64 then decide (9223372034707292161#u64 ≤ a)
        else decide (12240451741123816959#u64 < b)
      else decide (1845609449319885826#u64 < c)
    else decide (4176758429732224676#u64 < d)) := by
  rw [glv.at_least_half_r]
  rw [compare_loop_step _ 4#usize 3#usize (by decide) (by decide) (by simp [sub_ok])]
  rw [compare_loop_step _ 3#usize 2#usize (by decide) (by decide) (by simp [sub_ok])]
  rw [compare_loop_step _ 2#usize 1#usize (by decide) (by decide) (by simp [sub_ok])]
  rw [compare_loop_step _ 1#usize 0#usize (by decide) (by decide) (by simp [sub_ok])]
  rw [compare_loop_zero]
  simp only [glv.HALF_R_UP, Array.make, show (3#usize).val = 3 from rfl,
    show (2#usize).val = 2 from rfl, show (1#usize).val = 1 from rfl,
    show (0#usize).val = 0 from rfl, List.getElem_cons_succ, List.getElem_cons_zero]
  split_ifs <;> simp_all [Array.index_usize, sub_ok]
  omega

theorem at_least_half_r_refines (k : Array U64 4#usize) :
    glv.at_least_half_r k =
      ok (decide (26217937587563095239723870254092982918845276250263818911301829349969290592257 ≤ value k)) := by
  rcases k with ⟨xs, hxs⟩
  obtain ⟨a, b, c, d, rfl⟩ := List.length_eq_four.mp hxs
  change glv.at_least_half_r (Array.make 4#usize [a, b, c, d] (by rfl)) = _
  rw [at_least_half_r_eval]
  apply congrArg Result.ok
  have ha := a.hBounds
  have hb := b.hBounds
  have hc := c.hBounds
  have hd := d.hBounds
  split_ifs
  all_goals apply Bool.eq_iff_iff.mpr
  all_goals simp_all [value, wordsValue, radix, UScalarTy.numBits]
  all_goals omega

theorem negated_step (words p : Array U64 4#usize) (c : U128) (i : Usize)
    (hi : i.val < 4) (hc : c.val ≤ 1) :
    ∃ (t : U128) (next : Usize),
      t.val = radix - 1 - (words.val[i.val]'(by rw [words.property]; exact hi)).val + c.val ∧
      t.val ≤ radix ∧ next.val = i.val + 1 ∧
      glv.negated_loop.body words p c i =
        ok (cont (p.set i (UScalar.cast .U64 t), ⟨t.bv.ushiftRight 64⟩, next)) := by
  let a := words.val[i.val]'(by rw [words.property]; exact hi)
  have ht : radix - 1 - a.val + c.val < 2 ^ 128 := by norm_num [radix]; omega
  let t : U128 := UScalar.ofNatCore (radix - 1 - a.val + c.val) ht
  let next : Usize := UScalar.ofNatCore (i.val + 1)
    (lt_of_lt_of_le (by omega : i.val + 1 < 2 ^ 32) two_pow_32_le_usize)
  refine ⟨t, next, rfl, ?_, rfl, ?_⟩
  · change radix - 1 - a.val + c.val ≤ radix
    norm_num [radix]
    omega
  · simp only [glv.negated_loop.body, show i < 4#usize from hi, if_true]
    rw [index_usize_eq words i hi]
    simp only [lift, bind_tc_ok]
    rw [add_ok _ _ (by rw [cast128_val, complement_val]; exact ht)]
    simp only [bind_tc_ok, cast128_val, complement_val]
    change (do
      let a ← Array.update p i (UScalar.cast .U64 t)
      let c' ← t >>> 64#i32
      let i' ← i + 1#usize
      ok (cont (a, c', i'))) = _
    rw [update_eq p i _ hi, shiftRight_64_i32]
    simp only [bind_tc_ok]
    rw [usize_add_ok i 1#usize (by change i.val + 1 < 2 ^ 32; omega)]
    rfl

theorem negated_loop_exact (words p : Array U64 4#usize) (c : U128) (i : Usize)
    (hi : i.val ≤ 4) (hc : c.val ≤ 1)
    (hz : ∀ q (hq : q < 4), i.val ≤ q → p.val[q]'(by rw [p.property]; exact hq) = 0#u64) :
    ∃ (out : Array U64 4#usize) (carry : U128),
      glv.negated_loop words p c i = ok out ∧ carry.val ≤ 1 ∧
      value out + (carry.val : ℤ) * (radix : ℤ) ^ 4 = value p +
        ((radix : ℤ) ^ (4 - i.val) - 1 - sourceTail words i.val + c.val) *
          (radix : ℤ) ^ i.val := by
  induction hn : 4 - i.val generalizing p c i with
  | zero =>
    have hi4 : i.val = 4 := by omega
    have hige : ¬i < 4#usize := by change ¬i.val < 4; omega
    refine ⟨p, c, ?_, hc, ?_⟩
    · rw [glv.negated_loop, loop.eq_1]
      simp [glv.negated_loop.body, hige]
    · rw [hi4, sourceTail_four]
      norm_num
  | succ n ih =>
    have hilt : i.val < 4 := by omega
    obtain ⟨t, next, ht, htb, hnxt, hbody⟩ := negated_step words p c i hilt hc
    let p' := p.set i (UScalar.cast .U64 t)
    let c' : U128 := ⟨t.bv.ushiftRight 64⟩
    have hc' : c'.val ≤ 1 := by
      rw [high_val]
      norm_num [radix] at htb ⊢
      omega
    have hz' : ∀ q (hq : q < 4), next.val ≤ q →
        p'.val[q]'(by rw [p'.property]; exact hq) = 0#u64 := by
      intro q hq hqi
      change (p.val.set i.val (UScalar.cast .U64 t))[q]'_ = _
      rw [List.getElem_set_ne (by omega)]
      exact hz q hq (by omega)
    obtain ⟨out, carry, hloop, hcarry, heq⟩ := ih p' c' next (by omega) hc' hz' (by omega)
    refine ⟨out, carry, ?_, hcarry, ?_⟩
    · rw [glv.negated_loop, loop.eq_1]
      simpa only [hbody] using hloop
    · rw [heq, value_set p i _ hilt, hz i.val hilt (by omega), cast64_val]
      have ht' : (t.val : ℤ) = (radix : ℤ) - 1 -
          (words.val[i.val]'(by rw [words.property]; exact hilt)).val + c.val := by
        have ha := (words.val[i.val]'(by rw [words.property]; exact hilt)).hBounds
        rw [ht]
        norm_num [radix, UScalarTy.numBits] at ha ⊢
        omega
      have hdiv : ((t.val % radix : ℕ) : ℤ) + (radix : ℤ) * (t.val / radix : ℕ) = t.val := by
        exact_mod_cast Nat.mod_add_div t.val radix
      simp only [show (0#u64).val = 0 from rfl, Nat.cast_zero, sub_zero,
        sourceTail_step words i.val hilt, c', high_val, hnxt, pow_succ]
      linear_combination (hdiv + ht') * (radix : ℤ) ^ i.val

theorem negated_refines (words : Array U64 4#usize) :
    ∃ out : Array U64 4#usize, glv.negated words = ok out ∧
      value out = (-value words) % 2 ^ 256 := by
  obtain ⟨out, carry, hloop, hcarry, heq⟩ := negated_loop_exact words
    (Array.repeat 4#usize 0#u64) 1#u128 0#usize (by decide) (by decide)
    (by intro q hq _; change (List.replicate 4 (0#u64))[q]'_ = _; simp only [List.getElem_replicate])
  refine ⟨out, hloop, ?_⟩
  have hb := value_bounds out
  have hz : value (Array.repeat 4#usize 0#u64) = 0 := by
    change wordsValue (List.replicate 4 0#u64) = 0
    rfl
  rw [hz] at heq
  norm_num [value, wordsValue, sourceTail, Array.repeat, radix] at heq hb ⊢
  omega

theorem twice_radix_shift : 2#u128 <<< 64#i32 = ok 36893488147419103232#u128 := by
  rfl

theorem subtraction_facts (x y z borrow : U64) (hb : borrow.val ≤ 2) :
    36893488147419103232 + x.val < 2 ^ 128 ∧
    y.val ≤ 36893488147419103232 + x.val ∧
    z.val ≤ 36893488147419103232 + x.val - y.val ∧
    borrow.val ≤ 36893488147419103232 + x.val - y.val - z.val ∧
    36893488147419103232 + x.val - y.val - z.val - borrow.val < 3 * radix ∧
    ((36893488147419103232 + x.val - y.val - z.val - borrow.val : ℕ) : ℤ) =
      36893488147419103232 + (x.val : ℤ) - y.val - z.val - borrow.val := by
  have hx := x.hBounds
  have hy := y.hBounds
  have hz := z.hBounds
  norm_num [radix, UScalarTy.numBits] at hx hy hz ⊢
  omega

theorem subtraction_run {α : Type} (x y z borrow : U64) (hb : borrow.val ≤ 2)
    (f : U128 → Result α) :
    ∃ t : U128,
      (t.val : ℤ) = 36893488147419103232 + x.val - y.val - z.val - borrow.val ∧ t.val < 3 * radix ∧
      (do
        let base ← 2#u128 <<< 64#i32
        let s ← base + UScalar.cast .U128 x
        let s ← s - UScalar.cast .U128 y
        let s ← s - UScalar.cast .U128 z
        let t ← s - UScalar.cast .U128 borrow
        f t) = f t := by
  obtain ⟨hsum, hsub1, hsub2, hsub3, htb, htint⟩ := subtraction_facts x y z borrow hb
  obtain ⟨s1, hs1, hv1⟩ := add_value 36893488147419103232#u128 (UScalar.cast .U128 x)
    (by rw [cast128_val]; exact hsum)
  have hv1' : s1.val = 36893488147419103232 + x.val := by simpa only [cast128_val] using hv1
  obtain ⟨s2, hs2, hv2⟩ := sub_value s1 (UScalar.cast .U128 y)
    (by rw [cast128_val, hv1']; exact hsub1)
  have hv2' : s2.val = 36893488147419103232 + x.val - y.val := by simpa only [cast128_val, hv1'] using hv2
  obtain ⟨s3, hs3, hv3⟩ := sub_value s2 (UScalar.cast .U128 z)
    (by rw [cast128_val, hv2']; exact hsub2)
  have hv3' : s3.val = 36893488147419103232 + x.val - y.val - z.val := by simpa only [cast128_val, hv2'] using hv3
  obtain ⟨t, hst, hvt⟩ := sub_value s3 (UScalar.cast .U128 borrow)
    (by rw [cast128_val, hv3']; exact hsub3)
  have hvt' : t.val = 36893488147419103232 + x.val - y.val - z.val - borrow.val := by
    simpa only [cast128_val, hv3'] using hvt
  refine ⟨t, ?_, ?_, ?_⟩
  · rw [hvt']; exact htint
  · rw [hvt']; exact htb
  · rw [twice_radix_shift]
    simp only [bind_tc_ok, hs1, hs2, hs3, hst]

theorem subtract_step (a cd sub p : Array U64 4#usize) (borrow : U64) (i : Usize)
    (hi : i.val < 4) (hb : borrow.val ≤ 2) :
    ∃ (t : U128) (b : U64) (next : Usize),
      (t.val : ℤ) = 2 * (radix : ℤ) +
        (a.val[i.val]'(by rw [a.property]; exact hi)).val -
        (sub.val[i.val]'(by rw [sub.property]; exact hi)).val -
        (cd.val[i.val]'(by rw [cd.property]; exact hi)).val - borrow.val ∧
      t.val < 3 * radix ∧ b.val = 2 - t.val / radix ∧ next.val = i.val + 1 ∧
      glv.signed_difference_loop1.body a cd sub i p borrow =
        ok (cont (next, p.set i (UScalar.cast .U64 t), b)) := by
  let x := a.val[i.val]'(by rw [a.property]; exact hi)
  let y := sub.val[i.val]'(by rw [sub.property]; exact hi)
  let z := cd.val[i.val]'(by rw [cd.property]; exact hi)
  let f : U128 → Result (ControlFlow (Usize × Array U64 4#usize × U64) (Array U64 4#usize × U64)) := fun t => do
    let p' ← Array.update p i (UScalar.cast .U64 t)
    let h ← t >>> 64#i32
    let b' ← 2#u64 - UScalar.cast .U64 h
    let next' ← i + 1#usize
    ok (cont (next', p', b'))
  obtain ⟨t, htint, htb, hrun⟩ := subtraction_run x y z borrow hb f
  have hq : t.val / radix ≤ 2 := by norm_num [radix] at htb ⊢; omega
  let b : U64 := UScalar.ofNatCore (2 - t.val / radix) (lt_of_le_of_lt (Nat.sub_le 2 _) (by decide))
  let next : Usize := UScalar.ofNatCore (i.val + 1)
    (lt_of_lt_of_le (by omega : i.val + 1 < 2 ^ 32) two_pow_32_le_usize)
  refine ⟨t, b, next, htint, htb, rfl, rfl, ?_⟩
  simp only [glv.signed_difference_loop1.body, show i < 4#usize from hi, if_true]
  simp only [index_usize_eq a i hi, index_usize_eq sub i hi, index_usize_eq cd i hi,
    bind_tc_ok, lift]
  change (do
    let base ← 2#u128 <<< 64#i32
    let s ← base + UScalar.cast .U128 x
    let s ← s - UScalar.cast .U128 y
    let s ← s - UScalar.cast .U128 z
    let t ← s - UScalar.cast .U128 borrow
    f t) = _
  rw [hrun]
  dsimp only [f]
  rw [update_eq p i _ hi, shiftRight_64_i32]
  simp only [bind_tc_ok]
  have hcast : (UScalar.cast .U64 (⟨t.bv.ushiftRight 64⟩ : U128)).val = t.val / radix := by
    rw [cast64_val, high_val, Nat.mod_eq_of_lt]
    exact (high_val t) ▸ high_bound t
  rw [sub_ok _ _ (by rw [hcast]; exact hq)]
  simp only [bind_tc_ok, hcast]
  rw [usize_add_ok i 1#usize (by change i.val + 1 < 2 ^ 32; omega)]
  rfl

theorem subtract_loop_exact (a cd sub p : Array U64 4#usize) (borrow : U64) (i : Usize)
    (hi : i.val ≤ 4) (hb : borrow.val ≤ 2)
    (hz : ∀ q (hq : q < 4), i.val ≤ q → p.val[q]'(by rw [p.property]; exact hq) = 0#u64) :
    ∃ (out : Array U64 4#usize) (b : U64),
      glv.signed_difference_loop1 a cd i sub p borrow = ok (out, b) ∧ b.val ≤ 2 ∧
      value out - (b.val : ℤ) * (radix : ℤ) ^ 4 = value p +
        (sourceTail a i.val - sourceTail sub i.val - sourceTail cd i.val - borrow.val) *
          (radix : ℤ) ^ i.val := by
  induction hn : 4 - i.val generalizing p borrow i with
  | zero =>
    have hi4 : i.val = 4 := by omega
    have hige : ¬i < 4#usize := by change ¬i.val < 4; omega
    refine ⟨p, borrow, ?_, hb, ?_⟩
    · rw [glv.signed_difference_loop1, loop.eq_1]
      simp [glv.signed_difference_loop1.body, hige]
    · rw [hi4, sourceTail_four, sourceTail_four, sourceTail_four]
      ring
  | succ n ih =>
    have hilt : i.val < 4 := by omega
    obtain ⟨t, b, next, ht, htb, hbval, hnxt, hbody⟩ := subtract_step a cd sub p borrow i hilt hb
    let p' := p.set i (UScalar.cast .U64 t)
    have hb' : b.val ≤ 2 := by rw [hbval]; exact Nat.sub_le _ _
    have hz' : ∀ q (hq : q < 4), next.val ≤ q →
        p'.val[q]'(by rw [p'.property]; exact hq) = 0#u64 := by
      intro q hq hqi
      change (p.val.set i.val (UScalar.cast .U64 t))[q]'_ = _
      rw [List.getElem_set_ne (by omega)]
      exact hz q hq (by omega)
    obtain ⟨out, carry, hloop, hcarry, heq⟩ := ih p' b next (by omega) hb' hz' (by omega)
    refine ⟨out, carry, ?_, hcarry, ?_⟩
    · rw [glv.signed_difference_loop1, loop.eq_1]
      simpa only [hbody] using hloop
    · rw [heq, value_set p i _ hilt, hz i.val hilt (by omega), cast64_val]
      have hdiv : ((t.val % radix : ℕ) : ℤ) + (radix : ℤ) * (t.val / radix : ℕ) = t.val := by
        exact_mod_cast Nat.mod_add_div t.val radix
      have hbint : (b.val : ℤ) = 2 - ((t.val / radix : ℕ) : ℤ) := by
        rw [hbval]
        have hq : t.val / radix ≤ 2 := by norm_num [radix] at htb ⊢; omega
        omega
      simp only [show (0#u64).val = 0 from rfl, Nat.cast_zero, sub_zero,
        sourceTail_step a i.val hilt, sourceTail_step sub i.val hilt,
        sourceTail_step cd i.val hilt, hbint, hnxt, pow_succ]
      linear_combination (hdiv + ht) * (radix : ℤ) ^ i.val

theorem subtract_refines (a cd sub : Array U64 4#usize) :
    ∃ (out : Array U64 4#usize) (b : U64),
      glv.signed_difference_loop1 a cd 0#usize sub (Array.repeat 4#usize 0#u64) 0#u64 = ok (out, b) ∧
      b.val ≤ 2 ∧ value out - (b.val : ℤ) * 2 ^ 256 = value a - value sub - value cd := by
  obtain ⟨out, b, hloop, hb, heq⟩ := subtract_loop_exact a cd sub
    (Array.repeat 4#usize 0#u64) 0#u64 0#usize (by decide) (by decide)
    (by intro q hq _; change (List.replicate 4 (0#u64))[q]'_ = _; simp only [List.getElem_replicate])
  refine ⟨out, b, hloop, hb, ?_⟩
  have hz : value (Array.repeat 4#usize 0#u64) = 0 := rfl
  rw [hz] at heq
  simpa [value, sourceTail, radix] using heq

end LeanBlsSimd.GlvRefines

namespace LeanBlsSimd.GlvRefines
open silver_crypto_simd.bls.msm8

theorem mul2_inner_step (k d : Array U64 2#usize) (p : Array U64 4#usize)
    (i j : Usize) (c : U128) (hi : i.val < 2) (hj : j.val < 2)
    (hc : c.val < radix) :
    ∃ (t : U128) (ij j' : Usize),
      t.val = (k.val[i.val]'(by simpa using hi)).val *
        (d.val[j.val]'(by rw [d.property]; exact hj)).val +
        (p.val[i.val + j.val]'(by rw [p.property]; change i.val + j.val < 4; omega)).val + c.val ∧
      ij.val = i.val + j.val ∧ j'.val = j.val + 1 ∧
      glv.signed_difference_loop0_loop0.body k d i p c j =
        ok (cont (p.set ij (UScalar.cast .U64 t), ⟨t.bv.ushiftRight 64⟩, j')) := by
  let a := k.val[i.val]'(by simpa using hi)
  let b := d.val[j.val]'(by rw [d.property]; exact hj)
  let old := p.val[i.val + j.val]'(by rw [p.property]; change i.val + j.val < 4; omega)
  have ht := mac_bounds a b old c hc
  let t : U128 := UScalar.ofNatCore (a.val * b.val + old.val + c.val) ht
  let ij : Usize := UScalar.ofNatCore (i.val + j.val)
    (lt_of_lt_of_le (by omega : i.val + j.val < 2 ^ 32) two_pow_32_le_usize)
  let j' : Usize := UScalar.ofNatCore (j.val + 1)
    (lt_of_lt_of_le (by omega : j.val + 1 < 2 ^ 32) two_pow_32_le_usize)
  refine ⟨t, ij, j', rfl, rfl, rfl, ?_⟩
  have hj' : j < 2#usize := by exact hj
  simp only [glv.signed_difference_loop0_loop0.body, hj', if_true]
  rw [index_usize_eq k i (by exact hi), index_usize_eq d j (by exact hj)]
  simp only [lift, bind_tc_ok]
  rw [mul_ok _ _ (by rw [cast128_val, cast128_val]; change a.val * b.val < 2 ^ 128; omega)]
  simp only [bind_tc_ok]
  rw [usize_add_ok i j (by omega)]
  simp only [bind_tc_ok]
  change (do
    let old' ← Array.index_usize p ij
    let old'' ← lift (UScalar.cast .U128 old')
    let subtotal ← UScalar.ofNatCore (a.val * b.val) _ + old''
    let total ← subtotal + c
    let lo ← lift (UScalar.cast .U64 total)
    let p' ← Array.update p ij lo
    let c' ← total >>> 64#i32
    let j'' ← j + 1#usize
    ok (cont (p', c', j''))) = _
  rw [index_usize_eq p ij (by change i.val + j.val < 4; omega)]
  simp only [lift, bind_tc_ok]
  rw [add_ok _ _ (by rw [UScalar.ofNatCore_val_eq, cast128_val]; change a.val * b.val + old.val < 2 ^ 128; omega)]
  simp only [bind_tc_ok]
  rw [add_ok _ _ (by rw [UScalar.ofNatCore_val_eq]; exact ht)]
  simp only [bind_tc_ok]
  change (do
    let p' ← Array.update p ij (UScalar.cast .U64 t)
    let c' ← t >>> 64#i32
    let j'' ← j + 1#usize
    ok (cont (p', c', j''))) = _
  rw [update_eq p ij _ (by change i.val + j.val < 4; omega), shiftRight_64_i32]
  simp only [bind_tc_ok]
  rw [usize_add_ok j 1#usize (by change j.val + 1 < 2 ^ 32; omega)]
  rfl

def mul2_tail (d : Array U64 2#usize) (j : ℕ) : ℤ := wordsValue (d.val.drop j)

theorem mul2_tail_step (d : Array U64 2#usize) (j : ℕ) (hj : j < 2) :
    mul2_tail d j =
      (d.val[j]'(by rw [d.property]; exact hj)).val +
      (radix : ℤ) * mul2_tail d (j + 1) := by
  unfold mul2_tail
  rw [List.drop_eq_getElem_cons (by rw [d.property]; exact hj)]
  rfl

theorem mul2_tail_two (d : Array U64 2#usize) : mul2_tail d 2 = 0 := by
  simp [mul2_tail, d.property, wordsValue]

theorem mul2_inner_exact (k d : Array U64 2#usize) (p : Array U64 4#usize)
    (i j : Usize) (c : U128) (hi : i.val < 2) (hj : j.val ≤ 2)
    (hc : c.val < radix) :
    ∃ (out : Array U64 4#usize) (carry : U128),
      glv.signed_difference_loop0_loop0 k d p i c j = ok (out, carry) ∧
      carry.val < radix ∧
      value out + (carry.val : ℤ) * (radix : ℤ) ^ (i.val + 2) =
        value p + ((k.val[i.val]'(by rw [k.property]; exact hi)).val *
          mul2_tail d j.val + (c.val : ℤ)) * (radix : ℤ) ^ (i.val + j.val) ∧
      ∀ q (hq : q < 4), i.val + 2 ≤ q →
        out.val[q]'(by rw [out.property]; exact hq) =
        p.val[q]'(by rw [p.property]; exact hq) := by
  induction hn : 2 - j.val generalizing p j c with
  | zero =>
    have hj2 : j.val = 2 := by omega
    have hjge : ¬j < 2#usize := by change ¬j.val < 2; omega
    refine ⟨p, c, ?_, hc, ?_, fun _ _ _ => rfl⟩
    · rw [glv.signed_difference_loop0_loop0, loop.eq_1]
      simp [glv.signed_difference_loop0_loop0.body, hjge]
    · rw [hj2, mul2_tail_two d]
      ring
  | succ n ih =>
    have hjlt : j.val < 2 := by omega
    obtain ⟨t, ij, j', ht, hij, hj', hbody⟩ := mul2_inner_step k d p i j c hi hjlt hc
    obtain ⟨out, carry, hloop, hcarry, heq, htail⟩ := ih (p.set ij (UScalar.cast .U64 t)) j'
      ⟨t.bv.ushiftRight 64⟩ (by omega) (high_bound t) (by omega)
    refine ⟨out, carry, ?_, hcarry, ?_, ?_⟩
    · rw [glv.signed_difference_loop0_loop0, loop.eq_1]
      simpa only [hbody] using hloop
    · rw [heq, value_set p ij _ (by change ij.val < 4; omega)]
      simp only [hij, cast64_val, high_val, hj', mul2_tail_step d j.val hjlt]
      have ht' : (t.val : ℤ) =
          (k.val[i.val]'(by rw [k.property]; exact hi)).val *
          (d.val[j.val]'(by rw [d.property]; exact hjlt)).val +
          (p.val[i.val + j.val]'(by rw [p.property]; change i.val + j.val < 4; omega)).val + c.val := by
        exact_mod_cast ht
      have hdiv : ((t.val % radix : ℕ) : ℤ) + (radix : ℤ) * (t.val / radix : ℕ) = t.val := by
        exact_mod_cast Nat.mod_add_div t.val radix
      rw [show i.val + (j.val + 1) = i.val + j.val + 1 by omega, pow_succ]
      linear_combination (hdiv + ht') * (radix : ℤ) ^ (i.val + j.val)
    · intro q hq hqi
      rw [htail q hq hqi]
      change (p.val.set ij.val (UScalar.cast .U64 t))[q]'_ = _
      rw [List.getElem_set_ne (by omega)]

theorem mul2_outer_exact (k d : Array U64 2#usize) (p : Array U64 4#usize)
    (i : Usize) (hi : i.val ≤ 2)
    (hz : ∀ q (hq : q < 4), i.val + 2 ≤ q →
      p.val[q]'(by rw [p.property]; exact hq) = 0#u64) :
    ∃ out : Array U64 4#usize,
      glv.signed_difference_loop0 k d p i = ok out ∧
      value out = value p + mul2_tail k i.val * mul2_tail d 0 * (radix : ℤ) ^ i.val := by
  induction hn : 2 - i.val generalizing p i with
  | zero =>
    have hi2 : i.val = 2 := by omega
    have hige : ¬i < 2#usize := by change ¬i.val < 2; omega
    refine ⟨p, ?_, ?_⟩
    · rw [glv.signed_difference_loop0, loop.eq_1]
      simp [glv.signed_difference_loop0.body, hige]
    · rw [hi2, mul2_tail_two]
      ring
  | succ n ih =>
    have hilt : i.val < 2 := by omega
    obtain ⟨row, carry, hinner, hc, heq, htail⟩ :=
      mul2_inner_exact k d p i 0#usize 0#u128 hilt (by decide) (by decide)
    let last : Usize := UScalar.ofNatCore (i.val + 2)
      (lt_of_lt_of_le (by omega : i.val + 2 < 2 ^ 32) two_pow_32_le_usize)
    let next : Usize := UScalar.ofNatCore (i.val + 1)
      (lt_of_lt_of_le (by omega : i.val + 1 < 2 ^ 32) two_pow_32_le_usize)
    have hlast : last.val = i.val + 2 := rfl
    have hnext : next.val = i.val + 1 := rfl
    let p' := row.set last (UScalar.cast .U64 carry)
    have hpz : row.val[last.val]'(by rw [row.property]; change last.val < 4; omega) = 0#u64 := by
      rw [htail last.val (by omega) (by omega)]
      exact hz last.val (by omega) (by omega)
    have hp' : value p' = value p +
        (k.val[i.val]'(by rw [k.property]; exact hilt)).val * mul2_tail d 0 * (radix : ℤ) ^ i.val := by
      rw [value_set row last _ (by change last.val < 4; omega), hpz, cast64_val,
        Nat.mod_eq_of_lt hc]
      simp only [hlast]
      simp only [show (0#usize).val = 0 from rfl, show (0#u128).val = 0 from rfl,
        show (0#u64).val = 0 from rfl, Nat.cast_zero, add_zero, sub_zero] at heq ⊢
      exact heq
    have hz' : ∀ q (hq : q < 4), next.val + 2 ≤ q →
        p'.val[q]'(by rw [p'.property]; exact hq) = 0#u64 := by
      intro q hq hqi
      change (row.val.set last.val (UScalar.cast .U64 carry))[q]'_ = _
      rw [List.getElem_set_ne (by omega), htail q hq (by omega)]
      exact hz q hq (by omega)
    obtain ⟨out, hloop, hout⟩ := ih p' next (by omega) hz' (by omega)
    refine ⟨out, ?_, ?_⟩
    · rw [glv.signed_difference_loop0, loop.eq_1]
      have hbody : glv.signed_difference_loop0.body k d p i = ok (cont (p', next)) := by
        simp only [glv.signed_difference_loop0.body, show i < 2#usize from hilt,
          if_true, hinner, bind_tc_ok]
        rw [usize_add_ok i 2#usize (by change i.val + 2 < 2 ^ 32; omega)]
        simp only [bind_tc_ok, lift]
        change (do
          let a ← Array.update row last (UScalar.cast .U64 carry)
          let i3 ← i + 1#usize
          ok (cont (a, i3))) = _
        rw [update_eq row last _ (by change last.val < 4; omega)]
        simp only [bind_tc_ok]
        rw [usize_add_ok i 1#usize (by change i.val + 1 < 2 ^ 32; omega)]
        rfl
      simpa only [hbody] using hloop
    · rw [hout, hp', hnext, mul2_tail_step k i.val hilt, pow_succ]
      ring

theorem mul2_refines (c d : Array U64 2#usize) :
    ∃ cd : Array U64 4#usize,
      glv.signed_difference_loop0 c d (Array.repeat 4#usize 0#u64) 0#usize = ok cd ∧
      value cd = value c * value d := by
  obtain ⟨cd, hp, hv⟩ := mul2_outer_exact c d (Array.repeat 4#usize 0#u64) 0#usize
    (by decide) (by
      intro q hq _
      change (List.replicate 4 (0#u64))[q]'_ = _
      simp only [List.getElem_replicate])
  refine ⟨cd, hp, ?_⟩
  simpa [mul2_tail, value, Array.repeat, wordsValue] using hv

end LeanBlsSimd.GlvRefines

namespace LeanBlsSimd.GlvRefines
open silver_crypto_simd.bls.msm8
def finishHalf (magnitude : Array U64 4#usize) (negative : Bool) : Result glv.Half := do
  let i ← Array.index_usize magnitude 2#usize
  massert (i = 0#u64)
  let i1 ← Array.index_usize magnitude 3#usize
  massert (i1 = 0#u64)
  let i2 ← Array.index_usize magnitude 1#usize
  let i3 ← i2 >>> 63#i32
  massert (i3 = 0#u64)
  ok { magnitude, negative }

theorem finishHalf_ok (m : Array U64 4#usize) (negative : Bool) (hm : value m < 2 ^ 127) :
    finishHalf m negative = ok ⟨m, negative⟩ := by
  rcases m with ⟨xs, hxs⟩
  obtain ⟨a, b, c, d, rfl⟩ := List.length_eq_four.mp hxs
  have hc : c = 0#u64 := by
    apply UScalar.eq_of_val_eq
    norm_num [value, wordsValue, radix] at hm
    change c.val = 0
    omega
  have hd : d = 0#u64 := by
    apply UScalar.eq_of_val_eq
    norm_num [value, wordsValue, radix] at hm
    change d.val = 0
    omega
  have hb : b.val < 2 ^ 63 := by
    norm_num [value, wordsValue, radix] at hm ⊢
    omega
  have hshift : b >>> 63#i32 = ok 0#u64 := by
    rw [show b >>> 63#i32 = ok (⟨b.bv.ushiftRight 63⟩ : U64) from rfl]
    congr 1
    apply UScalar.eq_of_val_eq
    rw [shift63_val, Nat.div_eq_of_lt hb]
    rfl
  subst hc hd
  simp only [finishHalf]
  rw [index_usize_eq _ 2#usize (by decide), index_usize_eq _ 3#usize (by decide),
    index_usize_eq _ 1#usize (by decide)]
  change (do
    massert ((0#u64) = 0#u64)
    massert ((0#u64) = 0#u64)
    let b' ← b >>> 63#i32
    massert (b' = 0#u64)
    ok _) = _
  simp only [hshift, massert, if_true, bind_tc_ok]

def signedValue (h : glv.Half) : ℤ := if h.negative then -value h.magnitude else value h.magnitude

theorem signed_difference_refines (a : Array U64 4#usize) (b : U64) (c d : Array U64 2#usize)
    (hbound : |value a - (b.val : ℤ) - value c * value d| < 2 ^ 127) :
    ∃ h : glv.Half, glv.signed_difference a b c d = ok h ∧
      signedValue h = value a - (b.val : ℤ) - value c * value d ∧ value h.magnitude < 2 ^ 127 := by
  obtain ⟨cd, hcd, hcdv⟩ := mul2_refines c d
  let sub := Array.make 4#usize [b, 0#u64, 0#u64, 0#u64] (by rfl)
  obtain ⟨out, borrow, hsub, hborrow, hval⟩ := subtract_refines a cd sub
  have hsv : value sub = b.val := by
    change wordsValue [b, 0#u64, 0#u64, 0#u64] = b.val
    simp [wordsValue]
  rw [hsv, hcdv] at hval
  have hout := value_bounds out
  have hsmall := abs_lt.mp hbound
  by_cases hb0 : borrow = 0#u64
  · have heq : value out = value a - (b.val : ℤ) - value c * value d := by
      simpa only [hb0, show (0#u64).val = 0 from rfl, Nat.cast_zero, zero_mul, sub_zero] using hval
    have hsize : value out < 2 ^ 127 := by omega
    refine ⟨⟨out, false⟩, ?_, ?_, hsize⟩
    · rw [glv.signed_difference, hcd]
      simp only [bind_tc_ok]
      rw [hsub]
      simp only [bind_tc_ok]
      change ((if borrow != 0#u64 then
          (glv.negated out >>= fun magnitude => ok (true, magnitude))
        else ok (false, out)) >>= fun (negative, magnitude) => finishHalf magnitude negative) = _
      simp only [hb0, bne_self_eq_false, Bool.false_eq_true, if_false, bind_tc_ok]
      exact finishHalf_ok out false hsize
    · exact heq
  · have hbval : borrow.val ≠ 0 := by
      intro h
      apply hb0
      exact UScalar.eq_of_val_eq h
    have hneg : value a - (b.val : ℤ) - value c * value d < 0 := by
      norm_num [radix] at hout
      omega
    obtain ⟨mag, hmag, hmagv⟩ := negated_refines out
    have hmagval : value mag = -(value a - (b.val : ℤ) - value c * value d) := by
      rw [hmagv]
      norm_num [radix] at hout
      omega
    have hsize : value mag < 2 ^ 127 := by omega
    refine ⟨⟨mag, true⟩, ?_, ?_, hsize⟩
    · rw [glv.signed_difference, hcd]
      simp only [bind_tc_ok]
      rw [hsub]
      simp only [bind_tc_ok]
      change ((if borrow != 0#u64 then
          (glv.negated out >>= fun magnitude => ok (true, magnitude))
        else ok (false, out)) >>= fun (negative, magnitude) => finishHalf magnitude negative) = _
      simp only [bne_iff_ne, if_pos hb0]
      rw [hmag]
      change finishHalf mag true = _
      exact finishHalf_ok mag true hsize
    · change -value mag = _
      rw [hmagval, neg_neg]

end LeanBlsSimd.GlvRefines


namespace LeanBlsSimd.GlvRefines
open silver_crypto_simd.bls.msm8
theorem lambda_value : value glv.LAMBDA = Glv.lambda := by decide +kernel

theorem z2_value : value glv.Z2 = Glv.zSquared := by decide +kernel

def extendTwo (a : Array U64 2#usize) : Array U64 4#usize :=
  Array.make 4#usize [a.val[0], a.val[1], 0#u64, 0#u64] (by rfl)

theorem extendTwo_value (a : Array U64 2#usize) : value (extendTwo a) = value a := by
  rcases a with ⟨xs, hxs⟩
  obtain ⟨a, b, rfl⟩ := List.length_eq_two.mp hxs
  change wordsValue [a, b, 0#u64, 0#u64] = wordsValue [a, b]
  simp [wordsValue]

theorem boolCast_value (b : Bool) : (UScalar.cast_fromBool .U64 b).val = if b then 1 else 0 := by
  cases b <;> rfl

theorem decompose_refines (k : Array U64 4#usize) (hk : value k < 2 ^ 255) :
    ∃ h1 h2 : glv.Half, glv.decompose k = ok (h1, h2) ∧
      signedValue h1 = Glv.first (value k) ∧ signedValue h2 = Glv.second (value k) ∧
      value h1.magnitude < 2 ^ 127 ∧ value h2.magnitude < 2 ^ 127 := by
  obtain ⟨product, c1, hprod, hprefix, hc1⟩ := rounded_c1_refines k hk
  have hc1' : value c1 = Glv.c1 (value k) := hc1
  let b := UScalar.cast_fromBool .U64 (decide (Glv.halfModulusUp ≤ value k))
  have hb : (b.val : ℤ) = Glv.c2 (value k) := by
    simp only [b, boolCast_value, Glv.c2]
    split_ifs <;> simp_all
  have hk0 := (value_bounds k).1
  obtain ⟨hfirst, hsecond⟩ := Glv.halves_bounded (value k) hk0 hk
  have hf : value k - (b.val : ℤ) - value c1 * value glv.LAMBDA = Glv.first (value k) := by
    rw [hb, hc1', lambda_value]
    rfl
  obtain ⟨h1, hh1, hv1, hm1⟩ := signed_difference_refines k b c1 glv.LAMBDA (hf ▸ hfirst)
  let bwords := Array.make 2#usize [b, 0#u64] (by rfl)
  have hbwords : value bwords = b.val := by
    change wordsValue [b, 0#u64] = b.val
    simp [wordsValue]
  have hs : value (extendTwo c1) - ((0#u64).val : ℤ) - value bwords * value glv.Z2 =
      Glv.second (value k) := by
    rw [extendTwo_value, hc1', hbwords, hb, z2_value]
    change Glv.c1 (value k) - 0 - Glv.c2 (value k) * Glv.zSquared = _
    simp only [sub_zero, Glv.second]
  obtain ⟨h2, hh2, hv2, hm2⟩ := signed_difference_refines (extendTwo c1) 0#u64 bwords glv.Z2 (hs ▸ hsecond)
  refine ⟨h1, h2, ?_, hv1.trans hf, hv2.trans hs, hm1, hm2⟩
  rw [decompose_prefix, hprod]
  simp only [bind_tc_ok, hprefix, at_least_half_r_refines, lift]
  change (do
    let h1 ← glv.signed_difference k b c1 glv.LAMBDA
    let i10 ← Array.index_usize c1 0#usize
    let i11 ← Array.index_usize c1 1#usize
    let h2 ← glv.signed_difference (Array.make 4#usize [i10, i11, 0#u64, 0#u64] (by rfl)) 0#u64 bwords glv.Z2
    ok (h1, h2)) = _
  rw [hh1]
  simp only [bind_tc_ok]
  rw [index_usize_eq c1 0#usize (by decide), index_usize_eq c1 1#usize (by decide)]
  simp only [bind_tc_ok]
  change (do let h2 ← glv.signed_difference (extendTwo c1) 0#u64 bwords glv.Z2; ok (h1, h2)) = _
  rw [hh2]
  rfl

end LeanBlsSimd.GlvRefines
