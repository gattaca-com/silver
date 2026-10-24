import LeanBlsSimd.LaneTower.Representation

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls
open EthLib.Cryptography Bls

namespace LeanBlsSimd.LaneTower

def Strict (k : ℕ) (x : fp8.Fp8) (a : V F) : Prop :=
  ∀ l, Fp8.BoundRep k (ofFp8 x) l (a l)

def Strict2 (k : ℕ) (x : fp2x8.Fp2x8) (a : P F) : Prop :=
  Strict k x.c0 a.1 ∧ Strict k x.c1 a.2

theorem Strict.normal {k : ℕ} {x : fp8.Fp8} {a : V F} (h : Strict k x a) :
    Normal (fun _ => k) x a := fun l => (h l).capped

theorem Strict2.normal {k : ℕ} {x : fp2x8.Fp2x8} {a : P F} (h : Strict2 k x a) :
    Normal2 (fun _ => k, fun _ => k) x a := ⟨h.1.normal, h.2.normal⟩

theorem normal_cond_sub {k c : ℕ} {x o : fp8.Fp8} {a : V F}
    (hx : Normal (fun _ => k) x a) (ho : offset c o) (hk : k < 2 * c) :
    ∃ out, fp8.Fp8.cond_sub x o = ok out ∧ Strict c out a := by
  refine ⟨_, Fp8.cond_sub_refines x o, ?_⟩
  intro l
  simpa only [ofFp8_toFp8] using ((hx l).boundRep hk).cond_sub (ho l) (by omega)

theorem normal2_cond_sub {k c : ℕ} {x : fp2x8.Fp2x8} {o : fp8.Fp8} {a : P F}
    (hx : Normal2 (fun _ => k, fun _ => k) x a) (ho : offset c o) (hk : k < 2 * c) :
    ∃ out, fp2x8.Fp2x8.cond_sub x o = ok out ∧ Strict2 c out a := by
  obtain ⟨x0, hx0, rx0⟩ := normal_cond_sub hx.1 ho hk
  obtain ⟨x1, hx1, rx1⟩ := normal_cond_sub hx.2 ho hk
  refine ⟨⟨x0, x1⟩, ?_, rx0, rx1⟩
  simp only [fp2x8.Fp2x8.cond_sub, hx0, hx1, bind_tc_ok]

theorem strict_select {k : ℕ} {x y : fp8.Fp8} {a b : V F} (mask : U8)
    (hx : Strict k x a) (hy : Strict k y b) :
    ∃ out, fp8.Fp8.select mask x y = ok out ∧ Strict k out (select mask a b) := by
  refine ⟨_, Fp8.select_refines mask x y, ?_⟩
  intro l
  simp only [ofFp8_toFp8, select]
  split_ifs with h
  · have he : (Fp8.select (ofU8 mask) (ofFp8 x) (ofFp8 y)).lane l = (ofFp8 y).lane l := by
      simp only [Fp8.lane_select, if_pos h]
    constructor <;> rw [he]
    exacts [(hy l).normal, (hy l).bound, (hy l).value]
  · have he : (Fp8.select (ofU8 mask) (ofFp8 x) (ofFp8 y)).lane l = (ofFp8 x).lane l := by
      simp only [Fp8.lane_select, if_neg h]
    constructor <;> rw [he]
    exacts [(hx l).normal, (hx l).bound, (hx l).value]

theorem strict2_select {k : ℕ} {x y : fp2x8.Fp2x8} {a b : P F} (mask : U8)
    (hx : Strict2 k x a) (hy : Strict2 k y b) :
    ∃ out, fp2x8.Fp2x8.select mask x y = ok out ∧ Strict2 k out (select2 mask a b) := by
  obtain ⟨x0, hx0, rx0⟩ := strict_select mask hx.1 hy.1
  obtain ⟨x1, hx1, rx1⟩ := strict_select mask hx.2 hy.2
  refine ⟨⟨x0, x1⟩, ?_, rx0, rx1⟩
  simp only [fp2x8.Fp2x8.select, hx0, hx1, bind_tc_ok]

def conjugateValues (a : P F) : P F :=
  select2 56#u8 a (sub2 (fun _ => 0, fun _ => 0) a)

theorem conjugate_raw {x : fp2x8.Fp2x8} {a : P F} (hx : Strict2 256 x a) :
    ∃ out, fp12.Fp12.conjugate x = ok out ∧ Strict2 256 out (conjugateValues a) := by
  obtain ⟨p, hp, rp⟩ := raw_offset 256#u64 (by decide)
  obtain ⟨z, hz, rz⟩ := raw2_zero
  obtain ⟨s, hs, rs⟩ := raw2_sub rz.raw hx.normal.raw rp (by intro l; exact ⟨le_rfl, le_rfl⟩) (by decide)
  obtain ⟨n, hn, rn⟩ := raw2_normalise rs (by intro l; dsimp; decide) (by decide)
  obtain ⟨neg, hneg, rneg⟩ := normal2_cond_sub (k := 256) rn rp (by decide)
  obtain ⟨out, hout, rout⟩ := strict2_select 56#u8 hx rneg
  refine ⟨out, ?_, rout⟩
  simp only [fp12.Fp12.conjugate, fp12.BOUND, hp, hz, hs, hn, hneg, hout, bind_tc_ok]

theorem conjugate_value (a : P F) : value (conjugateValues a) = (value a).conjugate := by
  apply fp12_ext <;> apply fp6_ext <;> apply fp2_ext
  all_goals rfl

theorem conjugate_refines {x : fp2x8.Fp2x8} {a : Bls.Fp12} (hx : Rep x a) :
    ∃ out, fp12.Fp12.conjugate x = ok out ∧ Rep out a.conjugate := by
  obtain ⟨v, h0, h1, rfl⟩ := hx
  obtain ⟨out, hout, rout⟩ := conjugate_raw ⟨h0, h1⟩
  exact ⟨out, hout, conjugateValues v, rout.1, rout.2, conjugate_value v⟩

theorem one_refines : ∃ out, fp12.Fp12.one = ok out ∧ Rep out Bls.Fp12.one := by
  obtain ⟨z, hz, rz⟩ := raw_zero
  obtain ⟨o, ho, ro⟩ := raw_one
  let is : Array I64 8#usize := Array.make 8#usize
    [8#i64, 0#i64, 0#i64, 0#i64, 0#i64, 0#i64, 0#i64, 0#i64] (by rfl)
  obtain ⟨r, hr, rr⟩ := normal_permute2 is rz ro
  refine ⟨⟨r, z⟩, ?_, (shuffle is (fun _ => 0) (fun _ => 1), fun _ => 0), ?_, ?_, ?_⟩
  · dsimp only [is] at hr
    simp only [fp12.Fp12.one, hz, ho, hr, bind_tc_ok]
  · intro l
    exact (rr l).boundRep (by fin_cases l <;> decide +kernel)
  · intro l
    exact (rz l).boundRep (by change 0 < 256; decide)
  · dsimp only [is]
    apply fp12_ext <;> apply fp6_ext <;> apply fp2_ext <;> decide +kernel

end LeanBlsSimd.LaneTower
