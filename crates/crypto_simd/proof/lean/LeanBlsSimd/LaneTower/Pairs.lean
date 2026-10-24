import LeanBlsSimd.LaneTower.Vectors

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.LaneTower

abbrev P (α : Type) := V α × V α

def Raw2 (k : P ℕ) (m : ℕ) (x : fp2x8.Fp2x8) (a : P F) : Prop :=
  Raw k.1 m x.c0 a.1 ∧ Raw k.2 m x.c1 a.2

def Normal2 (k : P ℕ) (x : fp2x8.Fp2x8) (a : P F) : Prop :=
  Normal k.1 x.c0 a.1 ∧ Normal k.2 x.c1 a.2

def add2 {α : Type} [Add α] (a b : P α) : P α :=
  (fun l => a.1 l + b.1 l, fun l => a.2 l + b.2 l)

def sub2 (a b : P F) : P F :=
  (fun l => a.1 l - b.1 l, fun l => a.2 l - b.2 l)

def mul2 (a b : P F) : P F :=
  (fun l => a.1 l * b.1 l - a.2 l * b.2 l,
   fun l => a.1 l * b.2 l + a.2 l * b.1 l)

def select2 {α : Type} (mask : U8) (a b : P α) : P α :=
  (select mask a.1 b.1, select mask a.2 b.2)

def shuffle2 {α : Type} (is : Array I64 8#usize) (a b : P α) : P α :=
  (shuffle is a.1 b.1, shuffle is a.2 b.2)

variable {k k' : P ℕ} {m m' : ℕ} {x y : fp2x8.Fp2x8} {a b : P F}

theorem Normal2.raw (h : Normal2 k x a) : Raw2 k 1 x a := ⟨h.1.raw, h.2.raw⟩

theorem raw2_zero : ∃ out, fp12.zero2 = ok out ∧
    Normal2 (fun _ => 0, fun _ => 0) out (fun _ => 0, fun _ => 0) := by
  obtain ⟨z, hz, hr⟩ := raw_zero
  refine ⟨⟨z, z⟩, ?_, hr, hr⟩
  simp only [fp12.zero2, hz, bind_tc_ok]

theorem raw2_add (hx : Raw2 k m x a) (hy : Raw2 k' m' y b) (hm : m + m' ≤ 1024) :
    ∃ out, fp2x8.Fp2x8.add_raw x y = ok out ∧
      Raw2 (add2 k k') (m + m') out (add2 a b) := by
  obtain ⟨o0, h0, r0⟩ := raw_add hx.1 hy.1 hm
  obtain ⟨o1, h1, r1⟩ := raw_add hx.2 hy.2 hm
  refine ⟨⟨o0, o1⟩, ?_, r0, r1⟩
  simp only [fp2x8.Fp2x8.add_raw, h0, h1, bind_tc_ok]

theorem raw2_sub {c : ℕ} {o : fp8.Fp8} (hx : Raw2 k m x a) (hy : Raw2 k' m' y b)
    (ho : offset c o) (hc : ∀ l, k'.1 l ≤ c ∧ k'.2 l ≤ c) (hm : m + m' + 1 ≤ 1024) :
    ∃ out, fp2x8.Fp2x8.sub_raw x y o = ok out ∧
      Raw2 (fun l => k.1 l + c, fun l => k.2 l + c) (m + m' + 1) out (sub2 a b) := by
  obtain ⟨o0, h0, r0⟩ := raw_sub hx.1 hy.1 ho (fun l => (hc l).1) hm
  obtain ⟨o1, h1, r1⟩ := raw_sub hx.2 hy.2 ho (fun l => (hc l).2) hm
  refine ⟨⟨o0, o1⟩, ?_, r0, r1⟩
  simp only [fp2x8.Fp2x8.sub_raw, h0, h1, bind_tc_ok]

theorem raw2_normalise (hx : Raw2 k m x a) (hk : ∀ l, k.1 l ≤ 5120 ∧ k.2 l ≤ 5120)
    (hm : m ≤ 1024) : ∃ out, fp2x8.Fp2x8.normalise x = ok out ∧ Normal2 k out a := by
  obtain ⟨o0, h0, r0⟩ := raw_normalise hx.1 (fun l => (hk l).1) hm
  obtain ⟨o1, h1, r1⟩ := raw_normalise hx.2 (fun l => (hk l).2) hm
  refine ⟨⟨o0, o1⟩, ?_, r0, r1⟩
  simp only [fp2x8.Fp2x8.normalise, h0, h1, bind_tc_ok]

theorem raw2_select (mask : U8) (hx : Raw2 k m x a) (hy : Raw2 k' m' y b) :
    ∃ out, fp2x8.Fp2x8.select mask x y = ok out ∧
      Raw2 (select2 mask k k') (max m m') out (select2 mask a b) := by
  obtain ⟨o0, h0, r0⟩ := raw_select mask hx.1 hy.1
  obtain ⟨o1, h1, r1⟩ := raw_select mask hx.2 hy.2
  refine ⟨⟨o0, o1⟩, ?_, r0, r1⟩
  simp only [fp2x8.Fp2x8.select, h0, h1, bind_tc_ok]

theorem raw2_permute2 (is : Array I64 8#usize) (hx : Raw2 k m x a) (hy : Raw2 k' m' y b) :
    ∃ out, fp2x8.Fp2x8.permute2 x y is = ok out ∧
      Raw2 (shuffle2 is k k') (max m m') out (shuffle2 is a b) := by
  obtain ⟨o0, h0, r0⟩ := raw_permute2 is hx.1 hy.1
  obtain ⟨o1, h1, r1⟩ := raw_permute2 is hx.2 hy.2
  refine ⟨⟨o0, o1⟩, ?_, r0, r1⟩
  simp only [fp2x8.Fp2x8.permute2, h0, h1, bind_tc_ok]

theorem raw2_xi {c : ℕ} {o : fp8.Fp8} (hx : Raw2 k m x a)
    (ho : offset c o) (hc : ∀ l, k.2 l ≤ c) (hm : m + m + 1 ≤ 1024) :
    ∃ out, fp2x8.Fp2x8.mul_by_xi_raw x o = ok out ∧
      Raw2 (fun l => k.1 l + c, fun l => k.1 l + k.2 l) (m + m + 1) out
        (fun l => a.1 l - a.2 l, fun l => a.1 l + a.2 l) := by
  obtain ⟨o0, h0, r0⟩ := raw_sub hx.1 hx.2 ho hc hm
  obtain ⟨o1, h1, r1⟩ := raw_add hx.1 hx.2 (by omega)
  refine ⟨⟨o0, o1⟩, ?_, r0, ?_⟩
  · simp only [fp2x8.Fp2x8.mul_by_xi_raw, h0, h1, bind_tc_ok]
  · exact fun l => (r1 l).mono le_rfl (by omega)

theorem raw_from_products (c : U64) (hc : c.val < 2048) {m : ℕ}
    {x0 x1 x2 : fp8.Fp8} {a0 a1 a2 : V F}
    (h0 : Raw (fun _ => c.val) m x0 a0) (h1 : Raw (fun _ => c.val) m x1 a1)
    (h2 : Raw (fun _ => c.val) m x2 a2) (hm : 3 * m + 1 ≤ 1024) :
    ∃ out, fp12.fp2_from_products x0 x1 x2 c = ok out ∧
      Raw2 (fun _ => 2 * c.val, fun _ => 3 * c.val) (3 * m + 1) out
        (fun l => a0 l - a1 l, fun l => a2 l - (a0 l + a1 l)) := by
  obtain ⟨o, ho, ro⟩ := raw_offset c (by omega)
  obtain ⟨re, hre, rre⟩ := raw_sub h0 h1 ro (by intro l; rfl) (by omega)
  obtain ⟨sum, hsum, rsum⟩ := raw_add h0 h1 (by omega)
  let c2 : U64 := UScalar.ofNatCore (2 * c.val) (by scalar_tac)
  have hc2 : c2.val = 2 * c.val := rfl
  have hmul : 2#u64 * c = ok c2 := mul_ok _ _ (by scalar_tac)
  obtain ⟨o2, ho2, ro2⟩ := raw_offset c2 (by omega)
  obtain ⟨im, him, rim⟩ := raw_sub h2 rsum ro2 (by intro l; simp only [hc2]; omega) (by omega)
  refine ⟨⟨re, im⟩, ?_, ?_, ?_⟩
  · simp only [fp12.fp2_from_products, ho, hre, hsum, hmul, ho2, him, bind_tc_ok]
  · intro l
    exact (rre l).mono (by dsimp; omega) (by omega)
  · intro l
    exact (rim l).mono (by dsimp; omega) (by omega)

theorem raw2_products (hx : Normal2 k x a) (hy : Normal2 k' y b)
    (hk : ∀ l, k.1 l + k.2 l ≤ 5120 ∧ k'.1 l + k'.2 l ≤ 5120)
    (hp : ∀ l, (k.1 l + k.2 l) * (k'.1 l + k'.2 l) ≤ 80 * 256 ^ 2) :
    ∃ out, fp12.fp2_products x y = ok out ∧ Normal2 (fun _ => 4, fun _ => 6) out (mul2 a b) := by
  obtain ⟨m0, hm0, rm0⟩ := raw_mul hx.1 hy.1 (by
    intro l
    exact (Nat.mul_le_mul (Nat.le_add_right _ _) (Nat.le_add_right _ _)).trans (hp l))
  obtain ⟨m1, hm1, rm1⟩ := raw_mul hx.2 hy.2 (by
    intro l
    exact (Nat.mul_le_mul (Nat.le_add_left _ _) (Nat.le_add_left _ _)).trans (hp l))
  obtain ⟨sx, hsx, rsx⟩ := raw_add hx.1.raw hx.2.raw (by decide)
  obtain ⟨nx, hnx, rnx⟩ := raw_normalise rsx (fun l => (hk l).1) (by decide)
  obtain ⟨sy, hsy, rsy⟩ := raw_add hy.1.raw hy.2.raw (by decide)
  obtain ⟨ny, hny, rny⟩ := raw_normalise rsy (fun l => (hk l).2) (by decide)
  obtain ⟨m2, hm2, rm2⟩ := raw_mul rnx rny hp
  obtain ⟨r, hr, rr⟩ := raw_from_products 2#u64 (by decide) rm0.raw rm1.raw rm2.raw (by decide)
  obtain ⟨out, hout, rout⟩ := raw2_normalise rr (by intro l; dsimp; decide) (by decide)
  refine ⟨out, ?_, ?_⟩
  · simp only [fp12.fp2_products, hm0, hm1, hsx, hnx, hsy, hny, hm2, hr, hout, bind_tc_ok]
  · have he : (fun l => a.1 l * b.1 l - a.2 l * b.2 l,
        fun l => (a.1 l + a.2 l) * (b.1 l + b.2 l) - (a.1 l * b.1 l + a.2 l * b.2 l)) =
        mul2 a b := by
      apply Prod.ext
      · rfl
      · funext l; dsimp [mul2]; ring
    simpa only [he] using rout

end LeanBlsSimd.LaneTower
