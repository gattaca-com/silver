import LeanBlsSimd.LaneTower.Products

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.LaneTower

theorem Raw2.mono {k k' : P ℕ} {m m' : ℕ} {x : fp2x8.Fp2x8} {a : P F}
    (hx : Raw2 k m x a) (hk : ∀ l, k.1 l ≤ k'.1 l ∧ k.2 l ≤ k'.2 l) (hm : m ≤ m') :
    Raw2 k' m' x a :=
  ⟨fun l => (hx.1 l).mono (hk l).1 hm, fun l => (hx.2 l).mono (hk l).2 hm⟩

def clear2 {α : Type} [Zero α] (a : P α) : P α :=
  select2 192#u8 a (fun _ => 0, fun _ => 0)

theorem raw2_clear {k : P ℕ} {m : ℕ} {x : fp2x8.Fp2x8} {a : P F} (hx : Raw2 k m x a) :
    ∃ out, fp12.clear_free_lanes x = ok out ∧ Raw2 (clear2 k) (max m 1) out (clear2 a) := by
  obtain ⟨z, hz, rz⟩ := raw2_zero
  obtain ⟨out, hout, rout⟩ := raw2_select 192#u8 hx rz.raw
  refine ⟨out, ?_, rout⟩
  simp only [fp12.clear_free_lanes, hz, hout, bind_tc_ok]

def slices {α : Type} [Add α] (is : Array (Array I64 8#usize) 2#usize) (acc a b : P α) : P α :=
  add2 (add2 acc (shuffle2 is.val[0] a b)) (shuffle2 is.val[1] a b)

theorem raw2_slices {k ka kb : P ℕ} {m ma mb : ℕ}
    {x y z : fp2x8.Fp2x8} {a b c : P F}
    (is : Array (Array I64 8#usize) 2#usize) (hx : Raw2 k m x a)
    (hy : Raw2 ka ma y b) (hz : Raw2 kb mb z c) (hm : m + 2 * max ma mb ≤ 1024) :
    ∃ out, fp12.add_slices x y z is = ok out ∧
      Raw2 (slices is k ka kb) (m + max ma mb + max ma mb) out (slices is a b c) := by
  obtain ⟨s0, hs0, rs0⟩ := raw2_permute2 is.val[0] hy hz
  obtain ⟨o0, ho0, ro0⟩ := raw2_add hx rs0 (by omega)
  obtain ⟨s1, hs1, rs1⟩ := raw2_permute2 is.val[1] hy hz
  obtain ⟨out, hout, rout⟩ := raw2_add ro0 rs1 (by omega)
  refine ⟨out, ?_, rout⟩
  simp only [fp12.add_slices, index_usize_eq is 0#usize (by decide),
    index_usize_eq is 1#usize (by decide), UScalar.ofNatCore_val_eq,
    hs0, ho0, hs1, hout, bind_tc_ok]

def baseWord (h : Fin 2) : I64 := ![0#i64, 3#i64] h

def karaFirst (h : Fin 2) : Array I64 8#usize :=
  ![Array.make (α := I64) 8#usize [0#i64, 1#i64, 2#i64, 0#i64, 0#i64, 1#i64, 8#i64, 8#i64] (by rfl),
    Array.make (α := I64) 8#usize [3#i64, 4#i64, 5#i64, 3#i64, 3#i64, 4#i64, 8#i64, 8#i64] (by rfl)] h

def karaSecond (h : Fin 2) : Array I64 8#usize :=
  ![Array.make (α := I64) 8#usize [8#i64, 8#i64, 8#i64, 1#i64, 2#i64, 2#i64, 8#i64, 8#i64] (by rfl),
    Array.make (α := I64) 8#usize [8#i64, 8#i64, 8#i64, 4#i64, 5#i64, 5#i64, 8#i64, 8#i64] (by rfl)] h

def kara2 (h : Fin 2) (a : P F) : P F :=
  add2 (shuffle2 (karaFirst h) a (fun _ => 0, fun _ => 0))
    (shuffle2 (karaSecond h) a (fun _ => 0, fun _ => 0))

theorem karatsuba_lanes {k m : ℕ} {x : fp2x8.Fp2x8} {a : P F}
    (h : Fin 2) (hx : Raw2 (fun _ => k, fun _ => k) m x a)
    (hm : 2 * max m 1 ≤ 1024) :
    ∃ out, fp12.karatsuba_lanes x (baseWord h) = ok out ∧
      Raw2 (fun _ => 2 * k, fun _ => 2 * k) (2 * max m 1) out (kara2 h a) := by
  obtain ⟨z, hz, rz⟩ := raw2_zero
  obtain ⟨first, hfirst, rfirst⟩ := raw2_permute2 (karaFirst h) hx rz.raw
  obtain ⟨second, hsecond, rsecond⟩ := raw2_permute2 (karaSecond h) hx rz.raw
  obtain ⟨out, hout, rout⟩ := raw2_add rfirst rsecond (by omega)
  refine ⟨out, ?_, rout.mono ?_ (by omega)⟩
  · have h1 : baseWord h + 1#i64 = ok (![1#i64, 4#i64] h) := by
      fin_cases h <;> rfl
    have h2 : baseWord h + 2#i64 = ok (![2#i64, 5#i64] h) := by
      fin_cases h <;> rfl
    have hf : Array.make 8#usize
        [baseWord h, ![1#i64, 4#i64] h, ![2#i64, 5#i64] h, baseWord h, baseWord h,
          ![1#i64, 4#i64] h, fp12.Z, fp12.Z] (by rfl) = karaFirst h := by
      fin_cases h <;> simp [baseWord, karaFirst, fp12.Z]
    have hs : Array.make 8#usize
        [fp12.Z, fp12.Z, fp12.Z, ![1#i64, 4#i64] h, ![2#i64, 5#i64] h,
          ![2#i64, 5#i64] h, fp12.Z, fp12.Z] (by rfl) = karaSecond h := by
      fin_cases h <;> simp [karaSecond, fp12.Z]
    simp only [fp12.karatsuba_lanes, hz, h1, h2, hf, hs, hfirst, hsecond, hout, bind_tc_ok]
  · intro l
    dsimp [add2, shuffle2, shuffle]
    constructor <;> split_ifs <;> omega

def operands (a : P F) : Fin 3 → V F := ![a.1, a.2, fun l => a.1 l + a.2 l]

theorem fp2_operands {k m : ℕ} {x : fp2x8.Fp2x8} {a : P F}
    (hx : Raw2 (fun _ => k, fun _ => k) m x a) (hm : 2 * m ≤ 1024) :
    ∃ out, fp12.fp2_operands x = ok out ∧ RowsRaw (2 * k) (2 * m) out (operands a) := by
  obtain ⟨s, hs, rs⟩ := raw_add hx.1 hx.2 (by omega)
  refine ⟨Array.make 3#usize [x.c0, x.c1, s] (by rfl), ?_, ?_⟩
  · simp only [fp12.fp2_operands, hs, bind_tc_ok]
  · intro j
    fin_cases j
    · intro l
      exact (hx.1 l).mono (by dsimp; omega) (by omega)
    · intro l
      exact (hx.2 l).mono (by dsimp; omega) (by omega)
    · intro l
      exact (rs l).mono (by dsimp; omega) (by omega)

def productInputs (a : P F) : Fin 9 → V F :=
  let k0 := operands (kara2 0 a)
  let k1 := operands (kara2 1 a)
  let k01 := operands (add2 (kara2 0 a) (kara2 1 a))
  ![k0 0, k0 1, k0 2, k1 0, k1 1, k1 2, k01 0, k01 1, k01 2]

theorem product_operands {k : ℕ} {x : fp2x8.Fp2x8} {a : P F}
    (hx : Normal2 (fun _ => k, fun _ => k) x a) (hk : k ≤ 256) :
    ∃ out, fp12.product_operands x = ok out ∧ RowsNormal (8 * k) out (pack9 (productInputs a)) := by
  obtain ⟨k0, hk0, rk0⟩ := karatsuba_lanes 0 hx.raw (by decide)
  obtain ⟨k1, hk1, rk1⟩ := karatsuba_lanes 1 hx.raw (by decide)
  obtain ⟨k01, hk01, rk01⟩ := raw2_add rk0 rk1 (by decide)
  have r0 : Raw2 (fun _ => 4 * k, fun _ => 4 * k) 4 k0 (kara2 0 a) :=
    rk0.mono (by intro l; dsimp; omega) (by decide)
  have r1 : Raw2 (fun _ => 4 * k, fun _ => 4 * k) 4 k1 (kara2 1 a) :=
    rk1.mono (by intro l; dsimp; omega) (by decide)
  have r01 : Raw2 (fun _ => 4 * k, fun _ => 4 * k) 4 k01 (add2 (kara2 0 a) (kara2 1 a)) :=
    rk01.mono (by intro l; dsimp [add2]; omega) (by decide)
  obtain ⟨l0, hl0, rl0⟩ := fp2_operands r0 (by decide)
  obtain ⟨l1, hl1, rl1⟩ := fp2_operands r1 (by decide)
  obtain ⟨l2, hl2, rl2⟩ := fp2_operands r01 (by decide)
  let rows : Array fp8.Fp8 9#usize := Array.make 9#usize
    [l0.val[0], l0.val[1], l0.val[2], l1.val[0], l1.val[1], l1.val[2],
      l2.val[0], l2.val[1], l2.val[2]] (by rfl)
  have hr : RowsRaw (8 * k) 8 rows (productInputs a) := by
    intro j
    fin_cases j
    · simpa [rows, ofArray, Array.make, productInputs, ← Nat.mul_assoc] using rl0 ⟨0, by decide⟩
    · simpa [rows, ofArray, Array.make, productInputs, ← Nat.mul_assoc] using rl0 ⟨1, by decide⟩
    · simpa [rows, ofArray, Array.make, productInputs, ← Nat.mul_assoc] using rl0 ⟨2, by decide⟩
    · simpa [rows, ofArray, Array.make, productInputs, ← Nat.mul_assoc] using rl1 ⟨0, by decide⟩
    · simpa [rows, ofArray, Array.make, productInputs, ← Nat.mul_assoc] using rl1 ⟨1, by decide⟩
    · simpa [rows, ofArray, Array.make, productInputs, ← Nat.mul_assoc] using rl1 ⟨2, by decide⟩
    · simpa [rows, ofArray, Array.make, productInputs, ← Nat.mul_assoc] using rl2 ⟨0, by decide⟩
    · simpa [rows, ofArray, Array.make, productInputs, ← Nat.mul_assoc] using rl2 ⟨1, by decide⟩
    · simpa [rows, ofArray, Array.make, productInputs, ← Nat.mul_assoc] using rl2 ⟨2, by decide⟩
  obtain ⟨out, hout, rout⟩ := pack_nine hr (by omega) (by decide)
  refine ⟨out, ?_, rout⟩
  simp only [baseWord, Matrix.cons_val_zero, Matrix.cons_val_one] at hk0 hk1
  simp only [fp12.product_operands, hk0, hk1, hk01, hl0, hl1, hl2, bind_tc_ok,
    index_usize_eq l0 0#usize (by decide), index_usize_eq l0 1#usize (by decide),
    index_usize_eq l0 2#usize (by decide), index_usize_eq l1 0#usize (by decide),
    index_usize_eq l1 1#usize (by decide), index_usize_eq l1 2#usize (by decide),
    index_usize_eq l2 0#usize (by decide), index_usize_eq l2 1#usize (by decide),
    index_usize_eq l2 2#usize (by decide), UScalar.ofNatCore_val_eq]
  exact hout

end LeanBlsSimd.LaneTower
