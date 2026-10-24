import LeanBlsSimd.LaneTower.SquareRecombine

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls
open EthLib.Cryptography Bls

namespace LeanBlsSimd.LaneTower

def squareFirst : Array I64 8#usize := Array.make 8#usize
  [13#i64, 3#i64, 4#i64, 13#i64, 13#i64, 3#i64, 6#i64, 6#i64] (by rfl)

def squareSecond : Array I64 8#usize := Array.make 8#usize
  [fp12.Z, fp12.Z, fp12.Z, 3#i64, 4#i64, 4#i64, fp12.Z, fp12.Z] (by rfl)

def squareV1 (a : P F) : P F :=
  add2 (shuffle2 squareFirst a (xi2 a))
    (shuffle2 squareSecond a (fun _ => 0, fun _ => 0))

def joinRows {α : Type} (a b : Fin 3 → α) : Fin 6 → α :=
  ![a 0, a 1, a 2, b 0, b 1, b 2]

def joinArrays (a b : Array fp8.Fp8 3#usize) : Array fp8.Fp8 6#usize :=
  Array.make 6#usize [a.val[0], a.val[1], a.val[2], b.val[0], b.val[1], b.val[2]] (by rfl)

theorem join_rows {k m : ℕ} {x y : Array fp8.Fp8 3#usize} {a b : Fin 3 → V F}
    (hx : RowsRaw k m x a) (hy : RowsRaw k m y b) :
    RowsRaw k m (joinArrays x y) (joinRows a b) := by
  intro j
  fin_cases j
  · simpa [joinArrays, joinRows, ofArray, Array.make] using hx ⟨0, by decide⟩
  · simpa [joinArrays, joinRows, ofArray, Array.make] using hx ⟨1, by decide⟩
  · simpa [joinArrays, joinRows, ofArray, Array.make] using hx ⟨2, by decide⟩
  · simpa [joinArrays, joinRows, ofArray, Array.make] using hy ⟨0, by decide⟩
  · simpa [joinArrays, joinRows, ofArray, Array.make] using hy ⟨1, by decide⟩
  · simpa [joinArrays, joinRows, ofArray, Array.make] using hy ⟨2, by decide⟩

def squareLeft (a : P F) : Fin 6 → V F :=
  joinRows (operands (kara2 0 a)) (operands (add2 (kara2 0 a) (kara2 1 a)))

def squareRight (a : P F) : Fin 6 → V F :=
  joinRows (operands (kara2 1 a)) (operands (add2 (kara2 0 a) (squareV1 a)))

def squareValues (a : P F) : P F :=
  squareRecombine (unpack6 (fun j l => pack6 (squareLeft a) j l * pack6 (squareRight a) j l))

theorem square_raw {x : fp2x8.Fp2x8} {a : P F}
    (hx : Normal2 (fun _ => 256, fun _ => 256) x a) :
    ∃ out, fp12.Fp12.square x = ok out ∧
      Normal2 (fun _ => 112, fun _ => 112) out (squareValues a) := by
  obtain ⟨z, hz, rz⟩ := raw2_zero
  obtain ⟨p, hp, rp⟩ := raw_offset 256#u64 (by decide)
  obtain ⟨xi, hxi, rxi⟩ := raw2_xi hx.raw rp (by intro l; rfl) (by decide)
  obtain ⟨k0, hk0, rk0⟩ := karatsuba_lanes 0 hx.raw (by decide)
  obtain ⟨k1, hk1, rk1⟩ := karatsuba_lanes 1 hx.raw (by decide)
  obtain ⟨v0, hv0, rv0⟩ := raw2_permute2 squareFirst hx.raw rxi
  obtain ⟨v1, hv1, rv1⟩ := raw2_permute2 squareSecond hx.raw rz.raw
  obtain ⟨kv, hkv, rkv⟩ := raw2_add rv0 rv1 (by decide)
  have rv : Raw2 (fun _ => 768, fun _ => 768) 4 kv (squareV1 a) :=
    rkv.mono (by intro l; fin_cases l <;> decide +kernel) (by decide)
  obtain ⟨ls, hls, rls⟩ := raw2_add rk0 rk1 (by decide)
  obtain ⟨rs, hrs, rrs⟩ := raw2_add rk0 rv (by decide)
  have rlt : Raw2 (fun _ => 1024, fun _ => 1024) 4 k0 (kara2 0 a) :=
    rk0.mono (by intro l; dsimp; decide) (by decide)
  have rls' : Raw2 (fun _ => 1024, fun _ => 1024) 4 ls (add2 (kara2 0 a) (kara2 1 a)) := rls
  have rrt : Raw2 (fun _ => 1280, fun _ => 1280) 6 k1 (kara2 1 a) :=
    rk1.mono (by intro l; dsimp; decide) (by decide)
  have rrs' : Raw2 (fun _ => 1280, fun _ => 1280) 6 rs (add2 (kara2 0 a) (squareV1 a)) := rrs
  obtain ⟨lt, hlt, rlt⟩ := fp2_operands rlt (by decide)
  obtain ⟨ls', hls', rls⟩ := fp2_operands rls' (by decide)
  obtain ⟨rt, hrt, rrt⟩ := fp2_operands rrt (by decide)
  obtain ⟨rs', hrs', rrs⟩ := fp2_operands rrs' (by decide)
  obtain ⟨left, hleft, rleft⟩ := pack_six (join_rows rlt rls) (by decide) (by decide)
  obtain ⟨right, hright, rright⟩ := pack_six (join_rows rrt rrs) (by decide) (by decide)
  obtain ⟨z0, hz0, _⟩ := raw_zero
  obtain ⟨q, hq, rq⟩ := product_loop_start rleft rright (by decide) (Array.repeat 5#usize z0)
  obtain ⟨out, hout, rout⟩ := from_square_lanes rq
  refine ⟨out, ?_, rout⟩
  simp only [baseWord, Matrix.cons_val] at hk0 hk1
  dsimp only [squareFirst, squareSecond] at hv0 hv1
  dsimp only [joinArrays] at hleft hright
  simp only [fp12.Fp12.square, fp12.BOUND, hz, hp, hxi, hk0, hk1, hv0, hv1, hkv,
    hls, hrs, hlt, hls', hrt, hrs', hz0, square_loop_eq,
    index_usize_eq lt 0#usize (by decide), index_usize_eq lt 1#usize (by decide),
    index_usize_eq lt 2#usize (by decide), index_usize_eq ls' 0#usize (by decide),
    index_usize_eq ls' 1#usize (by decide), index_usize_eq ls' 2#usize (by decide),
    index_usize_eq rt 0#usize (by decide), index_usize_eq rt 1#usize (by decide),
    index_usize_eq rt 2#usize (by decide), index_usize_eq rs' 0#usize (by decide),
    index_usize_eq rs' 1#usize (by decide), index_usize_eq rs' 2#usize (by decide),
    UScalar.ofNatCore_val_eq, hleft, hright, hq, hout, bind_tc_ok]



theorem shuffle_squareFirst {α : Type} (a b : V α) :
    shuffle squareFirst a b = ![b 5, a 3, a 4, b 5, b 5, a 3, a 6, a 6] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_squareSecond {α : Type} [Zero α] (a : V α) :
    shuffle squareSecond a (fun _ => 0) = ![0, 0, 0, a 3, a 4, a 4, 0, 0] := by
  unfold squareSecond fp12.Z
  funext l
  fin_cases l <;> rfl

set_option maxHeartbeats 2000000 in
set_option maxRecDepth 4096 in
theorem square_value (a : P F) : value (squareValues a) = (value a).mul (value a) := by
  rw [← product_value a a]
  have s0 (j : Fin 6) := unpack6_products (squareLeft a) (squareRight a) j 0 (by decide)
  have s1 (j : Fin 6) := unpack6_products (squareLeft a) (squareRight a) j 1 (by decide)
  have s2 (j : Fin 6) := unpack6_products (squareLeft a) (squareRight a) j 2 (by decide)
  have s3 (j : Fin 6) := unpack6_products (squareLeft a) (squareRight a) j 3 (by decide)
  have s4 (j : Fin 6) := unpack6_products (squareLeft a) (squareRight a) j 4 (by decide)
  have s5 (j : Fin 6) := unpack6_products (squareLeft a) (squareRight a) j 5 (by decide)
  have p0 (j : Fin 9) := unpack9_products (productInputs a) (productInputs a) j 0 (by decide)
  have p1 (j : Fin 9) := unpack9_products (productInputs a) (productInputs a) j 1 (by decide)
  have p2 (j : Fin 9) := unpack9_products (productInputs a) (productInputs a) j 2 (by decide)
  have p3 (j : Fin 9) := unpack9_products (productInputs a) (productInputs a) j 3 (by decide)
  have p4 (j : Fin 9) := unpack9_products (productInputs a) (productInputs a) j 4 (by decide)
  have p5 (j : Fin 9) := unpack9_products (productInputs a) (productInputs a) j 5 (by decide)
  apply fp12_ext <;> apply fp6_ext <;> apply fp2_ext
  all_goals
    change (_ : F) = _
    simp only [value, squareValues, productValues, squareRecombine, productRecombine,
      fromTriple, xi2, clear2_eq, slices, add2, sub2, shuffle2,
      shuffle_Z0_POS_0, shuffle_Z0_POS_1, shuffle_Z0_NEG_0, shuffle_Z0_NEG_1,
      shuffle_V_Z0_POS_0, shuffle_V_Z0_POS_1, shuffle_V_Z0_NEG_0, shuffle_V_Z0_NEG_1,
      shuffle_Z3_POS_0, shuffle_Z3_POS_1, shuffle_Z3_NEG_0, shuffle_Z3_NEG_1,
      Matrix.cons_val, zero_add, add_zero]
    simp only [s0, s1, s2, s3, s4, s5, p0, p1, p2, p3, p4, p5]
    simp only [squareLeft, squareRight, joinRows, productInputs, operands, kara2,
      squareV1, xi2, add2, shuffle2, shuffle_squareFirst, shuffle_squareSecond,
      shuffle_karaFirst_0, shuffle_karaFirst_1, shuffle_karaSecond_0, shuffle_karaSecond_1,
      Matrix.cons_val, add_zero]
    ring

theorem square_refines {x : fp2x8.Fp2x8} {a : Bls.Fp12} (hx : Rep x a) :
    ∃ out, fp12.Fp12.square x = ok out ∧ Rep out a.square := by
  obtain ⟨v, h0, h1, rfl⟩ := hx
  obtain ⟨out, hout, rout⟩ := square_raw ⟨fun l => (h0 l).capped, fun l => (h1 l).capped⟩
  exact ⟨out, hout, squareValues v,
    fun l => (rout.1 l).boundRep (by change 112 < 256; decide),
    fun l => (rout.2 l).boundRep (by change 112 < 256; decide), square_value v⟩

end LeanBlsSimd.LaneTower
