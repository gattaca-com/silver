import LeanBlsSimd.LaneTower.InversePower
import LeanBlsSimd.LaneTower.CyclotomicCoordinates

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls
open EthLib.Cryptography Bls

namespace LeanBlsSimd.LaneTower

theorem Normal.mono {k k' : V ℕ} {x : fp8.Fp8} {a : V F}
    (hx : Normal k x a) (hk : ∀ l, k l ≤ k' l) : Normal k' x a :=
  fun l => ⟨(hx l).normal, (hx l).bound.trans (Nat.mul_le_mul_right _ (hk l)), (hx l).value⟩

theorem Normal2.mono {k k' : P ℕ} {x : fp2x8.Fp2x8} {a : P F}
    (hx : Normal2 k x a) (hk : ∀ l, k.1 l ≤ k'.1 l ∧ k.2 l ≤ k'.2 l) : Normal2 k' x a :=
  ⟨hx.1.mono (fun l => (hk l).1), hx.2.mono (fun l => (hk l).2)⟩

theorem normal_permute {k : V ℕ} {x : fp8.Fp8} {a : V F}
    (is : Array I64 8#usize) (hx : Normal k x a) :
    ∃ out, fp8.Fp8.permute x is = ok out ∧ Normal (shuffle is k k) out (shuffle is a a) := by
  refine ⟨_, Fp8.permute_refines x is, ?_⟩
  intro l
  simp only [ofFp8_toFp8, shuffle]
  split_ifs <;> exact (hx _).of_lane_eq (by simp [Fp8.lane_permute, index])

theorem normal2_permute {k : P ℕ} {x : fp2x8.Fp2x8} {a : P F}
    (is : Array I64 8#usize) (hx : Normal2 k x a) :
    ∃ out, fp2x8.Fp2x8.permute x is = ok out ∧
      Normal2 (shuffle2 is k k) out (shuffle2 is a a) := by
  obtain ⟨r, hr, rr⟩ := normal_permute is hx.1
  obtain ⟨i, hi, ri⟩ := normal_permute is hx.2
  exact ⟨⟨r, i⟩, by simp only [fp2x8.Fp2x8.permute, hr, hi, bind_tc_ok], rr, ri⟩

theorem normal2_permute2 {k k' : P ℕ} {x y : fp2x8.Fp2x8} {a b : P F}
    (is : Array I64 8#usize) (hx : Normal2 k x a) (hy : Normal2 k' y b) :
    ∃ out, fp2x8.Fp2x8.permute2 x y is = ok out ∧
      Normal2 (shuffle2 is k k') out (shuffle2 is a b) := by
  obtain ⟨r, hr, rr⟩ := normal_permute2 is hx.1 hy.1
  obtain ⟨i, hi, ri⟩ := normal_permute2 is hx.2 hy.2
  exact ⟨⟨r, i⟩, by simp only [fp2x8.Fp2x8.permute2, hr, hi, bind_tc_ok], rr, ri⟩

def invLeft : Array I64 8#usize := Array.make 8#usize
  [0#i64, 10#i64, 1#i64, 1#i64, 0#i64, 0#i64, 0#i64, 0#i64] (by rfl)
def invRight : Array I64 8#usize := Array.make 8#usize
  [0#i64, 2#i64, 1#i64, 2#i64, 1#i64, 2#i64, 0#i64, 0#i64] (by rfl)
def invSub : Array I64 8#usize := Array.make 8#usize
  [11#i64, 4#i64, 5#i64, 0#i64, 0#i64, 0#i64, 0#i64, 0#i64] (by rfl)
def invDet : Array I64 8#usize := Array.make 8#usize
  [0#i64, 2#i64, 1#i64, 0#i64, 0#i64, 0#i64, 0#i64, 0#i64] (by rfl)

def inverseProducts (a : P F) : P F :=
  mul2 (shuffle2 invLeft a (xi2 a)) (shuffle2 invRight a a)
def inverseAdjugate (a : P F) : P F :=
  sub2 (inverseProducts a) (shuffle2 invSub (inverseProducts a) (xi2 (inverseProducts a)))
def inverseDetProducts (a t : P F) : P F := mul2 (shuffle2 invDet a a) t
def inverseDeterminant (a t : P F) : P F :=
  let d := inverseDetProducts a t
  add2 (add2 d (shuffle2 (Array.repeat 8#usize 1#i64) (xi2 d) (xi2 d)))
    (shuffle2 (Array.repeat 8#usize 2#i64) (xi2 d) (xi2 d))

noncomputable def adjugateRun (f : fp2x8.Fp2x8) : Result fp2x8.Fp2x8 := do
  let p256 ← fp8.Fp8.multiple_of_p fp12.BOUND
  let x0 ← fp2x8.Fp2x8.mul_by_xi_raw f p256
  let xn ← fp2x8.Fp2x8.normalise x0
  let left ← fp2x8.Fp2x8.permute2 f xn invLeft
  let right ← fp2x8.Fp2x8.permute f invRight
  let prods ← fp12.fp2_products left right
  let p6 ← fp8.Fp8.multiple_of_p 6#u64
  let xp ← fp2x8.Fp2x8.mul_by_xi_raw prods p6
  let xpn ← fp2x8.Fp2x8.normalise xp
  let sub ← fp2x8.Fp2x8.permute2 prods xpn invSub
  let p12 ← fp8.Fp8.multiple_of_p 12#u64
  let t ← fp2x8.Fp2x8.sub_raw prods sub p12
  fp2x8.Fp2x8.normalise t

noncomputable def determinantRun (f t : fp2x8.Fp2x8) : Result fp2x8.Fp2x8 := do
  let fp ← fp2x8.Fp2x8.permute f invDet
  let d ← fp12.fp2_products fp t
  let p6 ← fp8.Fp8.multiple_of_p 6#u64
  let xd ← fp2x8.Fp2x8.mul_by_xi_raw d p6
  let xdn ← fp2x8.Fp2x8.normalise xd
  let d1 ← fp2x8.Fp2x8.permute xdn (Array.repeat 8#usize 1#i64)
  let s1 ← fp2x8.Fp2x8.add_raw d d1
  let d2 ← fp2x8.Fp2x8.permute xdn (Array.repeat 8#usize 2#i64)
  let s2 ← fp2x8.Fp2x8.add_raw s1 d2
  fp2x8.Fp2x8.normalise s2

theorem adjugate_raw {f : fp2x8.Fp2x8} {a : P F}
    (hf : Normal2 (fun _ => 256, fun _ => 256) f a) :
    ∃ out, adjugateRun f = ok out ∧
      Normal2 (fun _ => 18, fun _ => 18) out (inverseAdjugate a) := by
  obtain ⟨p256, hp256, rp256⟩ := raw_offset 256#u64 (by decide)
  obtain ⟨x0, hx0, rx0⟩ := raw2_xi hf.raw rp256 (by intro l; rfl) (by decide)
  have rx0' : Raw2 (fun _ => 512, fun _ => 512) 3 x0 (xi2 a) := rx0
  obtain ⟨xn, hxn, rxn⟩ := raw2_normalise rx0' (by intro l; norm_num) (by decide)
  obtain ⟨left, hl, rl⟩ := normal2_permute2 invLeft hf rxn
  have rl' : Normal2 (fun _ => 512, fun _ => 512) left (shuffle2 invLeft a (xi2 a)) :=
    rl.mono (by intro l; dsimp [shuffle2, shuffle]; split_ifs <;> decide)
  obtain ⟨right, hr, rr⟩ := normal2_permute invRight hf
  have rr' : Normal2 (fun _ => 256, fun _ => 256) right (shuffle2 invRight a a) :=
    rr.mono (by intro l; simp [shuffle2, shuffle])
  obtain ⟨p, hp, rp⟩ := raw2_products rl' rr' (by intro l; norm_num) (by intro l; norm_num)
  obtain ⟨p6, hp6, rp6⟩ := raw_offset 6#u64 (by decide)
  obtain ⟨xp, hxp, rxp⟩ := raw2_xi rp.raw rp6 (by intro l; rfl) (by decide)
  have rxp' : Raw2 (fun _ => 10, fun _ => 10) 3 xp (xi2 (inverseProducts a)) := rxp
  obtain ⟨xpn, hxpn, rxpn⟩ := raw2_normalise rxp' (by intro l; norm_num) (by decide)
  obtain ⟨sub, hs, rs⟩ := normal2_permute2 invSub rp rxpn
  have rs' : Normal2 (fun _ => 10, fun _ => 10) sub
      (shuffle2 invSub (inverseProducts a) (xi2 (inverseProducts a))) :=
    rs.mono (by intro l; dsimp [shuffle2, shuffle]; split_ifs <;> decide)
  obtain ⟨p12, hp12, rp12⟩ := raw_offset 12#u64 (by decide)
  obtain ⟨t, ht, rt⟩ := raw2_sub rp.raw rs'.raw rp12 (by intro l; norm_num) (by decide)
  have rt' : Raw2 (fun _ => 18, fun _ => 18) 3 t (inverseAdjugate a) :=
    rt.mono (by intro l; norm_num) (by decide)
  obtain ⟨out, hout, rout⟩ := raw2_normalise rt' (by intro l; norm_num) (by decide)
  refine ⟨out, ?_, rout⟩
  simp only [adjugateRun, fp12.BOUND, hp256, hx0, hxn, hl, hr, hp, hp6, hxp, hxpn,
    hs, hp12, ht, hout, bind_tc_ok]

theorem determinant_raw {f t : fp2x8.Fp2x8} {a b : P F}
    (hf : Normal2 (fun _ => 256, fun _ => 256) f a)
    (ht : Normal2 (fun _ => 18, fun _ => 18) t b) :
    ∃ out, determinantRun f t = ok out ∧
      Normal2 (fun _ => 30, fun _ => 30) out (inverseDeterminant a b) := by
  obtain ⟨fp, hfp, rfp⟩ := normal2_permute invDet hf
  have rfp' : Normal2 (fun _ => 256, fun _ => 256) fp (shuffle2 invDet a a) :=
    rfp.mono (by intro l; simp [shuffle2, shuffle])
  obtain ⟨d, hd, rd⟩ := raw2_products rfp' ht (by intro l; norm_num) (by intro l; norm_num)
  obtain ⟨p6, hp6, rp6⟩ := raw_offset 6#u64 (by decide)
  obtain ⟨xd, hxd, rxd⟩ := raw2_xi rd.raw rp6 (by intro l; rfl) (by decide)
  have rxd' : Raw2 (fun _ => 10, fun _ => 10) 3 xd (xi2 (inverseDetProducts a b)) := rxd
  obtain ⟨xdn, hxdn, rxdn⟩ := raw2_normalise rxd' (by intro l; norm_num) (by decide)
  obtain ⟨d1, hd1, rd1⟩ := normal2_permute (Array.repeat 8#usize 1#i64) rxdn
  have rd1' : Normal2 (fun _ => 10, fun _ => 10) d1
      (shuffle2 (Array.repeat 8#usize 1#i64) (xi2 (inverseDetProducts a b)) (xi2 (inverseDetProducts a b))) :=
    rd1.mono (by intro l; simp [shuffle2, shuffle])
  obtain ⟨s1, hs1, rs1⟩ := raw2_add rd.raw rd1'.raw (by decide)
  obtain ⟨d2, hd2, rd2⟩ := normal2_permute (Array.repeat 8#usize 2#i64) rxdn
  have rd2' : Normal2 (fun _ => 10, fun _ => 10) d2
      (shuffle2 (Array.repeat 8#usize 2#i64) (xi2 (inverseDetProducts a b)) (xi2 (inverseDetProducts a b))) :=
    rd2.mono (by intro l; simp [shuffle2, shuffle])
  obtain ⟨s2, hs2, rs2⟩ := raw2_add rs1 rd2'.raw (by decide)
  have rs2' : Raw2 (fun _ => 30, fun _ => 30) 3 s2 (inverseDeterminant a b) :=
    rs2.mono (by intro l; dsimp [add2]; decide) (by decide)
  obtain ⟨out, hout, rout⟩ := raw2_normalise rs2' (by intro l; norm_num) (by decide)
  refine ⟨out, ?_, rout⟩
  simp only [determinantRun, hfp, hd, hp6, hxd, hxdn, hd1, hs1, hd2, hs2, hout, bind_tc_ok]

end LeanBlsSimd.LaneTower
