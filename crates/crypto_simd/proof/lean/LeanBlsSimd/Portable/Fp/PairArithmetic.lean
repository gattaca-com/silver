import LeanBlsSimd.Portable.Fp.Powers
import LeanBlsSimd.Portable.Fp.Equality

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Fp
set_option maxRecDepth 4096

def pairEncode (x y : ZMod Bls.Fp.modulus) : Array portable.fp.Fp 2#usize :=
  Array.make 2#usize [(Kzg.fpEncode x).l,(Kzg.fpEncode y).l] (by rfl)

theorem pair_index_zero (x y : ZMod Bls.Fp.modulus) :
    Array.index_usize (pairEncode x y) 0#usize = ok (Kzg.fpEncode x).l := by
  rw [index_usize_eq _ _ (by decide)]
  rfl

theorem pair_index_one (x y : ZMod Bls.Fp.modulus) :
    Array.index_usize (pairEncode x y) 1#usize = ok (Kzg.fpEncode y).l := by
  rw [index_usize_eq _ _ (by decide)]
  rfl

theorem mul_pair_encoded [RuntimeFeatures] (x0 x1 y0 y1 : ZMod Bls.Fp.modulus) :
    portable.fp.Fp.mul_pair (pairEncode x0 x1) (pairEncode y0 y1) = ok (pairEncode (x0*y0) (x1*y1)) := by
  simp only [portable.fp.Fp.mul_pair,pair_index_zero,pair_index_one,bind_tc_ok,mul_encoded]
  rfl

theorem pair_square_four [RuntimeFeatures] (x y : ZMod Bls.Fp.modulus) :
    portable.fp.Fp.pow_p_minus_3_over_4_pair_loop1_loop0 (pairEncode x y) 0#i32 =
      ok (pairEncode (x^16) (y^16)) := by
  have ha0 : 0#i32+1#i32 = ok 1#i32 := by rfl
  have ha1 : 1#i32+1#i32 = ok 2#i32 := by rfl
  have ha2 : 2#i32+1#i32 = ok 3#i32 := by rfl
  have ha3 : 3#i32+1#i32 = ok 4#i32 := by rfl
  unfold portable.fp.Fp.pow_p_minus_3_over_4_pair_loop1_loop0
  rw [loop.eq_1]
  simp only [portable.fp.Fp.pow_p_minus_3_over_4_pair_loop1_loop0.body,
    show 0#i32 < 4#i32 from by decide,if_true,mul_pair_encoded,bind_tc_ok,ha0]
  rw [loop.eq_1]
  simp only [
    show 1#i32 < 4#i32 from by decide,if_true,mul_pair_encoded,bind_tc_ok,ha1]
  rw [loop.eq_1]
  simp only [
    show 2#i32 < 4#i32 from by decide,if_true,mul_pair_encoded,bind_tc_ok,ha2]
  rw [loop.eq_1]
  simp only [
    show 3#i32 < 4#i32 from by decide,if_true,mul_pair_encoded,bind_tc_ok,ha3]
  rw [loop.eq_1]
  simp only [lt_self_iff_false,if_false]
  have hx : (((x*x)*(x*x))*((x*x)*(x*x)))*(((x*x)*(x*x))*((x*x)*(x*x))) = x^16 := by ring
  have hy : (((y*y)*(y*y))*((y*y)*(y*y)))*(((y*y)*(y*y))*((y*y)*(y*y))) = y^16 := by ring
  simp only [hx,hy]

end LeanBlsSimd.Portable.Fp
