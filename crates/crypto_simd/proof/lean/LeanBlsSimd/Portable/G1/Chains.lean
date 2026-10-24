import LeanBlsSimd.Portable.G1.Mixed
import LeanBlsSimd.Refines.G1x8

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.G1
set_option maxRecDepth 4096

def chainStep (P Q : Bls.G1) (bit : Nat) : Bls.G1 :=
  let D := Kzg.PortableG1.doubleValues Q
  if G1x8.is_lower_z_bit bit then Bls.G1.add D P else D

def timesZ (P : Bls.G1) : Bls.G1 :=
  (List.range Z_BITS[0]!).reverse.foldl (chainStep P) P

theorem times_z_loop_encoded [RuntimeFeatures] (P Q : Bls.G1) (c : U32) (n : Nat)
    (hcn : c.val = n) :
    portable.g1.G1.times_z_loop (encode P) (encode Q) c =
      ok (encode ((List.range n).reverse.foldl (chainStep P) Q)) := by
  unfold portable.g1.G1.times_z_loop
  refine loop_countdown _ (fun (Q : Bls.G1) c => (encode Q,c)) (chainStep P) encode n
    ?_ ?_ c Q hcn
  · intro Q c hc
    simp [portable.g1.G1.times_z_loop.body,hc]
  · intro Q c c' hc _
    simp only [portable.g1.G1.times_z_loop.body]
    rw [if_pos (by simp; omega),sub_ok _ _ (by simp; omega)]
    have e : (UScalar.ofNatCore (c.val-(1#u32).val) (by have := c.hBounds; omega) : U32) =
        c' := UScalar.eq_of_val_eq (by simp; omega)
    rw [e]
    simp only [bind_tc_ok,double_encoded,G1x8.is_lower_z_bit_refines,add_complete_encoded,chainStep]
    cases G1x8.is_lower_z_bit c'.val <;> simp

theorem times_z_affine_loop_encoded [RuntimeFeatures] (x y : Bls.Fp) (Q : Bls.G1) (c : U32) (n : Nat)
    (hcn : c.val = n) :
    portable.g1.G1.times_z_affine_loop (Kzg.fpEncode x).l (Kzg.fpEncode y).l (encode Q) c =
      ok (encode ((List.range n).reverse.foldl (chainStep ⟨x,y,Bls.Fp.one⟩) Q)) := by
  unfold portable.g1.G1.times_z_affine_loop
  refine loop_countdown _ (fun (Q : Bls.G1) c => (encode Q,c))
    (chainStep ⟨x,y,Bls.Fp.one⟩) encode n ?_ ?_ c Q hcn
  · intro Q c hc
    simp [portable.g1.G1.times_z_affine_loop.body,hc]
  · intro Q c c' hc _
    simp only [portable.g1.G1.times_z_affine_loop.body]
    rw [if_pos (by simp; omega),sub_ok _ _ (by simp; omega)]
    have e : (UScalar.ofNatCore (c.val-(1#u32).val) (by have := c.hBounds; omega) : U32) =
        c' := UScalar.eq_of_val_eq (by simp; omega)
    rw [e]
    simp only [bind_tc_ok,double_encoded,G1x8.is_lower_z_bit_refines,add_affine_complete_encoded,chainStep]
    cases G1x8.is_lower_z_bit c'.val <;> simp

theorem times_z_encoded [RuntimeFeatures] (P : Bls.G1) :
    portable.g1.G1.times_z (encode P) = ok (encode (timesZ P)) := by
  simp only [portable.g1.G1.times_z,Z_BITS_index 0#usize (by decide),bind_tc_ok]
  exact times_z_loop_encoded P P _ Z_BITS[0]! (by simp)

theorem times_z_affine_encoded [RuntimeFeatures] (x y : Bls.Fp) :
    portable.g1.G1.times_z_affine (Kzg.fpEncode x).l (Kzg.fpEncode y).l =
      ok (encode (timesZ ⟨x,y,Bls.Fp.one⟩)) := by
  simp only [portable.g1.G1.times_z_affine,from_affine_encoded,
    Z_BITS_index 0#usize (by decide),bind_tc_ok]
  exact times_z_affine_loop_encoded x y _ _ Z_BITS[0]! (by simp)

private def scalarStep (n bit : Nat) : Nat :=
  if G1x8.is_lower_z_bit bit then 2*n+1 else 2*n

private theorem scalar_chain_eq :
    (List.range Z_BITS[0]!).reverse.foldl scalarStep 1 = blsX := by decide +kernel

theorem timesZ_valid_point (P : Bls.G1) (hp : Bls.G1.Valid P) :
    Bls.G1.Valid (timesZ P) ∧ Bls.G1.toPoint (timesZ P) = blsX • Bls.G1.toPoint P := by
  have hf := List.foldl_rel
    (fun (Q : Bls.G1) (n : Nat) => Bls.G1.Valid Q ∧ Bls.G1.toPoint Q = n • Bls.G1.toPoint P)
    (chainStep P) scalarStep ?_ (List.range Z_BITS[0]!).reverse P 1 ⟨hp,by simp⟩
  · simpa only [timesZ,scalar_chain_eq] using hf
  · rintro Q n bit ⟨hq,hqn⟩
    have hd := double_values_valid hq
    have hdp := double_values_point hq
    by_cases hb : G1x8.is_lower_z_bit bit = true
    · simp only [chainStep,scalarStep,hb,if_true]
      refine ⟨Bls.G1.valid_add hd hp,?_⟩
      rw [Bls.G1.toPoint_add hd hp,hdp,hqn]
      simp [add_nsmul,mul_nsmul,two_nsmul,nsmul_add]
    · simp only [chainStep,scalarStep,hb,Bool.false_eq_true,if_false]
      refine ⟨hd,?_⟩
      rw [hdp,hqn]
      simp [mul_nsmul,two_nsmul,nsmul_add]

end LeanBlsSimd.Portable.G1
