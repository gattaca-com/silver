import LeanBlsSimd.Msm8.Lanes
import LeanBlsSimd.Refines.Fp2x8

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.Fp8

def permute2 (self other : Fp8) (indices : Vector Int64 8) : Fp8 :=
  ⟨Vector.ofFn fun j => _mm512_permutex2var_epi64 self.limbs[j]
    (indices.map Int64.toUInt64) other.limbs[j]⟩

theorem lane_permute2 (self other : Fp8) (indices : Vector Int64 8) (l : Fin 8) :
    (self.permute2 other indices).lane l =
      if indices[l].toUInt64.toNat.testBit 3 then
        other.lane ⟨indices[l].toUInt64.toNat % 8, Nat.mod_lt _ (by decide)⟩
      else self.lane ⟨indices[l].toUInt64.toNat % 8, Nat.mod_lt _ (by decide)⟩ := by
  ext j hj
  simp [permute2, lane, _mm512_permutex2var_epi64]
  split_ifs <;> simp_all

theorem permute2_loop_refines (self other : fp8.Fp8) (index : M512)
    (v : Vector M512 8) (i : Usize) (hi : i.val ≤ 8)
    (hv : ∀ j : Fin 8, j.val < i.val → v[j] =
      _mm512_permutex2var_epi64 (ofArray id self)[j] index (ofArray id other)[j]) :
    fp8.Fp8.permute2_loop self other index (toArray id v) i =
      ok (toArray id (Vector.ofFn fun j : Fin 8 => _mm512_permutex2var_epi64 (ofArray id self)[j] index (ofArray id other)[j])) := by
  unfold fp8.Fp8.permute2_loop
  induction hn : 8 - i.val generalizing i v with
  | zero =>
    have hi8 : i.val = 8 := by omega
    have hb : fp8.Fp8.permute2_loop.body index self other (toArray id v) i = ok (done (toArray id v)) := by
      simp only [fp8.Fp8.permute2_loop.body, LIMBS_refines, UScalar.lt_equiv,
        hi8, UScalar.ofNatCore_val_eq, Nat.lt_irrefl, ↓reduceIte]
    rw [loop.eq_1]
    simp only [hb]
    apply congrArg ok
    apply congrArg (toArray id)
    apply Vector.ext
    intro j hj
    simpa only [Vector.getElem_ofFn] using hv ⟨j, hj⟩ (by omega)
  | succ n ih =>
    have hlt : i.val < 8 := by omega
    let i' : Usize := UScalar.ofNatCore (i.val + 1) (by scalar_tac)
    have hi' : i'.val = i.val + 1 := UScalar.ofNatCore_val_eq _
    let value := _mm512_permutex2var_epi64 (ofArray id self)[i.val] index (ofArray id other)[i.val]
    let v' := v.set i.val value
    have hb : fp8.Fp8.permute2_loop.body index self other (toArray id v) i =
        ok (cont (self, other, toArray id v', i')) := by
      simp only [fp8.Fp8.permute2_loop.body, LIMBS_refines, UScalar.lt_equiv,
        UScalar.ofNatCore_val_eq, hlt, ↓reduceIte,
        index_usize_eq self i hlt, index_usize_eq other i hlt, bind_tc_ok,
        core.core_arch.x86.avx512f._mm512_permutex2var_epi64, update_eq (n := 8#usize) _ i _ hlt]
      rw [add_ok _ _ (by scalar_tac)]
      simp [v', value, i']
      exact set_toArray id v rfl i _ hlt
    rw [loop.eq_1]
    simp only [hb]
    apply ih v' i' (by omega) ?_ (by omega)
    intro j hj
    by_cases hji : j.val = i.val
    · simp [v', value, hji]
    · simpa [v', Vector.getElem_set, hji, Ne.symm hji] using hv j (by omega)

theorem permute2_refines (self other : fp8.Fp8) (indices : Array I64 8#usize) :
    fp8.Fp8.permute2 self other indices =
      ok (toFp8 ((ofFp8 self).permute2 (ofFp8 other) (ofArray (fun i => Int64.ofBitVec i.bv) indices))) := by
  simp only [fp8.Fp8.permute2, index_vector_refines, Simd.zero_refines, bind_tc_ok]
  have hre : Array.repeat 8#usize Simd.zero = toArray id (Vector.replicate 8 Simd.zero) :=
    (toArray_replicate id Simd.zero rfl).symm
  rw [hre]
  rw [permute2_loop_refines self other _ _ 0#usize (by decide) (by simp)]
  rfl

end LeanBlsSimd.Fp8

namespace LeanBlsSimd.Fp2x8

def permute2 (self other : Fp2x8) (indices : Vector Int64 8) : Fp2x8 :=
  ⟨self.c0.permute2 other.c0 indices, self.c1.permute2 other.c1 indices⟩

def permute (self : Fp2x8) (indices : Vector Int64 8) : Fp2x8 :=
  ⟨self.c0.permute indices, self.c1.permute indices⟩

theorem permute2_refines (self other : fp2x8.Fp2x8) (indices : Array I64 8#usize) :
    fp2x8.Fp2x8.permute2 self other indices =
      ok (toFp2x8 ((ofFp2x8 self).permute2 (ofFp2x8 other)
        (ofArray (fun i => Int64.ofBitVec i.bv) indices))) := by
  simp only [fp2x8.Fp2x8.permute2, Fp8.permute2_refines, bind_tc_ok]
  rfl

theorem permute_refines (self : fp2x8.Fp2x8) (indices : Array I64 8#usize) :
    fp2x8.Fp2x8.permute self indices =
      ok (toFp2x8 ((ofFp2x8 self).permute
        (ofArray (fun i => Int64.ofBitVec i.bv) indices))) := by
  simp only [fp2x8.Fp2x8.permute, Fp8.permute_refines, bind_tc_ok]
  rfl

end LeanBlsSimd.Fp2x8
