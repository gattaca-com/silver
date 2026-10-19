import LeanBlsSimd.Kzg.Refines.Loop
import LeanBlsSimd.Kzg.Externals
import LeanBlsSimd.Kzg.Model
import EthCryptographySpecs.Proofs.Bls.Fr

open Aeneas Aeneas.Std Result ControlFlow
open EthCryptographySpecs Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

deriving instance DecidableEq for Aeneas.Std.Error
deriving instance DecidableEq for Aeneas.Std.Result

namespace LeanBlsSimd.Kzg
namespace Refinement

set_option maxRecDepth 16000
set_option maxHeartbeats 2000000

private theorem powers_loop [e : KzgExternals] (h : BlstCorrect e)
    (root power : Fr) (rs : alloc.vec.Vec blst.blst_fr)
    (iter : core.ops.range.Range Usize)
    (hi : iter.start.val ≤ iter.end.val)
    (hb : rs.val.length + (iter.end.val - iter.start.val) ≤ Usize.max) :
    ∃ out, loop
      (fun (it, xs, p) => domain.roots_of_unity_loop.body (frEncode root) it xs p)
      (iter, rs, frEncode power) = ok out ∧
      out.val = rs.val ++ (computePowersAux root power
        (iter.end.val - iter.start.val)).map frEncode := by
  induction hk : iter.end.val - iter.start.val generalizing iter rs power with
  | zero =>
    have he : iter.end.val ≤ iter.start.val := by omega
    have hn := next_ge iter he
    refine ⟨rs, ?_, ?_⟩
    · rw [loop.eq_1]
      simp only [domain.roots_of_unity_loop.body, hn, bind_tc_ok, Function.uncurry_apply_pair]
    · simp [computePowersAux]
  | succ k ih =>
    have hlt : iter.start.val < iter.end.val := by omega
    obtain ⟨it', hs, he, hn⟩ := next_lt iter hlt
    have hlen : rs.val.length + 1 ≤ Usize.max := by omega
    let rs' : alloc.vec.Vec blst.blst_fr := ⟨rs.val ++ [frEncode power], by simpa using hlen⟩
    have hp : alloc.vec.Vec.push rs (frEncode power) = ok rs' := by
      simp [alloc.vec.Vec.push, hlen, rs']
    have hv : rs'.val = rs.val ++ [frEncode power] := rfl
    have hmul : blst_ops.fr_mul (frEncode power) (frEncode root) =
        ok (frEncode (power * root)) := h.fr_mul _ _
    have hi' : it'.start.val ≤ it'.end.val := by rw [he, hs]; omega
    have hk' : it'.end.val - it'.start.val = k := by rw [he, hs]; omega
    obtain ⟨out, hout, hvout⟩ := ih (power * root) rs' it' hi'
      (by rw [hv, List.length_append, List.length_singleton, he, hs]; omega) hk'
    refine ⟨out, ?_, ?_⟩
    · rw [loop.eq_1]
      simpa only [domain.roots_of_unity_loop.body, hn, hp, hmul, bind_tc_ok, Function.uncurry_apply_pair] using hout
    · rw [hvout, hv]
      simp [computePowersAux, List.append_assoc]

private def primitiveBits (bit : U32) : Result (U32 × Bool) := do
  let bit1 ← bit - 1#u32
  let i ← bit1 / 64#u32
  let i1 ← lift (UScalar.cast .Usize i)
  let i2 ← Aeneas.Std.Array.index_usize domain.R_MINUS_ONE i1
  let i3 ← bit1 % 64#u32
  let i4 ← i2 >>> i3
  let i5 ← lift (i4 &&& 1#u64)
  ok (bit1, i5 == 1#u64)

private def bit32 (n : Nat) : U32 := ⟨BitVec.ofNat 32 n⟩

private theorem primitive_bits (i : Fin 256) :
    primitiveBits (bit32 (i.val + 1)) =
      ok (bit32 i.val, decide (((Fr.modulus - 1) / 2^i.val) % 2 = 1)) := by
  simp only [primitiveBits, lift, bind_tc_ok, Aeneas.Std.Array.index_usize,
    Aeneas.Std.Array.getElem?_Usize_eq, U32.cast_Usize_val_eq]
  fin_cases i <;> decide +kernel

private def primitivePower (i : Nat) : Fr :=
  Fr.powNat (Fr.ofNat 7) ((Fr.modulus - 1) / 2^i)

private theorem primitive_power_step (i : Nat) :
    (if ((Fr.modulus - 1) / 2^i) % 2 = 1
      then primitivePower (i + 1) * primitivePower (i + 1) * Fr.ofNat 7
      else primitivePower (i + 1) * primitivePower (i + 1)) = primitivePower i := by
  unfold primitivePower
  rw [Nat.pow_succ, ← Nat.div_div_eq_div_mul]
  split_ifs with ho
  · rw [← Fr.powNat_add, Fr.mul_comm, ← Fr.powNat_succ]
    congr 1
    omega
  · rw [← Fr.powNat_add]
    congr 1
    omega

private theorem primitive_step [e : KzgExternals] (h : BlstCorrect e)
    (logOrder : U32) (i : Fin 256) (hi : logOrder.val ≤ i.val) (x : Fr) :
    domain.primitive_root_loop.body logOrder (frEncode (Fr.ofNat 7))
      (frEncode x) (bit32 (i.val + 1)) =
      ok (cont (frEncode (if ((Fr.modulus - 1) / 2^i.val) % 2 = 1
        then x * x * Fr.ofNat 7 else x * x), bit32 i.val)) := by
  have hib : (bit32 (i.val + 1)).val = i.val + 1 := by
    change (i.val + 1) % 2^32 = i.val + 1
    exact Nat.mod_eq_of_lt (by omega)
  have hc : (bit32 (i.val + 1)) > logOrder := by
    simp only [GT.gt, UScalar.lt_equiv, hib]
    omega
  have he : domain.primitive_root_loop.body logOrder (frEncode (Fr.ofNat 7))
      (frEncode x) (bit32 (i.val + 1)) = (do
      let (b, flag) ← primitiveBits (bit32 (i.val + 1))
      ok (cont (frEncode (if flag then x * x * Fr.ofNat 7 else x * x), b))) := by
    simp only [domain.primitive_root_loop.body, hc, if_true, primitiveBits,
      blst_ops.fr_mul, h.fr_mul, bind_tc_ok, bind_assoc]
    simp only [Function.uncurry_apply_pair, beq_iff_eq, apply_ite]
    congr!
    all_goals split_ifs <;> rfl
  rw [he, primitive_bits]
  simp only [bind_tc_ok, Function.uncurry_apply_pair, decide_eq_true_eq]

private theorem primitive_loop [e : KzgExternals] (h : BlstCorrect e)
    (logOrder : U32) (n : Nat) (hl : logOrder.val ≤ n) (hn : n ≤ 256) :
    loop (fun (x, b) => domain.primitive_root_loop.body logOrder
      (frEncode (Fr.ofNat 7)) x b) (frEncode (primitivePower n), bit32 n) =
      ok (frEncode (primitivePower logOrder.val)) := by
  induction n using Nat.strongRecOn with
  | ind n ih =>
    have hv : (bit32 n).val = n := by
      change n % 2^32 = n
      exact Nat.mod_eq_of_lt (by omega)
    by_cases he : n = logOrder.val
    · have hstop : ¬ (bit32 n) > logOrder := by
        simp only [GT.gt, UScalar.lt_equiv, hv]
        omega
      rw [loop.eq_1]
      simp only [domain.primitive_root_loop.body, hstop, if_false]
      simp only [he]
    · have hn0 : 0 < n := by omega
      have hn1 : n - 1 < 256 := by omega
      have hstep := primitive_step h logOrder ⟨n - 1, hn1⟩ (by change logOrder.val ≤ n - 1; omega)
        (primitivePower n)
      have hnEq : n - 1 + 1 = n := by omega
      simp only [hnEq] at hstep
      have hp := primitive_power_step (n - 1)
      rw [hnEq] at hp
      rw [loop.eq_1]
      simp only [hstep, hp]
      exact ih (n - 1) (by omega) (by omega) (by omega)

theorem primitive_root_refinement_of_blst [e : KzgExternals] (h : BlstCorrect e)
    (logOrder : U32) (hl : logOrder.val ≤ 256) :
    domain.primitive_root logOrder = ok (frEncode
      (Fr.powNat (Fr.ofNat 7) ((Fr.modulus - 1) / 2^logOrder.val))) := by
  unfold domain.primitive_root domain.primitive_root_loop
  simp only [domain.PRIMITIVE_ROOT_OF_UNITY, blst_ops.fr_from_u64,
    h.fr_u64, bind_tc_ok]
  have h0 : primitivePower 256 = Fr.ofNat 1 := by
    rw [primitivePower, show (Fr.modulus - 1) / 2^256 = 0 by decide, Fr.powNat_zero]
    rfl
  change loop (fun (x, b) => domain.primitive_root_loop.body logOrder
    (frEncode (Fr.ofNat 7)) x b) (frEncode (Fr.ofNat 1), bit32 256) = _
  rw [← h0]
  exact primitive_loop h logOrder 256 hl (by omega)

private theorem model_roots (l : Nat) (hl : l ≤ 13) :
    Model.roots l = computePowers (primitivePower l) (2^l) := by
  interval_cases l <;> rfl

end Refinement

open Refinement

theorem roots_refinement_of_blst [e : KzgExternals] (h : BlstCorrect e) (logOrder : U32)
    (hl : logOrder.val ≤ 13) :
    ∃ rs, domain.roots_of_unity logOrder = ok rs ∧
      rs.val = (Model.roots logOrder.val).toList.map frEncode := by
  have hn : 2^logOrder.val ≤ 8192 := by calc
    2 ^ logOrder.val ≤ 2 ^ 13 := Nat.pow_le_pow_right (by decide) hl
    _ = 8192 := by decide
  have hbound : 8192 < 2^UScalarTy.Usize.numBits := by
    rcases System.Platform.numBits_eq with h | h <;> simp [UScalarTy.numBits, h]
  let order : Usize := UScalar.ofNatCore (2^logOrder.val) (by omega)
  have hv : order.val = 2^logOrder.val := UScalar.ofNatCore_val_eq _
  have hlog : logOrder.val < UScalarTy.Usize.numBits := by
    rcases System.Platform.numBits_eq with h | h <;>
      simp only [UScalarTy.numBits, h] <;> omega
  have hshift : 1#usize <<< logOrder = ok order := by
    show UScalar.shiftLeft_UScalar _ _ = _
    simp only [UScalar.shiftLeft_UScalar, UScalar.shiftLeft, hlog, if_true, Result.ok.injEq]
    apply (UScalar.eq_equiv _ _).mpr
    change ((1#usize).bv.shiftLeft logOrder.val).toNat = order.val
    rw [BitVec.shiftLeft_eq, BitVec.toNat_shiftLeft, Nat.shiftLeft_eq]
    change ((1#usize).val * 2^logOrder.val) % 2^UScalarTy.Usize.numBits = order.val
    simp only [UScalar.ofNatCore_val_eq, one_mul, hv]
    exact Nat.mod_eq_of_lt (by omega)
  have hmax : 2^logOrder.val ≤ Usize.max := by scalar_tac
  obtain ⟨rs, hr, hval⟩ := powers_loop h (primitivePower logOrder.val) Fr.one
    (alloc.vec.Vec.with_capacity blst.blst_fr order)
    { start := 0#usize, «end» := order }
    (by simp [hv]) (by simpa [alloc.vec.Vec.with_capacity, hv] using hmax)
  refine ⟨rs, ?_, ?_⟩
  · unfold domain.roots_of_unity
    rw [hshift, primitive_root_refinement_of_blst h logOrder (by omega)]
    simp only [blst_ops.fr_from_u64, h.fr_u64, bind_tc_ok]
    exact hr
  · simpa [alloc.vec.Vec.with_capacity, hv, model_roots _ hl, computePowers] using hval

theorem Refinement.primitive_root_refinement [e : KzgExternals] (h : ExternalsCorrect e)
    (logOrder : U32) (hl : logOrder.val ≤ 256) :
    domain.primitive_root logOrder = ok (frEncode
      (Fr.powNat (Fr.ofNat 7) ((Fr.modulus - 1) / 2^logOrder.val))) :=
  Refinement.primitive_root_refinement_of_blst h.blst logOrder hl

theorem roots_refinement [e : KzgExternals] (h : ExternalsCorrect e) (logOrder : U32)
    (hl : logOrder.val = 6 ∨ logOrder.val = 13) :
    ∃ rs, domain.roots_of_unity logOrder = ok rs ∧
      rs.val = (Model.roots logOrder.val).toList.map frEncode :=
  roots_refinement_of_blst h.blst logOrder (by rcases hl with h | h <;> omega)

end LeanBlsSimd.Kzg
