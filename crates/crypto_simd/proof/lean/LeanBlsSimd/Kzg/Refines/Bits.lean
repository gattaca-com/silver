import LeanBlsSimd.Extracted.Funs
import EthLib.Cryptography.Kzg.BitReversal

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Kzg
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg

private abbrev bitsUsize (n : Nat) : Usize := ⟨BitVec.ofNat _ n⟩

private theorem bits_shift_left (x : Usize) :
    x <<< 1#i32 = ok (⟨x.bv.shiftLeft 1⟩ : Usize) := by
  have h : 1 < System.Platform.numBits := by
    rcases System.Platform.numBits_eq with h | h <;> omega
  show UScalar.shiftLeft_IScalar x 1#i32 = _
  simp [UScalar.shiftLeft_IScalar, UScalar.shiftLeft, h]

private theorem bits_shift_right (x : Usize) :
    x >>> 1#i32 = ok (⟨x.bv.ushiftRight 1⟩ : Usize) := by
  have h : 1 < System.Platform.numBits := by
    rcases System.Platform.numBits_eq with h | h <;> omega
  show UScalar.shiftRight_IScalar x 1#i32 = _
  simp [UScalar.shiftRight_IScalar, UScalar.shiftRight, h]

private theorem bits_step (rest : Usize) (r : Nat) :
    ((⟨(bitsUsize r).bv.shiftLeft 1⟩ : Usize) ||| (rest &&& 1#usize)) =
      bitsUsize ((r <<< 1) ||| (rest.val &&& 1)) := by
  apply (UScalar.eq_equiv_bv_eq _ _).mpr
  change (UScalar.or (ty := .Usize) ⟨(bitsUsize r).bv.shiftLeft 1⟩
    (UScalar.and rest 1#usize)).bv = _
  simp only [UScalar.or, UScalar.and, bitsUsize, Usize.ofNat_bv]
  rw [BitVec.ofNat_or, BitVec.ofNat_and, UScalar.BitVec_ofNat_val]
  congr 1
  apply BitVec.eq_of_toNat_eq
  change ((r % 2 ^ System.Platform.numBits) <<< 1) % 2 ^ System.Platform.numBits =
    (r <<< 1) % 2 ^ System.Platform.numBits
  exact Nat.mod_two_pow_shiftLeft_mod_two_pow

private theorem reverse_bits_loop_eq (bits bit : U32) (rest : Usize) (r : Nat)
    (hb : bit.val ≤ bits.val) :
    loop (fun (rest, reversed, bit) => domain.reverse_bits_loop.body bits rest reversed bit)
        (rest, bitsUsize r, bit) =
      ok (bitsUsize (BitReversal.reverseBitsAux rest.val r (bits.val - bit.val))) := by
  induction hk : bits.val - bit.val generalizing bit rest r with
  | zero =>
    have hstop : ¬ bit < bits := by simp only [UScalar.lt_equiv]; omega
    rw [loop.eq_1]
    simp [domain.reverse_bits_loop.body, hstop, BitReversal.reverseBitsAux]
  | succ k ih =>
    have hlt : bit < bits := by simp only [UScalar.lt_equiv]; omega
    have hbound : bit.val + 1 < 2 ^ UScalarTy.U32.numBits := by
      have := bits.hBounds
      simp only [UScalar.lt_equiv] at hlt
      omega
    let bit' : U32 := UScalar.ofNatCore (bit.val + 1) hbound
    have hbit' : bit'.val = bit.val + 1 := UScalar.ofNatCore_val_eq _
    have hadd : bit + 1#u32 = ok bit' := by
      show UScalar.tryMk .U32 (bit.val + (1#u32).val) = ok bit'
      have hbound' : bit.val + 1 < 4294967296 := hbound
      simp [UScalar.tryMk, UScalar.tryMkOpt, hbound', Result.ofOption, bit']
    let rest' : Usize := ⟨rest.bv.ushiftRight 1⟩
    have hrest' : rest'.val = rest.val >>> 1 := BitVec.toNat_ushiftRight _ _
    have hrec := ih bit' rest' ((r <<< 1) ||| (rest.val &&& 1)) (by omega) (by omega)
    have hbody : domain.reverse_bits_loop.body bits rest (bitsUsize r) bit =
        ok (cont (rest', bitsUsize ((r <<< 1) ||| (rest.val &&& 1)), bit')) := by
      simp only [domain.reverse_bits_loop.body, hlt, if_true, bits_shift_left,
        bits_shift_right, lift, bind_tc_ok, bits_step, hadd]
      rfl
    rw [loop.eq_1]
    simp only [hbody]
    change loop _ (rest', bitsUsize ((r <<< 1) ||| (rest.val &&& 1)), bit') = _
    rw [hrec]
    simp only [BitReversal.reverseBitsAux, hrest']

theorem reverse_bits_refinement (index : Usize) (bits : U32)
    (_hb : bits.val ≤ Usize.numBits) :
    domain.reverse_bits index bits =
      ok ⟨BitVec.ofNat _ (BitReversal.reverseBitsAux index.val 0 bits.val)⟩ := by
  simpa [domain.reverse_bits, domain.reverse_bits_loop] using
    reverse_bits_loop_eq bits 0#u32 index 0 (by simp)

end LeanBlsSimd.Kzg
