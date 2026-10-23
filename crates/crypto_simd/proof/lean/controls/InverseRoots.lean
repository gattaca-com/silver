import LeanBlsSimd.Kzg.Refines.InverseRoots
import LeanBlsSimd.Kzg.Fr.Arithmetic

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.kzg
open EthLib.Cryptography Bls Kzg
open LeanBlsSimd.Kzg LeanBlsSimd.Word64
open scoped EthLib.Cryptography.Bls.Fr

namespace LeanBlsSimd.Controls.InverseRoots

attribute [-instance] Lean.Grind.Fin.instHPowFinNatOfNeZero
attribute [-instance] Lean.Grind.Fin.instPowFinNatOfNeZero

def values : _root_.Array Fr := #[Fr.ofNat 1,Fr.ofNat 2,Fr.ofNat 3,Fr.ofNat 4]
def input : Slice blst.blst_fr := ⟨values.toList.map frEncode,by simp [values]; scalar_tac⟩
def forwardTable : alloc.vec.Vec blst.blst_fr := ⟨values.toList.map frEncode,by simp [values]; scalar_tac⟩

theorem forward_table_rejected : domain.inverse_roots input ≠ ok forwardTable := by
  intro h
  obtain ⟨out,hr,hvalue⟩ := Refinement.inverse_roots_refinement 4#usize (by decide)
    input values (by rfl) (by rfl)
  have heq := Result.ok.inj (hr.symm.trans h)
  subst out
  have hval := congrArg (fun xs : List blst.blst_fr => value (xs[1]!).l) hvalue
  have hne : value (frEncode (Fr.ofNat 2)).l ≠ value (frEncode (Fr.ofNat 4)).l := by decide +kernel
  exact hne hval

theorem wrong_inverse_exponent_rejected :
    domainRoot 8192 ^ (8190 : Nat) ≠ (domainRoot 8192).inverse := by
  intro h
  rw [Fr.inverse_eq_inv] at h
  have hprim : IsPrimitiveRoot (domainRoot 8192) 8192 :=
    isPrimitiveRoot_domainRoot (Nat.dvd_of_mod_eq_zero (by decide))
  have hp : domainRoot 8192 ^ (8191 : Nat) = 1 := by
    rw [show 8191 = 8190+1 by rfl,pow_succ,h]
    exact inv_mul_cancel₀ (hprim.ne_zero (by decide))
  have hd := hprim.dvd_of_pow_eq_one 8191 hp
  norm_num at hd

end LeanBlsSimd.Controls.InverseRoots
