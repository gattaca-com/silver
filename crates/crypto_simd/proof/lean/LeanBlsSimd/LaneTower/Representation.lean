import LeanBlsSimd.LaneTower.Coordinates

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls
open EthLib.Cryptography Bls

namespace LeanBlsSimd.LaneTower

/-- Every lane is normalized and below 256p. Only lanes 0–5 determine the field value. -/
def Rep (x : fp2x8.Fp2x8) (a : Bls.Fp12) : Prop :=
  ∃ v : P F, (∀ l, Fp8.BoundRep 256 (ofFp8 x.c0) l (v.1 l)) ∧
    (∀ l, Fp8.BoundRep 256 (ofFp8 x.c1) l (v.2 l)) ∧ value v = a

theorem mul_refines {x y : fp2x8.Fp2x8} {a b : Bls.Fp12} (hx : Rep x a) (hy : Rep y b) :
    ∃ out, fp12.Fp12.mul x y = ok out ∧ Rep out (a.mul b) := by
  obtain ⟨v, hv0, hv1, rfl⟩ := hx
  obtain ⟨w, hw0, hw1, rfl⟩ := hy
  obtain ⟨out, hout, rout⟩ := mul_raw
    ⟨fun l => (hv0 l).capped, fun l => (hv1 l).capped⟩
    ⟨fun l => (hw0 l).capped, fun l => (hw1 l).capped⟩
  exact ⟨out, hout, productValues v w,
    fun l => (rout.1 l).boundRep (by change 108 < 256; decide),
    fun l => (rout.2 l).boundRep (by change 108 < 256; decide), product_value v w⟩

end LeanBlsSimd.LaneTower
