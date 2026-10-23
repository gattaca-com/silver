import LeanBlsSimd.Kzg.Extender.WriteStep

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender

theorem arrayBytes_size {n : Usize} (xs : Aeneas.Std.Array U8 n) :
    (arrayBytes xs).size = n.val := by
  simp [arrayBytes, bytes, ByteArray.size, xs.property]

theorem arrayBytes_get {n : Usize} (xs : Aeneas.Std.Array U8 n)
    (i : Nat) (hi : i < n.val) :
    (arrayBytes xs)[i]! = UInt8.ofBitVec xs.val[i]!.bv := by
  have hl : i < xs.val.length := by simpa only [xs.property] using hi
  rw [getElem!_pos (arrayBytes xs) i (by rw [arrayBytes_size]; exact hi)]
  simp [arrayBytes, bytes, ByteArray.getElem_eq_getElem_data, List.getElem?_eq_getElem hl]

theorem storeChunk_first (cells : Cells) (j k : Nat)
    (bs : Aeneas.Std.Array U8 32#usize) (hk : k < 64) :
    (storeChunk cells j bs).val[k]! = cells.val[k]! := by
  exact List.getElem!_set_ne _ _ _ _ (by omega)

theorem storeChunk_current (cells : Cells) (j b : Nat) (hj : j < 4096)
    (bs : Aeneas.Std.Array U8 32#usize) (hb : b < 32) :
    (arrayBytes (storeChunk cells j bs).val[64+j/64]!)[(j%64)*32+b]! =
      (arrayBytes bs)[b]! := by
  have hc : 64+j/64 < cells.val.length := by
    simp only [cells.property, UScalar.ofNatCore_val_eq]; omega
  have hat : (j%64)*32+b < 2048 := by omega
  change (arrayBytes ((cells.val.set (64+j/64) _)[64+j/64]!))[_]! = _
  rw [List.getElem!_set _ _ _ hc, arrayBytes_get _ _ hat, arrayBytes_get bs b hb]
  apply congrArg (fun x : U8 => UInt8.ofBitVec x.bv)
  change (cells.val[64+j/64]!.val.setSlice! ((j%64)*32) bs.val)[(j%64)*32+b]! = bs.val[b]!
  rw [List.getElem!_setSlice!_middle cells.val[64+j/64]!.val bs.val
    ((j%64)*32) ((j%64)*32+b) (by
      simp only [bs.property, cells.val[64+j/64]!.property, UScalar.ofNatCore_val_eq]
      omega)]
  simp only [Nat.add_sub_cancel_left]

theorem storeChunk_previous (cells : Cells) (j i b : Nat) (hj : j < 4096)
    (hi : i < j) (bs : Aeneas.Std.Array U8 32#usize) (hb : b < 32) :
    (arrayBytes (storeChunk cells j bs).val[64+i/64]!)[(i%64)*32+b]! =
      (arrayBytes cells.val[64+i/64]!)[(i%64)*32+b]! := by
  by_cases he : i/64 = j/64
  · have hc : 64+j/64 < cells.val.length := by
      simp only [cells.property, UScalar.ofNatCore_val_eq]; omega
    have hat : (i%64)*32+b < 2048 := by omega
    change (arrayBytes ((cells.val.set (64+j/64) _)[64+i/64]!))[_]! = _
    rw [he, List.getElem!_set _ _ _ hc,
      arrayBytes_get _ _ hat, arrayBytes_get _ _ hat]
    apply congrArg (fun x : U8 => UInt8.ofBitVec x.bv)
    exact List.getElem!_setSlice!_prefix cells.val[64+j/64]!.val bs.val
      ((j%64)*32) ((i%64)*32+b) (by omega)
  · have hne : 64+j/64 ≠ 64+i/64 := by omega
    change (arrayBytes ((cells.val.set (64+j/64) _)[64+i/64]!))[_]! = _
    rw [List.getElem!_set_ne cells.val (64+j/64) (64+i/64) _ (by omega)]

def Written (values : _root_.Array Fr) (initial : Cells) (n : Nat) (cells : Cells) : Prop :=
  (∀ k, k < 64 → cells.val[k]! = initial.val[k]!) ∧
  ∀ j, j < n → ∀ b, b < 32 →
    (arrayBytes cells.val[64+j/64]!)[(j%64)*32+b]! =
      (blsFieldToBytes values[rev j]!)[b]!

theorem Written.step (values : _root_.Array Fr) (initial cells : Cells) (j : Nat)
    (hj : j < 4096) (hw : Written values initial j cells)
    (bs : Aeneas.Std.Array U8 32#usize)
    (hbs : arrayBytes bs = blsFieldToBytes values[rev j]!) :
    Written values initial (j+1) (storeChunk cells j bs) := by
  constructor
  · intro k hk
    exact (storeChunk_first cells j k bs hk).trans (hw.1 k hk)
  · intro i hi b hb
    by_cases he : i = j
    · subst i
      rw [storeChunk_current cells j b hj bs hb, hbs]
    · rw [storeChunk_previous cells j i b hj (by omega) bs hb]
      exact hw.2 i (by omega) b hb

end LeanBlsSimd.Kzg.Extender
