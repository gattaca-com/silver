import LeanBlsSimd.Kzg.Externals
import LeanBlsSimd.Kzg.Extender.Model

open Aeneas Aeneas.Std Result
open EthCryptographySpecs Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender

abbrev Blob := Aeneas.Std.Array U8 131072#usize
abbrev Cells := Aeneas.Std.Array (Aeneas.Std.Array U8 2048#usize) 128#usize

def cellBytes (cells : Cells) : _root_.Array Cell :=
  (cells.val.map arrayBytes).toArray

def Canonical (blob : Blob) : Prop :=
  ∀ i : Fin 4096,
    Fr.bytesBEToNat ((arrayBytes blob).extract (i.val * 32) ((i.val + 1) * 32)) < Fr.modulus

/-- Precomputed constants and scratch sizes; scratch contents may come from any prior call. -/
def StateInvariant (v : cell_extender.CellExtender) : Prop :=
  v.roots.val = (Kzg.Model.roots 12).toList.map frEncode ∧
  v.inverse_roots.val = (Kzg.Model.inverseRoots (Kzg.Model.roots 12)).toList.map frEncode ∧
  v.inverse_size = frEncode (Fr.ofNat 4096).inverse ∧
  v.shift_powers.val = ((Kzg.Model.roots 13).extract 0 4096).toList.map frEncode ∧
  v.evaluations.val.length = 4096 ∧
  v.coefficients.val.length = 4096

end LeanBlsSimd.Kzg.Extender
