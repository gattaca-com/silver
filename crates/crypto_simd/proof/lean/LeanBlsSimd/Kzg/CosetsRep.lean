import LeanBlsSimd.Kzg.Model
import LeanBlsSimd.Kzg.Representation

open Aeneas.Std
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg

def CosetsRep (c : cosets.Cosets) : Prop :=
  c.inverse_roots.val = ((Model.inverseRoots (Model.roots 6)).toList.map frEncode) ∧
  c.inverse_size = frEncode (Fr.ofNat 64).inverse ∧
  c.shift_inverse.val = (List.range 128).map (fun i => frEncode (Model.cosetShift i).inverse) ∧
  c.shift_pow_cell.val = (List.range 128).map (fun i => frEncode (Fr.powNat (Model.cosetShift i) 64))

end LeanBlsSimd.Kzg
