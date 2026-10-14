import LeanBlsSimd.Refines.DecompressG2
import LeanBlsSimd.Model.UncompressG1

open Aeneas Aeneas.Std Result
open silver_bls_simd

namespace LeanBlsSimd

def ofG1x8 (a : g1x8.G1x8) : G1x8 := ⟨ofFp8 a.x, ofFp8 a.y, ofFp8 a.z⟩

def toG1x8 (a : G1x8) : g1x8.G1x8 := ⟨toFp8 a.x, toFp8 a.y, toFp8 a.z⟩

namespace G1x8

theorem from_affine_refines (x y : fp8.Fp8) :
    g1x8.G1x8.from_affine x y = ok (toG1x8 (from_affine (ofFp8 x) (ofFp8 y))) := by
  sorry

theorem double_refines (self : g1x8.G1x8) :
    g1x8.G1x8.double self = ok (Prod.map toG1x8 toU8 (ofG1x8 self).double) := by
  sorry

theorem add_affine_refines (self : g1x8.G1x8) (qx qy : fp8.Fp8) :
    g1x8.G1x8.add_affine self qx qy =
      ok (Prod.map toG1x8 toU8 ((ofG1x8 self).add_affine (ofFp8 qx) (ofFp8 qy))) := by
  sorry

theorem add_refines (self q : g1x8.G1x8) :
    g1x8.G1x8.add self q = ok (Prod.map toG1x8 toU8 ((ofG1x8 self).add (ofG1x8 q))) := by
  sorry

theorem is_lower_z_bit_refines (bit : U32) :
    g1x8.is_lower_z_bit bit = ok (is_lower_z_bit bit.val) := by
  sorry

theorem times_z_affine_refines (px py : fp8.Fp8) :
    g1x8.G1x8.times_z_affine px py =
      ok (Prod.map toG1x8 toU8 (times_z_affine (ofFp8 px) (ofFp8 py))) := by
  sorry

theorem times_z_refines (self : g1x8.G1x8) :
    g1x8.G1x8.times_z self = ok (Prod.map toG1x8 toU8 (ofG1x8 self).times_z) := by
  sorry

theorem scott_membership_refines (px py : fp8.Fp8) :
    g1x8.G1x8.scott_membership px py =
      ok (toMembership (scott_membership (ofFp8 px) (ofFp8 py))) := by
  sorry

end G1x8

namespace DecompressG1

def ofBlstP1Affine (a : blst.blst_p1_affine) : BlstP1Affine :=
  ⟨DecompressG2.ofBlstFp a.x, DecompressG2.ofBlstFp a.y⟩

def toBlstP1Affine (p : BlstP1Affine) : blst.blst_p1_affine :=
  ⟨DecompressG2.toBlstFp p.x, DecompressG2.toBlstFp p.y⟩

def toDecoded (d : Decoded) : decompress.Decoded :=
  ⟨toArray (toArray toU64) d.x, toU8 d.larger_root, toU8 d.invalid, toU8 d.undecided⟩

def ofBatch (b : decompress.Batch) : Batch :=
  ⟨ofArray ofBlstP1Affine b.points, ofU8 b.valid, ofU8 b.undecided⟩

def toBatch (b : Batch) : decompress.Batch :=
  ⟨toArray toBlstP1Affine b.points, toU8 b.valid, toU8 b.undecided⟩

theorem decode_refines (inputs : Array (Array U8 48#usize) 8#usize) :
    decompress.decode inputs = ok (toDecoded (decode (ofArray (ofArray ofU8) inputs))) := by
  sorry

theorem point_refines (x y : Array U64 6#usize) :
    decompress.point x y = ok (toBlstP1Affine (point (ofArray ofU64 x) (ofArray ofU64 y))) := by
  sorry

theorem decompress_refines (inputs : Array (Array U8 48#usize) 8#usize) :
    silver_bls_simd.decompress.decompress inputs =
      ok (toBatch (decompress (ofArray (ofArray ofU8) inputs))) := by
  sorry

end DecompressG1

namespace UncompressG1

open DecompressG1

def modelBlst [G1Externals] (bytes : Encoding) : Option BlstP1Affine :=
  (G1Externals.uncompress (toArray toU8 bytes)).map ofBlstP1Affine

theorem chunk_refines [G1Externals] (inputs : Array (Array U8 48#usize) 8#usize)
    (out : Slice (Option blst.blst_p1_affine)) (hlen : out.val.length = 8) :
    ∃ result, silver_bls_simd.decompress_g1_chunk inputs out = ok result ∧
      result.val = ((chunk modelBlst (ofArray (ofArray ofU8) inputs)).toList.map
        (Option.map toBlstP1Affine)) := by
  sorry

theorem uncompress_refines [G1Externals] (inputs : Slice (Array U8 48#usize))
    (out : Slice (Option blst.blst_p1_affine)) (hlen : out.val.length = inputs.val.length) :
    ∃ result, silver_bls_simd.uncompress_in_g1 inputs out = ok result ∧
      result.val = (uncompress G1Externals.simdAvailable modelBlst
        (inputs.val.map (ofArray ofU8))).map (Option.map toBlstP1Affine) := by
  sorry

end UncompressG1
end LeanBlsSimd
