import LeanBlsSimd.Kzg.SetupPoints

open Aeneas Aeneas.Std
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Kzg.SetupLiterals

set_option exponentiation.threshold 512
set_option maxRecDepth 16000
set_option maxHeartbeats 2000000

local instance {α : Type} [DecidableEq α] (n : Usize) : DecidableEq (Array α n) := fun a b =>
  decidable_of_iff (a.val = b.val) ⟨Subtype.ext,congrArg Subtype.val⟩

local instance : DecidableEq blst.blst_fp := fun a b =>
  decidable_of_iff (a.l = b.l) (by cases a; cases b; simp)
local instance : DecidableEq blst.blst_fp2 := fun a b =>
  decidable_of_iff (a.fp = b.fp) (by cases a; cases b; simp)
local instance : DecidableEq blst.blst_p2_affine := fun a b =>
  decidable_of_iff (a.x = b.x ∧ a.y = b.y) (by cases a; cases b; simp)

-- The test-only Rust G2 literals in src/kzg/setup.rs are absent from extraction.
def g2_s_pow_cell : blst.blst_p2_affine :=
  { x := { fp := Array.make 2#usize [
      { l := Array.make 6#usize [0xc0b3d27b16a3640b#u64, 0xace3fa1ffc86682b#u64, 0x533831bb8af82f36#u64, 0xb04049d0baad5520#u64, 0xb7b7a0cd6e353592#u64, 0x105956acf773013b#u64] (by rfl) },
      { l := Array.make 6#usize [0x400a96a17290e706#u64, 0x2d92fc169e6085d6#u64, 0xcb48449e82fd9627#u64, 0x6463852ef6e582a0#u64, 0xd1c38da04c0f254a#u64, 0x13d2c8b4b80b8f54#u64] (by rfl) }] (by rfl) },
    y := { fp := Array.make 2#usize [
      { l := Array.make 6#usize [0xa14dd902d0c036fc#u64, 0xaa16b4532ce039d2#u64, 0xc9a38eb6477d2ee3#u64, 0x94060859ee3b25f2#u64, 0x911ea5483e24cadf#u64, 0x1268d588701c449f#u64] (by rfl) },
      { l := Array.make 6#usize [0x1e1d07b20f3a0b68#u64, 0x5d6d22b125cc5716#u64, 0xb7c8bda9efe3655d#u64, 0xaa4032886c427640#u64, 0x880cb9e55b9b2304#u64, 0x15fcee3b528d2639#u64] (by rfl) }] (by rfl) } }

def g2_neg_generator : blst.blst_p2_affine :=
  { x := { fp := Array.make 2#usize [
      { l := Array.make 6#usize [0xf5f28fa202940a10#u64, 0xb3f5fb2687b4961a#u64, 0xa1a893b53e2ae580#u64, 0x9894999d1a3caee9#u64, 0x6f67b7631863366b#u64, 0x058191924350bcd7#u64] (by rfl) },
      { l := Array.make 6#usize [0xa5a9c0759e23f606#u64, 0xaaa0c59dbccd60c3#u64, 0x3bb17e18e2867806#u64, 0x1b1ab6cc8541b367#u64, 0xc2b6ed0ef2158547#u64, 0x11922a097360edf3#u64] (by rfl) }] (by rfl) },
    y := { fp := Array.make 2#usize [
      { l := Array.make 6#usize [0x6d8bf5079fb65e61#u64, 0xc52f05df531d63a5#u64, 0x7f4a4d344ca692c9#u64, 0xa887959b8577c95f#u64, 0x4347fe40525c8734#u64, 0x197d145bbaff0bb5#u64] (by rfl) },
      { l := Array.make 6#usize [0x0c3e036d209afa4e#u64, 0x0601d8f4863f9e23#u64, 0xe0832636bacc0a84#u64, 0xeb2def362a476f84#u64, 0x64044f659f0ee1e9#u64, 0x0ed54f48d5a1caa7#u64] (by rfl) }] (by rfl) } }

theorem g2_s_pow_cell_eq : g2_s_pow_cell = g2Affine SetupPoints.g2Point64 := by
  decide +kernel

theorem g2_neg_generator_eq : g2_neg_generator = g2Affine (G2.neg SetupPoints.g2Point0) := by
  decide +kernel

end LeanBlsSimd.Kzg.SetupLiterals
