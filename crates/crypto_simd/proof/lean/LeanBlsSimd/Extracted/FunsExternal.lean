import Aeneas
import LeanBlsSimd.Extracted.Types
import LeanBlsSimd.Model.Intrinsics
open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls

def Aeneas.Std.alloc.vec.Vec.clear (_Allocator : Type) {α : Type} (_ : alloc.vec.Vec α) :
    Result (alloc.vec.Vec α) :=
  ok ⟨[], by simp⟩

def Aeneas.Std.alloc.vec.Vec.is_empty (_Allocator : Type) {α : Type}
    (v : alloc.vec.Vec α) : Result Bool :=
  ok v.val.isEmpty

/-- External observations supplied to the generated BLS APIs. -/
class silver_crypto_simd.bls.BlsExternals where
  simdAvailable : Bool
  uncompressG1 : Array Std.U8 48#usize → Option blst.blst_p1_affine
  uncompressG2 : Array Std.U8 96#usize → Option blst.blst_p2_affine

class silver_crypto_simd.kzg.KzgExternals extends BlsExternals where
  frFromBytes : Array U8 32#usize → Result (Option blst.blst_fr)
  frToBytes : blst.blst_fr → Result (Array U8 32#usize)
  frFromU64 : U64 → Result blst.blst_fr
  frAdd : blst.blst_fr → blst.blst_fr → Result blst.blst_fr
  frSub : blst.blst_fr → blst.blst_fr → Result blst.blst_fr
  frMul : blst.blst_fr → blst.blst_fr → Result blst.blst_fr
  frInverse : blst.blst_fr → Result blst.blst_fr
  hashToFr : Slice U8 → Result blst.blst_fr
  g1ToAffine : blst.blst_p1 → Result blst.blst_p1_affine
  g1Add : blst.blst_p1 → blst.blst_p1 → Result blst.blst_p1
  g1Neg : blst.blst_p1 → Result blst.blst_p1
  g2Neg : blst.blst_p2_affine → Result blst.blst_p2_affine
  g1Lincomb : Slice blst.blst_p1_affine → Slice blst.blst_fr → kzg.blst_ops.LincombScratch →
    Result (blst.blst_p1 × kzg.blst_ops.LincombScratch)
  pairingCheck : blst.blst_p1_affine → blst.blst_p2_affine →
    blst.blst_p1_affine → blst.blst_p2_affine → Result Bool

def silver_crypto_simd.ifma_available [BlsExternals] : Result Bool :=
  ok BlsExternals.simdAvailable

def silver_crypto_simd.bls.uncompress_in_g1_blst [BlsExternals]
    (bytes : Array Std.U8 48#usize) : Result (Option blst.blst_p1_affine) :=
  ok (BlsExternals.uncompressG1 bytes)

def silver_crypto_simd.bls.uncompress_in_g2_blst [BlsExternals]
    (bytes : Array Std.U8 96#usize) : Result (Option blst.blst_p2_affine) :=
  ok (BlsExternals.uncompressG2 bytes)

def blst.blst_p1_affine.Insts.CoreDefaultDefault.default : Result blst.blst_p1_affine :=
  let fp : blst.blst_fp := { l := Array.repeat 6#usize 0#u64 }
  ok { x := fp, y := fp }

/-!
Handwritten definitions for functions that Aeneas leaves external. The starting template is
`FunsExternal_Template.lean`, generated beside `Funs.lean`; `extract.sh` preserves this file.

Each intrinsic wraps the corresponding `Model/Intrinsics.lean` operation in `ok`. Conversions
between Aeneas integers and Lean's fixed-width integers preserve their bit vectors.
-/

/-- [core::core_arch::x86::avx512f::_mm512_add_epi64]:
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/x86/avx512f.rs', lines 779:0-779:64
    Name pattern: [core::core_arch::x86::avx512f::_mm512_add_epi64]
    Visibility: public -/
@[rust_fun "core::core_arch::x86::avx512f::_mm512_add_epi64"]
def core.core_arch.x86.avx512f._mm512_add_epi64 (a b : core.core_arch.x86.__m512i) :
    Result core.core_arch.x86.__m512i :=
  ok (LeanBlsSimd._mm512_add_epi64 a b)

/-- [core::core_arch::x86::avx512f::_mm512_sub_epi64]:
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/x86/avx512f.rs', lines 1187:0-1187:64
    Name pattern: [core::core_arch::x86::avx512f::_mm512_sub_epi64]
    Visibility: public -/
@[rust_fun "core::core_arch::x86::avx512f::_mm512_sub_epi64"]
def core.core_arch.x86.avx512f._mm512_sub_epi64 (a b : core.core_arch.x86.__m512i) :
    Result core.core_arch.x86.__m512i :=
  ok (LeanBlsSimd._mm512_sub_epi64 a b)

/-- [core::core_arch::x86::avx512f::_mm512_setzero_si512]:
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/x86/avx512f.rs', lines 16684:0-16684:46
    Name pattern: [core::core_arch::x86::avx512f::_mm512_setzero_si512]
    Visibility: public -/
@[rust_fun "core::core_arch::x86::avx512f::_mm512_setzero_si512"]
def core.core_arch.x86.avx512f._mm512_setzero_si512 : Result core.core_arch.x86.__m512i :=
  ok LeanBlsSimd._mm512_setzero_si512

/-- [core::core_arch::x86::avx512f::_mm512_set_epi64]:
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/x86/avx512f.rs', lines 16943:0-16952:12
    Name pattern: [core::core_arch::x86::avx512f::_mm512_set_epi64]
    Visibility: public -/
@[rust_fun "core::core_arch::x86::avx512f::_mm512_set_epi64"]
def core.core_arch.x86.avx512f._mm512_set_epi64 (e7 e6 e5 e4 e3 e2 e1 e0 : Std.I64) :
    Result core.core_arch.x86.__m512i :=
  ok (LeanBlsSimd._mm512_set_epi64 (Int64.ofBitVec e7.bv) (Int64.ofBitVec e6.bv)
    (Int64.ofBitVec e5.bv) (Int64.ofBitVec e4.bv) (Int64.ofBitVec e3.bv) (Int64.ofBitVec e2.bv)
    (Int64.ofBitVec e1.bv) (Int64.ofBitVec e0.bv))

/-- [core::core_arch::x86::avx512f::_mm512_srli_epi64]:
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/x86/avx512f.rs', lines 20499:0-20499:70
    Name pattern: [core::core_arch::x86::avx512f::_mm512_srli_epi64]
    Visibility: public -/
@[rust_fun "core::core_arch::x86::avx512f::_mm512_srli_epi64"]
def core.core_arch.x86.avx512f._mm512_srli_epi64 (IMM8 : Std.U32) (a : core.core_arch.x86.__m512i) :
    Result core.core_arch.x86.__m512i :=
  ok (LeanBlsSimd._mm512_srli_epi64 IMM8.bv.toNat a)

/-- [core::core_arch::x86::avx512f::_mm512_slli_epi64]:
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/x86/avx512f.rs', lines 19969:0-19969:70
    Name pattern: [core::core_arch::x86::avx512f::_mm512_slli_epi64]
    Visibility: public -/
@[rust_fun "core::core_arch::x86::avx512f::_mm512_slli_epi64"]
def core.core_arch.x86.avx512f._mm512_slli_epi64 (IMM8 : Std.U32) (a : core.core_arch.x86.__m512i) :
    Result core.core_arch.x86.__m512i :=
  ok (LeanBlsSimd._mm512_slli_epi64 IMM8.bv.toNat a)

/-- [core::core_arch::x86::avx512f::_mm512_srai_epi64]:
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/x86/avx512f.rs', lines 21375:0-21375:70
    Name pattern: [core::core_arch::x86::avx512f::_mm512_srai_epi64]
    Visibility: public -/
@[rust_fun "core::core_arch::x86::avx512f::_mm512_srai_epi64"]
def core.core_arch.x86.avx512f._mm512_srai_epi64 (IMM8 : Std.U32) (a : core.core_arch.x86.__m512i) :
    Result core.core_arch.x86.__m512i :=
  ok (LeanBlsSimd._mm512_srai_epi64 IMM8.bv.toNat a)

/-- [core::core_arch::x86::avx512f::_mm512_mask_blend_epi64]:
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/x86/avx512f.rs', lines 28757:0-28757:84
    Name pattern: [core::core_arch::x86::avx512f::_mm512_mask_blend_epi64]
    Visibility: public -/
@[rust_fun "core::core_arch::x86::avx512f::_mm512_mask_blend_epi64"]
def core.core_arch.x86.avx512f._mm512_mask_blend_epi64 (k : Std.U8)
    (a b : core.core_arch.x86.__m512i) : Result core.core_arch.x86.__m512i :=
  ok (LeanBlsSimd._mm512_mask_blend_epi64 (UInt8.ofBitVec k.bv) a b)

/-- [core::core_arch::x86::avx512f::_mm512_permutex2var_epi64]:
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/x86/avx512f.rs', lines 24132:0-24132:81
    Name pattern: [core::core_arch::x86::avx512f::_mm512_permutex2var_epi64]
    Visibility: public -/
@[rust_fun "core::core_arch::x86::avx512f::_mm512_permutex2var_epi64"]
def core.core_arch.x86.avx512f._mm512_permutex2var_epi64
    (a index b : core.core_arch.x86.__m512i) : Result core.core_arch.x86.__m512i :=
  ok (LeanBlsSimd._mm512_permutex2var_epi64 a index b)

/-- [core::core_arch::x86::avx512f::_mm512_and_si512]:
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/x86/avx512f.rs', lines 29551:0-29551:64
    Name pattern: [core::core_arch::x86::avx512f::_mm512_and_si512]
    Visibility: public -/
@[rust_fun "core::core_arch::x86::avx512f::_mm512_and_si512"]
def core.core_arch.x86.avx512f._mm512_and_si512 (a b : core.core_arch.x86.__m512i) :
    Result core.core_arch.x86.__m512i :=
  ok (LeanBlsSimd._mm512_and_si512 a b)

/-- [core::core_arch::x86::avx512f::_mm512_set1_epi64]:
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/x86/avx512f.rs', lines 31330:0-31330:49
    Name pattern: [core::core_arch::x86::avx512f::_mm512_set1_epi64]
    Visibility: public -/
@[rust_fun "core::core_arch::x86::avx512f::_mm512_set1_epi64"]
def core.core_arch.x86.avx512f._mm512_set1_epi64 (a : Std.I64) :
    Result core.core_arch.x86.__m512i :=
  ok (LeanBlsSimd._mm512_set1_epi64 (Int64.ofBitVec a.bv))

/-- [core::core_arch::x86::avx512f::_mm512_cmpeq_epi64_mask]:
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/x86/avx512f.rs', lines 34423:0-34423:72
    Name pattern: [core::core_arch::x86::avx512f::_mm512_cmpeq_epi64_mask]
    Visibility: public -/
@[rust_fun "core::core_arch::x86::avx512f::_mm512_cmpeq_epi64_mask"]
def core.core_arch.x86.avx512f._mm512_cmpeq_epi64_mask (a b : core.core_arch.x86.__m512i) :
    Result Std.U8 :=
  ok ⟨(LeanBlsSimd._mm512_cmpeq_epi64_mask a b).toBitVec⟩

/-- [core::core_arch::x86::avx512ifma::_mm512_madd52hi_epu64]:
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/x86/avx512ifma.rs', lines 18:0-18:75
    Name pattern: [core::core_arch::x86::avx512ifma::_mm512_madd52hi_epu64]
    Visibility: public -/
@[rust_fun "core::core_arch::x86::avx512ifma::_mm512_madd52hi_epu64"]
def core.core_arch.x86.avx512ifma._mm512_madd52hi_epu64 (a b c : core.core_arch.x86.__m512i) :
    Result core.core_arch.x86.__m512i :=
  ok (LeanBlsSimd._mm512_madd52hi_epu64 a b c)

/-- [core::core_arch::x86::avx512ifma::_mm512_madd52lo_epu64]:
    Source: '/rustc/library/core/src/../../stdarch/crates/core_arch/src/x86/avx512ifma.rs', lines 65:0-65:75
    Name pattern: [core::core_arch::x86::avx512ifma::_mm512_madd52lo_epu64]
    Visibility: public -/
@[rust_fun "core::core_arch::x86::avx512ifma::_mm512_madd52lo_epu64"]
def core.core_arch.x86.avx512ifma._mm512_madd52lo_epu64 (a b c : core.core_arch.x86.__m512i) :
    Result core.core_arch.x86.__m512i :=
  ok (LeanBlsSimd._mm512_madd52lo_epu64 a b c)

/-- [blst::{core::default::Default for blst::blst_p2_affine}::default]:
    Source: '/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/blst-0.3.16/src/bindings.rs', lines 634:16-634:23
    Name pattern: [blst::{core::default::Default<blst::blst_p2_affine>}::default]
    Visibility: public -/
@[rust_fun "blst::{core::default::Default<blst::blst_p2_affine>}::default"]
def blst.blst_p2_affine.Insts.CoreDefaultDefault.default : Result blst.blst_p2_affine :=
  -- `#[derive(Default)]` on `blst_p2_affine`, `blst_fp2` and `blst_fp`: every limb is 0.
  let fp2 : blst.blst_fp2 := { fp := Array.repeat 2#usize { l := Array.repeat 6#usize 0#u64 } }
  ok { x := fp2, y := fp2 }

/-- [silver_crypto_simd::bls::fp8::lanes]:
    Source: 'crates/crypto_simd/src/bls/fp8.rs', lines 50:0-54:1 -/
def silver_crypto_simd.bls.fp8.lanes (v : core.core_arch.x86.__m512i) : Result (Array Std.U64 8#usize) :=
  -- A `transmute`: element `l` of the array is lane `l` of `v`.
  ok ⟨v.toList.map fun x => ⟨x.toBitVec⟩, by simp⟩

namespace silver_crypto_simd

def kzg.blst_ops.fr_from_bytes [kzg.KzgExternals] := kzg.KzgExternals.frFromBytes
def kzg.blst_ops.fr_to_bytes [kzg.KzgExternals] := kzg.KzgExternals.frToBytes
def kzg.blst_ops.fr_from_u64 [kzg.KzgExternals] := kzg.KzgExternals.frFromU64
def kzg.blst_ops.fr_add [kzg.KzgExternals] := kzg.KzgExternals.frAdd
def kzg.blst_ops.fr_sub [kzg.KzgExternals] := kzg.KzgExternals.frSub
def kzg.blst_ops.fr_mul [kzg.KzgExternals] := kzg.KzgExternals.frMul
def kzg.blst_ops.fr_inverse [kzg.KzgExternals] := kzg.KzgExternals.frInverse
def kzg.blst_ops.hash_to_fr [kzg.KzgExternals] := kzg.KzgExternals.hashToFr
def kzg.blst_ops.g1_to_affine [kzg.KzgExternals] := kzg.KzgExternals.g1ToAffine
def kzg.blst_ops.g1_add [kzg.KzgExternals] := kzg.KzgExternals.g1Add
def kzg.blst_ops.g1_neg [kzg.KzgExternals] := kzg.KzgExternals.g1Neg
def kzg.blst_ops.g2_neg [kzg.KzgExternals] := kzg.KzgExternals.g2Neg
def kzg.blst_ops.g1_lincomb [kzg.KzgExternals] := kzg.KzgExternals.g1Lincomb
def kzg.blst_ops.pairing_check [kzg.KzgExternals] := kzg.KzgExternals.pairingCheck

def U32.Insts.CoreIterRangeStep.backward_checked (a : Std.U32) (n : Usize) :
    Result (Option Std.U32) :=
  ok (if n.val ≤ a.val then some ⟨BitVec.ofNat 32 (a.val - n.val)⟩ else none)

def U32.Insts.CoreIterRangeStep.forward_checked (a : Std.U32) (n : Usize) :
    Result (Option Std.U32) :=
  ok (if a.val + n.val < 2^32 then some ⟨BitVec.ofNat 32 (a.val + n.val)⟩ else none)

def U32.Insts.CoreIterRangeStep.steps_between (a b : Std.U32) :
    Result (Usize × Option Usize) :=
  ok (if a.val ≤ b.val then
    (⟨BitVec.ofNat _ (b.val - a.val)⟩, some ⟨BitVec.ofNat _ (b.val - a.val)⟩)
    else (0#usize, none))

def core.option.Option.Insts.CoreCloneClone.clone {T : Type} (inst : core.clone.Clone T)
    (x : Option T) : Result (Option T) :=
  match x with
  | none => ok none
  | some a => inst.clone a >>= fun b => ok (some b)

def alloc.vec.Vec.Insts.CoreDefaultDefault.default (T : Type) : Result (alloc.vec.Vec T) :=
  ok (alloc.vec.Vec.new T)

def blst.blst_fr.Insts.CoreCloneClone.clone (x : blst.blst_fr) : Result blst.blst_fr := ok x
def blst.blst_p1_affine.Insts.CoreCloneClone.clone (x : blst.blst_p1_affine) :
    Result blst.blst_p1_affine := ok x

end silver_crypto_simd
