import LeanBlsSimd.Kzg.Extender.Kernel.Basic

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg
open scoped EthLib.Cryptography.Bls.Fr

attribute [-instance] Lean.Grind.Fin.instHPowFinNatOfNeZero
attribute [-instance] Lean.Grind.Fin.instPowFinNatOfNeZero

namespace LeanBlsSimd.Kzg.InterpolationKernel

open Extender.Kernel

theorem vectors_per_cell_eq : interpolation_kernel.VECTORS_PER_CELL = ok 8#usize := by
  unfold interpolation_kernel.VECTORS_PER_CELL FIELD_ELEMENTS_PER_CELL fr8.LANES
  rfl

theorem bytes_per_vector_eq : interpolation_kernel.BYTES_PER_VECTOR = ok 256#usize := by
  unfold interpolation_kernel.BYTES_PER_VECTOR fr8.LANES BYTES_PER_FIELD_ELEMENT
  have h : (256 : Nat) < 2 ^ UScalarTy.Usize.numBits := by scalar_tac
  change 256 < 2 ^ System.Platform.numBits at h
  change UScalar.tryMk .Usize 256 = ok 256#usize
  simp [UScalar.tryMk, UScalar.tryMkOpt, h, Result.ofOption]

def shiftFactor (column coefficient : Nat) : Fr :=
  (Fr.ofNat 64).inverse * (Model.cosetShift column).inverse ^ coefficient

def StateInvariant (kernel : interpolation_kernel.InterpolationKernel) : Prop :=
  FftInvariant kernel.inverse (Model.inverseRoots (Model.roots 6)) ∧
  kernel.shift.val.length = 1024 ∧ kernel.columns.val.length = 1024 ∧
  kernel.used.val.length = 128 ∧
  ∀ (column : Fin 128) (v : Fin 8),
    MultiplierRep kernel.shift.val[column.val * 8 + v.val]!
      (fun lane => shiftFactor column.val (8 * v.val + lane.val))

def SameTables (before after : interpolation_kernel.InterpolationKernel) : Prop :=
  after.inverse = before.inverse ∧ after.shift = before.shift

def CellRep (cell : Array U8 2048#usize) (values : _root_.Array Fr) : Prop :=
  values.size = 64 ∧ ∀ j : Fin 64,
    (bytesToBlsField ((arrayBytes cell).extract (32 * j.val) (32 * (j.val + 1)))).toOption =
      some values[j.val]!

def CellsRep (cells : Slice (Array U8 2048#usize))
    (values : _root_.Array (_root_.Array Fr)) : Prop :=
  cells.val.length = values.size ∧
  ∀ k : Fin cells.val.length, CellRep cells.val[k.val] values[k.val]!

end LeanBlsSimd.Kzg.InterpolationKernel
