import LeanBlsSimd.Refines.Basic
import LeanBlsSimd.Spec.Sha256

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open private EthLib.Cryptography.Bls.Sha256.rotr
  EthLib.Cryptography.Bls.Sha256.ch EthLib.Cryptography.Bls.Sha256.maj
  EthLib.Cryptography.Bls.Sha256.bigSigma0 EthLib.Cryptography.Bls.Sha256.bigSigma1
  EthLib.Cryptography.Bls.Sha256.smallSigma0 EthLib.Cryptography.Bls.Sha256.smallSigma1
  from EthLib.Cryptography.Bls.Sha256

namespace LeanBlsSimd.Sha256

def word (x : UInt32) : U32 := ⟨x.toBitVec⟩
def ofWord (x : U32) : UInt32 := UInt32.ofBitVec x.bv

@[simp] theorem ofWord_word (x : UInt32) : ofWord (word x) = x := rfl
@[simp] theorem word_ofWord (x : U32) : word (ofWord x) = x := rfl

theorem wrapping_add_word (x y : UInt32) :
    core.num.U32.wrapping_add (word x) (word y) = word (x+y) := rfl

def words {n : Usize} (a : Array U32 n) : _root_.Array UInt32 :=
  (a.val.map ofWord).toArray

@[simp] theorem words_size {n : Usize} (a : Array U32 n) :
    (words a).size = n.val := by simp [words,a.property]

theorem words_get {n : Usize} (a : Array U32 n) (i : Nat) (hi : i < n.val) :
    (words a)[i]! = ofWord (a.val[i]'(by rw [a.property]; exact hi)) := by
  rw [getElem!_pos (words a) i (by simpa using hi)]
  simp [words]

theorem words_set {n : Usize} (a : Array U32 n) (i : Usize) (x : U32) :
    words (a.set i x) = (words a).set! i.val (ofWord x) := by
  apply _root_.Array.toList_inj.mp
  simp [words,List.map_set]

namespace Portable

theorem choose_refines (x y z : UInt32) :
    sha256.portable.ch (word x) (word y) (word z) = ok (word (Spec.choose x y z)) := rfl

theorem majority_refines (x y z : UInt32) :
    sha256.portable.maj (word x) (word y) (word z) = ok (word (Spec.majority x y z)) := rfl

theorem bigSigma0_refines (x : UInt32) :
    sha256.portable.big_sigma0 (word x) = ok (word (Spec.bigSigma0 x)) := by
  change ok (⟨(x.toBitVec.rotateRight 2 ^^^ x.toBitVec.rotateRight 13) ^^^ x.toBitVec.rotateRight 22⟩ : U32) = _
  simp only [BitVec.rotateRight_def]
  rfl

theorem bigSigma1_refines (x : UInt32) :
    sha256.portable.big_sigma1 (word x) = ok (word (Spec.bigSigma1 x)) := by
  change ok (⟨(x.toBitVec.rotateRight 6 ^^^ x.toBitVec.rotateRight 11) ^^^ x.toBitVec.rotateRight 25⟩ : U32) = _
  simp only [BitVec.rotateRight_def]
  rfl

theorem smallSigma0_refines (x : UInt32) :
    sha256.portable.small_sigma0 (word x) = ok (word (Spec.smallSigma0 x)) := by
  change ok (⟨(x.toBitVec.rotateRight 7 ^^^ x.toBitVec.rotateRight 18) ^^^ (x.toBitVec >>> 3)⟩ : U32) = _
  simp only [BitVec.rotateRight_def]
  rfl

theorem smallSigma1_refines (x : UInt32) :
    sha256.portable.small_sigma1 (word x) = ok (word (Spec.smallSigma1 x)) := by
  change ok (⟨(x.toBitVec.rotateRight 17 ^^^ x.toBitVec.rotateRight 19) ^^^ (x.toBitVec >>> 10)⟩ : U32) = _
  simp only [BitVec.rotateRight_def]
  rfl

end Portable
end LeanBlsSimd.Sha256
