import LeanBlsSimd.Kzg.RepresentationLemmas
import LeanBlsSimd.Extracted.Funs

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd
open scoped EthLib.Cryptography.Bls.Fp

namespace LeanBlsSimd.Kzg

def PortableFpRep (raw : portable.fp.Fp) (x : Fp) : Prop :=
  FpReduced ⟨raw⟩ ∧ fpRead ⟨raw⟩ = x

/-- Primitive laws for canonical six-word Montgomery field values. -/
structure PortableFpCorrect [RuntimeFeatures] : Prop where
  add : ∀ {a b : portable.fp.Fp} {x y : Fp},
    PortableFpRep a x → PortableFpRep b y →
    ∃ out, portable.fp.Fp.add a b = ok out ∧ PortableFpRep out (x + y)
  sub : ∀ {a b : portable.fp.Fp} {x y : Fp},
    PortableFpRep a x → PortableFpRep b y →
    ∃ out, portable.fp.Fp.sub a b = ok out ∧ PortableFpRep out (x - y)
  mul : ∀ {a b : portable.fp.Fp} {x y : Fp},
    PortableFpRep a x → PortableFpRep b y →
    ∃ out, portable.fp.Fp.mul a b = ok out ∧ PortableFpRep out (x * y)
  is_zero : ∀ {a : portable.fp.Fp} {x : Fp}, PortableFpRep a x →
    portable.fp.Fp.is_zero a = ok x.isZero

theorem portableFpRep_encode (x : Fp) : PortableFpRep (fpEncode x).l x :=
  ⟨fpEncode_reduced x, fpRead_fpEncode x⟩

theorem portableFpRep_zero : PortableFpRep portable.fp.Fp.ZERO Fp.zero := by
  have h : portable.fp.Fp.ZERO = (fpEncode Fp.zero).l := by
    apply Subtype.ext
    decide +kernel
  rw [h]
  exact portableFpRep_encode _

theorem portableFpRep_one : PortableFpRep portable.constants.ONE Fp.one := by
  have h : portable.constants.ONE = (fpEncode Fp.one).l := by
    apply Subtype.ext
    decide +kernel
  rw [h]
  exact portableFpRep_encode _

theorem PortableFpCorrect.square [RuntimeFeatures] (h : PortableFpCorrect)
    {a : portable.fp.Fp} {x : Fp} (ha : PortableFpRep a x) :
    ∃ out, portable.fp.Fp.square a = ok out ∧ PortableFpRep out (x * x) :=
  h.mul ha ha

theorem PortableFpCorrect.double [RuntimeFeatures] (h : PortableFpCorrect)
    {a : portable.fp.Fp} {x : Fp} (ha : PortableFpRep a x) :
    ∃ out, portable.fp.Fp.double a = ok out ∧ PortableFpRep out (x + x) :=
  h.add ha ha

theorem PortableFpCorrect.neg [RuntimeFeatures] (h : PortableFpCorrect)
    {a : portable.fp.Fp} {x : Fp} (ha : PortableFpRep a x) :
    ∃ out, portable.fp.Fp.neg a = ok out ∧ PortableFpRep out (-x) := by
  obtain ⟨out, he, hr⟩ := h.sub portableFpRep_zero ha
  exact ⟨out, he, by simpa only [show Fp.zero = (0 : Fp) from rfl, zero_sub] using hr⟩

end LeanBlsSimd.Kzg
