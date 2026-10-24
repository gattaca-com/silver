import LeanBlsSimd.Sha256.Words

open Aeneas Aeneas.Std Result

open private EthLib.Cryptography.Bls.Sha256.bigSigma0 EthLib.Cryptography.Bls.Sha256.bigSigma1
  EthLib.Cryptography.Bls.Sha256.ch EthLib.Cryptography.Bls.Sha256.maj from EthLib.Cryptography.Bls.Sha256

namespace LeanBlsSimd.Sha256.Extensions

def abef (s : Spec.RoundState) : M128 :=
  #v[s.2.2.2.2.2.1,s.2.2.2.2.1,s.2.1,s.1]

def cdgh (s : Spec.RoundState) : M128 :=
  #v[s.2.2.2.2.2.2.2,s.2.2.2.2.2.2.1,s.2.2.2.1,s.2.2.1]

theorem bigSigma0_eq (x : UInt32) : ShaIntrinsics.bigSigma0 x = Spec.bigSigma0 x := rfl
theorem bigSigma1_eq (x : UInt32) : ShaIntrinsics.bigSigma1 x = Spec.bigSigma1 x := rfl
theorem smallSigma0_eq (x : UInt32) : ShaIntrinsics.smallSigma0 x = Spec.smallSigma0 x := rfl
theorem smallSigma1_eq (x : UInt32) : ShaIntrinsics.smallSigma1 x = Spec.smallSigma1 x := rfl
theorem choose_eq (x y z : UInt32) : ShaIntrinsics.choose x y z = Spec.choose x y z := rfl
theorem majority_eq (x y z : UInt32) : ShaIntrinsics.majority x y z = Spec.majority x y z := rfl

attribute [local irreducible] EthLib.Cryptography.Bls.Sha256.bigSigma0
  EthLib.Cryptography.Bls.Sha256.bigSigma1 EthLib.Cryptography.Bls.Sha256.ch EthLib.Cryptography.Bls.Sha256.maj

theorem two_rounds (s : Spec.RoundState) (k0 k1 w0 w1 u v : UInt32) :
    _mm_sha256rnds2_epu32 (cdgh s) (abef s) #v[k0+w0,k1+w1,u,v] =
      abef (Spec.round k1 w1 (Spec.round k0 w0 s)) := by
  rcases s with ⟨a,b,c,d,e,f,g,h⟩
  simp only [abef,cdgh,_mm_sha256rnds2_epu32,Spec.round]
  simp only [bigSigma0_eq,bigSigma1_eq,choose_eq,majority_eq]
  simp only [Vector.getElem_mk,List.getElem_toArray,List.getElem_cons_zero,List.getElem_cons_succ]
  apply Vector.toList_inj.mp
  simp only [Vector.toList_mk]
  have he : Spec.choose e f g + Spec.bigSigma1 e + (k0+w0) + h + d =
      d + (h + Spec.bigSigma1 e + Spec.choose e f g + k0 + w0) := by ac_rfl
  have ha : Spec.choose e f g + Spec.bigSigma1 e + (k0+w0) + h + Spec.majority a b c + Spec.bigSigma0 a =
      h + Spec.bigSigma1 e + Spec.choose e f g + k0 + w0 + (Spec.bigSigma0 a + Spec.majority a b c) := by ac_rfl
  rw [he,ha]
  simp only [List.cons.injEq]
  repeat' constructor
  all_goals ac_rfl


theorem cdgh_two_rounds (s : Spec.RoundState) (k0 k1 w0 w1 : UInt32) :
    cdgh (Spec.round k1 w1 (Spec.round k0 w0 s)) = abef s := by
  rcases s with ⟨a,b,c,d,e,f,g,h⟩
  rfl

theorem shuffle_high (a b c d : UInt32) :
    _mm_shuffle_epi32 0x0e #v[a,b,c,d] = #v[c,d,a,a] := by
  apply Vector.ext
  intro i hi
  interval_cases i <;> rfl

theorem four_rounds (s : Spec.RoundState) (k0 k1 k2 k3 w0 w1 w2 w3 : UInt32) :
    let wk := #v[k0+w0,k1+w1,k2+w2,k3+w3]
    let cdgh' := _mm_sha256rnds2_epu32 (cdgh s) (abef s) wk
    let abef' := _mm_sha256rnds2_epu32 (abef s) cdgh' (_mm_shuffle_epi32 0x0e wk)
    let s' := Spec.round k3 w3 (Spec.round k2 w2 (Spec.round k1 w1 (Spec.round k0 w0 s)))
    (abef',cdgh') = (abef s',cdgh s') := by
  have h0 := two_rounds s k0 k1 w0 w1 (k2+w2) (k3+w3)
  have h1 := two_rounds (Spec.round k1 w1 (Spec.round k0 w0 s)) k2 k3 w2 w3 (k0+w0) (k0+w0)
  rw [cdgh_two_rounds] at h1
  dsimp only
  rw [h0,shuffle_high,h1,cdgh_two_rounds]

end LeanBlsSimd.Sha256.Extensions
