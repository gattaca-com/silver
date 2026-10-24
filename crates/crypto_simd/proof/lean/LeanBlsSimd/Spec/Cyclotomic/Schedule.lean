import LeanBlsSimd.Spec.Cyclotomic.Tower

namespace LeanBlsSimd.Cyclotomic.Schedule
variable {R : Type*} [CommRing R]

structure Coeffs (R : Type*) where
  c00 : R
  c01 : R
  c02 : R
  c10 : R
  c11 : R
  c12 : R

/-- The operations and permutations of portable/fp12.rs, before word representation. -/
def fp4Square (xi a b : R) : R × R :=
  let s0 := a*a
  let s1 := b*b
  (s0 + xi*s1, (a+b)*(a+b)-s0-s1)

def less (t a : R) := (t-a)+(t-a)+t
def plus (t a : R) := (t+a)+(t+a)+t

def raw (xi : R) (x : Coeffs R) : Coeffs R :=
  let t0 := fp4Square xi x.c00 x.c11
  let t1 := fp4Square xi x.c10 x.c02
  let t2 := fp4Square xi x.c01 x.c12
  ⟨less t0.1 x.c00, less t1.1 x.c01, less t2.1 x.c02,
    plus (xi*t2.2) x.c10, plus t0.2 x.c11, plus t1.2 x.c12⟩

abbrev Q (xi : R) := QuadraticAlgebra R xi 0
noncomputable abbrev omega (xi : R) : Q xi := QuadraticAlgebra.omega

def ca (xi : R) (x : Coeffs R) : Q xi := ⟨x.c00,x.c11⟩
def cb (xi : R) (x : Coeffs R) : Q xi := ⟨x.c10,x.c02⟩
def cc (xi : R) (x : Coeffs R) : Q xi := ⟨x.c01,x.c12⟩
noncomputable def decode (xi : R) (x : Coeffs R) := assemble (omega xi) (ca xi x) (cb xi x) (cc xi x)

theorem raw_a (xi : R) (x : Coeffs R) :
    ca xi (raw xi x) = 3*(ca xi x)^2 - 2*star (ca xi x) := by
  have h2 : (2 : Q xi) = ⟨2,0⟩ := rfl
  have h3 : (3 : Q xi) = ⟨3,0⟩ := rfl
  rw [h2,h3]
  ext <;> simp [ca,raw,fp4Square,less,plus,pow_two,QuadraticAlgebra.star_mk] <;> ring

theorem raw_b (xi : R) (x : Coeffs R) :
    cb xi (raw xi x) = 3*omega xi*(cc xi x)^2 + 2*star (cb xi x) := by
  have h2 : (2 : Q xi) = ⟨2,0⟩ := rfl
  have h3 : (3 : Q xi) = ⟨3,0⟩ := rfl
  rw [h2,h3]
  ext <;> simp [cb,cc,raw,fp4Square,less,plus,pow_two,QuadraticAlgebra.star_mk] <;> ring

theorem raw_c (xi : R) (x : Coeffs R) :
    cc xi (raw xi x) = 3*(cb xi x)^2 - 2*star (cc xi x) := by
  have h2 : (2 : Q xi) = ⟨2,0⟩ := rfl
  have h3 : (3 : Q xi) = ⟨3,0⟩ := rfl
  rw [h2,h3]
  ext <;> simp [cb,cc,raw,fp4Square,less,plus,pow_two,QuadraticAlgebra.star_mk] <;> ring

theorem raw_decode (xi : R) (x : Coeffs R) : decode xi (raw xi x) =
    assemble (omega xi) (3*(ca xi x)^2-2*star (ca xi x))
      (3*omega xi*(cc xi x)^2+2*star (cb xi x)) (3*(cb xi x)^2-2*star (cc xi x)) := by
  simp only [decode,raw_a,raw_b,raw_c]

theorem bls_cyclotomic_square (x : Coeffs Bls.K)
    (hphi : decode Bls.xi x ^ (Bls.p^4-Bls.p^2+1) = 1) :
    decode Bls.xi (raw Bls.xi x) = decode Bls.xi x ^ 2 := by
  rw [raw_decode]
  exact (Bls.cyclotomic_square (ca _ x) (cb _ x) (cc _ x) hphi).symm

def conjugate (x : Coeffs R) : Coeffs R :=
  ⟨x.c00,x.c01,x.c02,-x.c10,-x.c11,-x.c12⟩

theorem conjugate_decode (x : Coeffs Bls.K) :
    decode Bls.xi (conjugate x) = decode Bls.xi x ^ (Bls.p^6) := by
  simp only [decode]
  rw [Bls.assemble_pow_p6]
  congr 1 <;> ext <;> simp [ca,cb,cc,conjugate,QuadraticAlgebra.star_mk]

end LeanBlsSimd.Cyclotomic.Schedule
