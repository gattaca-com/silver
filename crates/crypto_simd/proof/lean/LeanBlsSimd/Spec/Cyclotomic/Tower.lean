import LeanBlsSimd.Spec.Cyclotomic.Constants

namespace LeanBlsSimd.Cyclotomic.Bls
open LeanBlsSimd EthLib.Cryptography EthLib.Cryptography.Bls
open QuadraticAlgebra

theorem k_pow_q (a : K) : a^q = a := by
  rw [show q = Fintype.card K from Fp2Field.card_eq.symm]
  exact FiniteField.pow_card a

abbrev S := QuadraticAlgebra K xi 0
noncomputable abbrev u : S := QuadraticAlgebra.omega
noncomputable abbrev j : K →+* S := algebraMap K S
abbrev T := Cubic u
noncomputable abbrev d : S := j delta

instance : CharP S p := (CharP.charP_iff_prime_eq_zero (Fact.out : p.Prime)).2 (by
  rw [← map_natCast j, LeanBlsSimd.Fp2Field.natCast_modulus, map_zero])

theorem embed_injective : Function.Injective (embed u) := by
  intro a b h
  have ha : assemble u a 0 0 = embed u a := by simp [assemble]
  have hb : assemble u b 0 0 = embed u b := by simp [assemble]
  exact (assemble_injective u a 0 0 b 0 0 (by rw [ha,hb,h])).1

instance : Nontrivial T := Function.Injective.nontrivial embed_injective

instance : CharP T p := (CharP.charP_iff_prime_eq_zero (Fact.out : p.Prime)).2 (by
  rw [← map_natCast (embed u), CharP.cast_eq_zero S p, map_zero])

theorem u_square : u^2 = j xi := by
  rw [sq, QuadraticAlgebra.omega_mul_omega_eq_mk]
  rfl

theorem u_pow_q : u^q = -u := by
  have hq : q = 2*((q-1)/2)+1 := by decide +kernel
  rw [hq, pow_succ, pow_mul, u_square, ← map_pow, xi_half, map_neg, map_one, neg_one_mul]

theorem s_pow_q (a : S) : a^q = star a := by
  have ha : a = j a.re + j a.im*u := by ext <;> simp
  conv_lhs => rw [ha]
  rw [add_pow_char_pow, mul_pow, ← map_pow, ← map_pow, k_pow_q, k_pow_q, u_pow_q]
  rcases a with ⟨a,b⟩
  ext <;> simp [QuadraticAlgebra.star_mk]

theorem d_polynomial : d^2-d+1 = 0 := by
  rw [← map_pow, ← map_sub, ← map_one j, ← map_add, delta_polynomial, map_zero]

theorem w_sixth : w u ^ 6 = embed u (j xi) := by
  rw [show 6 = 3*2 by rfl, pow_mul, w_cube, ← map_pow, u_square]

theorem w_pow_q : w u ^ q = embed u d * w u := by
  have hq : q = 6*((q-1)/6)+1 := by decide +kernel
  rw [root_power (w u) (embed u (j xi)) q ((q-1)/6) hq w_sixth,
    ← map_pow, ← map_pow, xi_sixth]

theorem assemble_pow_q (a b c : S) :
    assemble u a b c ^ q = assemble u (star a) (d*star b) (d^2*star c) := by
  have h2 : (w u ^ 2)^q = (embed u d * w u)^2 := by
    rw [← pow_mul, Nat.mul_comm 2 q, pow_mul, w_pow_q]
  simp only [assemble, add_pow_char_pow, mul_pow, h2, ← map_pow, s_pow_q, w_pow_q]
  simp only [map_mul, map_pow]
  ring

theorem assemble_pow_qq (a b c : S) :
    assemble u a b c ^ (q^2) = assemble u a (d^2*b) (d^4*c) := by
  rw [sq, pow_mul, assemble_pow_q, assemble_pow_q]
  have hd : star d = d := by
    change star (⟨delta,0⟩ : S) = ⟨delta,0⟩
    simp [QuadraticAlgebra.star_mk]
  simp only [star_mul, star_pow, star_star, hd]
  congr 1 <;> ring

theorem cyclotomic_square (a b c : S)
    (hphi : assemble u a b c ^ (p^4-p^2+1) = 1) :
    assemble u a b c ^ 2 =
      assemble u (3*a^2-2*star a) (3*u*c^2+2*star b) (3*b^2-2*star c) := by
  apply granger_scott_of_frobenius_relation u a b c (star a) (star b) (star c) d d_polynomial
  rw [← assemble_pow_qq]
  have hp : q^2 = p^4 := by simp only [q, ← pow_mul]
  rw [hp]
  have hrel := cyclotomic_relation (assemble u a b c) (p^2) (by decide +kernel)
  rw [← pow_mul, show 2*2=4 by rfl] at hrel
  rw [hrel hphi, assemble_pow_q]

theorem k_pow_p (a : K) : a^p = star a := by
  have hi : (QuadraticAlgebra.omega : K)^p = -QuadraticAlgebra.omega := by
    have hp : p = 4*((p-3)/4)+3 := by decide +kernel
    have hi4 : (QuadraticAlgebra.omega : K)^4 = 1 := by
      rw [show 4=2*2 by rfl, pow_mul, Fp2Field.omega_sq]
      ring
    rw [hp,pow_add,pow_mul,hi4,one_pow,one_mul,
      show 3=2+1 by rfl,pow_succ,Fp2Field.omega_sq,neg_one_mul]
  let f : ZMod p →+* K := algebraMap _ _
  have ha : a = f a.re + f a.im*QuadraticAlgebra.omega := by ext <;> simp [f]
  conv_lhs => rw [ha]
  rw [add_pow_char, mul_pow, ← map_pow, ← map_pow, ZMod.pow_card, ZMod.pow_card, hi]
  ext <;> simp [f]

noncomputable abbrev kembed : K →+* T := (embed u).comp j
noncomputable def sextic (a : Fin 6 → K) : T := ∑ i : Fin 6, kembed (a i)*w u^i.val

theorem p_power_coefficients (a : Fin 6 → K) :
    sextic a ^ p = sextic (fun i => star (a i)*xi^(i.val*((p-1)/6))) := by
  have hp : p^1 = 6*((p-1)/6)+1 := by decide +kernel
  have h := coefficient_frobenius p 1 (w u) (kembed xi)
    (fun i => kembed (a i)) ((p-1)/6) hp w_sixth
  simp only [pow_one] at h
  change (∑ i : Fin 6, kembed (a i)*w u^i.val)^p = _
  rw [h]
  unfold sextic
  apply Finset.sum_congr rfl
  intro i _
  rw [← map_pow, k_pow_p, ← map_pow, ← map_mul]

theorem d_cube : d^3 = -1 := by
  linear_combination (d+1)*d_polynomial

theorem d_sixth : d^6 = 1 := by
  rw [show 6=3*2 by rfl, pow_mul, d_cube]
  ring

theorem assemble_pow_p6 (a b c : S) :
    assemble u a b c ^ (p^6) = assemble u (star a) (-star b) (star c) := by
  have hexp : p^6 = q^2*q := by simp only [q]; ring
  rw [hexp, pow_mul, assemble_pow_qq, assemble_pow_q]
  have hd : star d = d := by
    change star (⟨delta,0⟩ : S) = ⟨delta,0⟩
    simp [QuadraticAlgebra.star_mk]
  simp only [star_mul, star_pow, hd]
  congr 1
  · calc
      d * (star b * d^2) = d^3*star b := by ring
      _ = -star b := by rw [d_cube, neg_one_mul]
  · calc
      d^2 * (star c * d^4) = d^6*star c := by ring
      _ = star c := by rw [d_sixth, one_mul]

theorem tower_period (g : T) : g^(p^12) = g := by
  obtain ⟨a,b,c,rfl⟩ := assemble_surjective u g
  rw [show p^12 = p^6*p^6 by ring, pow_mul, assemble_pow_p6, assemble_pow_p6]
  simp only [star_star, star_neg, neg_neg]

theorem unit_period (g : Tˣ) : g^(p^12-1) = 1 := by
  have hperiod : g^(p^12) = g := by
    apply Units.ext
    simpa only [Units.val_pow_eq_pow_val] using tower_period (g : T)
  apply mul_left_cancel (a := g)
  calc
    g * g^(p^12-1) = g^(p^12) := by
      rw [← pow_succ', Nat.sub_add_cancel (by decide +kernel : 1 ≤ p^12)]
    _ = g := hperiod
    _ = g*1 := (mul_one _).symm

theorem easy_cyclotomic (g : Tˣ) : LeanBlsSimd.Cyclotomic.easyPart g p ^ (p^4-p^2+1) = 1 :=
  easyPart_cyclotomic g p (by decide +kernel) (unit_period g)

theorem easy_unitary (g : Tˣ) : LeanBlsSimd.Cyclotomic.easyPart g p ^ (p^6+1) = 1 :=
  cyclotomic_unitary _ p (by decide +kernel) (easy_cyclotomic g)

theorem easy_conjugate_inverse (g : Tˣ) : LeanBlsSimd.Cyclotomic.easyPart g p ^ (p^6) = (LeanBlsSimd.Cyclotomic.easyPart g p)⁻¹ :=
  conjugate_inverse _ _ (easy_unitary g)

end LeanBlsSimd.Cyclotomic.Bls
