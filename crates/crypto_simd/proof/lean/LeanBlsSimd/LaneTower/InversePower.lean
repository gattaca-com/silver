import LeanBlsSimd.LaneTower.Vectors
import LeanBlsSimd.Msm8.Inversion

open EthLib.Cryptography Bls

namespace LeanBlsSimd.Fp8

def BoundPowTable (a : ZMod Fp.modulus) (l : Fin 8) (table : Vector Fp8 16) : Prop :=
  ∀ k : Fin 16, BoundRep 32 table[k] l (a ^ k.val)

def BoundPartTable (a : ZMod Fp.modulus) (l : Fin 8) (m : ℕ) (table : Vector Fp8 16) : Prop :=
  ∀ k : Fin 16, BoundRep 32 table[k] l (if k.val ≤ m then a ^ k.val else 1)

theorem bound_table_fold {x : Fp8} {l : Fin 8} {a : ZMod Fp.modulus}
    (hx : BoundRep 32 x l a) :
    ∀ (ks : List (Fin 16)) (m : ℕ) (table : Vector Fp8 16), 1 ≤ m →
      ks = (List.finRange 16).drop (m + 1) → BoundPartTable a l m table →
      BoundPowTable a l (ks.foldl (fun table (k : Fin 16) => table.set k (table[k.val - 1].mul x)) table)
  | [], m, table, _, hks, ht => by
    have hm : 15 ≤ m := by
      have : ((List.finRange 16).drop (m + 1)).length = 15 - m := by simp
      rw [← hks] at this
      simp at this
      omega
    intro k
    simpa only [List.foldl_nil, if_pos (show k.val ≤ m by omega)] using ht k
  | k :: ks, m, table, hm, hks, ht => by
    obtain ⟨hk, hks'⟩ := drop_finRange_cons hks.symm
    rw [List.foldl_cons]
    refine bound_table_fold hx ks (m + 1) _ (by omega) hks' fun j => ?_
    have hprev := ht ⟨k.val - 1, by omega⟩
    simp only [Fin.getElem_fin, if_pos (show k.val - 1 ≤ m by omega)] at hprev
    simp only [Fin.getElem_fin, Vector.getElem_set]
    by_cases hjk : k.val = j.val
    · rw [if_pos hjk, if_pos (show j.val ≤ m + 1 by omega)]
      have hp := ((hprev.mul hx (by decide)).boundRep).mono (show 2 ≤ 32 by decide)
      simpa only [← hjk, ← pow_succ, Nat.sub_add_cancel (show 1 ≤ k.val by omega)] using hp
    · rw [if_neg hjk]
      have hj := ht j
      simp only [Fin.getElem_fin] at hj
      by_cases hjm : j.val ≤ m
      · simpa only [if_pos hjm, if_pos (show j.val ≤ m + 1 by omega)] using hj
      · simpa only [if_neg hjm, if_neg (show ¬j.val ≤ m + 1 by omega)] using hj

theorem bound_table_init {x : Fp8} {l : Fin 8} {a : ZMod Fp.modulus}
    (hx : BoundRep 32 x l a) : BoundPartTable a l 1 ((Vector.replicate 16 one).set 1 x) := by
  intro k
  simp only [Fin.getElem_fin, Vector.getElem_set, Vector.getElem_replicate]
  by_cases hk : 1 = k.val
  · rw [if_pos hk, if_pos (by omega), ← hk, pow_one]
    exact hx
  · rw [if_neg hk]
    have ho := ((holds_one l).boundRep).mono (show 2 ≤ 32 by decide)
    split_ifs with h
    · simpa only [show k.val = 0 by omega, pow_zero] using ho
    · exact ho

theorem bound_window_step {l : Fin 8} {a : ZMod Fp.modulus} {table : Vector Fp8 16}
    (ht : BoundPowTable a l table) {w e : ℕ} {r : Fp8}
    (hw : P_MINUS_3_OVER_4_WINDOWS[w]! < 16) (hr : BoundRep 32 r l (a ^ e)) :
    BoundRep 32 (windowStep table r w) l (a ^ (16 * e + P_MINUS_3_OVER_4_WINDOWS[w]!)) := by
  have h4 : (r.square.square.square.square).Holds l (a ^ (16 * e)) := by
    have h := (hr.square (by decide)).square.square.square
    convert h using 1
    simp only [← pow_mul]
    congr 1
    omega
  unfold windowStep
  dsimp only
  split_ifs with hdig
  · have htab := ht ⟨_, hw⟩
    simp only [Fin.getElem_fin] at htab
    rw [getElem!_pos table _ hw]
    simpa only [← pow_add] using ((h4.boundRep.mul htab (by decide)).boundRep).mono (show 2 ≤ 32 by decide)
  · simpa only [show P_MINUS_3_OVER_4_WINDOWS[w]! = 0 by simpa using hdig, add_zero]
      using h4.boundRep.mono (show 2 ≤ 32 by decide)

theorem bound_window_fold {l : Fin 8} {a : ZMod Fp.modulus} {table : Vector Fp8 16}
    (ht : BoundPowTable a l table) (ws : List ℕ) :
    ∀ (e : ℕ) (r : Fp8), (∀ w ∈ ws, P_MINUS_3_OVER_4_WINDOWS[w]! < 16) →
      BoundRep 32 r l (a ^ e) →
      BoundRep 32 (ws.foldl (windowStep table) r) l
        (a ^ ws.foldl (fun e w => 16 * e + P_MINUS_3_OVER_4_WINDOWS[w]!) e) := by
  induction ws with
  | nil => intro e r _ hr; exact hr
  | cons w ws ih =>
    intro e r hw hr
    exact ih _ _ (fun w' hw' => hw w' (by simp [hw'])) (bound_window_step ht (hw w (by simp)) hr)

theorem BoundRep.pow_p_minus_3_over_4 {x : Fp8} {l : Fin 8} {a : ZMod Fp.modulus}
    (hx : BoundRep 32 x l a) : BoundRep 32 x.pow_p_minus_3_over_4 l (a ^ ((Fp.modulus - 3) / 4)) := by
  have ht := bound_table_fold hx ((List.finRange 16).drop 2) 1 _ le_rfl rfl (bound_table_init hx)
  unfold Fp8.pow_p_minus_3_over_4
  dsimp only
  generalize ((List.finRange 16).drop 2).foldl _ _ = table at ht ⊢
  have h94 : P_MINUS_3_OVER_4_WINDOWS[94]! < 16 := by decide
  have ht94 := ht ⟨_, h94⟩
  simp only [Fin.getElem_fin] at ht94
  rw [← getElem!_pos table _ h94] at ht94
  have h := bound_window_fold ht ((List.range 94).reverse) _ _
    (fun w hw => windows_lt w (by simp at hw ⊢; omega)) ht94
  simpa only [windows_horner] using h

theorem BoundRep.inverse {x : Fp8} {l : Fin 8} {a : ZMod Fp.modulus}
    (hx : BoundRep 32 x l a) : x.inverse.Holds l a⁻¹ := by
  have hp := hx.pow_p_minus_3_over_4
  have h := (((hp.square (by decide)).square).boundRep.mul hx (by decide))
  change x.inverse.Holds l _ at h
  apply h.of_eq
  rw [← pow_mul, ← pow_mul, ← pow_succ, ← Nat.mul_assoc, inverse_exponent,
    pow_p_minus_two_eq_inv]

end LeanBlsSimd.Fp8

namespace LeanBlsSimd.LaneTower
open Aeneas Aeneas.Std Result silver_crypto_simd silver_crypto_simd.bls

theorem inverse_raw {x : fp8.Fp8} {a : V F} (hx : Normal (fun _ => 4) x a) :
    ∃ out, fp8.Fp8.inverse x = ok out ∧ Normal (fun _ => 2) out (fun l => (a l)⁻¹) := by
  refine ⟨_, Fp8.inverse_refines x, ?_⟩
  intro l
  simpa only [ofFp8_toFp8] using ((hx l).boundRep (by decide : 4 < 32)).inverse.capped

end LeanBlsSimd.LaneTower
