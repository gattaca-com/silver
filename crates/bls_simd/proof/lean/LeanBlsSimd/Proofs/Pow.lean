import LeanBlsSimd.Proofs.Fp8

/-!
# `pow_p_minus_3_over_4` and `sqrt_candidate`

On a lane that keeps `Fp8Inv`, `pow_p_minus_3_over_4` computes x^((p − 3)/4) and
`sqrt_candidate` x^((p + 1)/4) in Montgomery form, and both keep `Fp8Inv`. The table holds x^k at
k (`PowTable`); each window raises the running power to the 16th and multiplies in the window's
entry, so the exponent follows Horner's rule over the windows (`windows_horner`).
-/

namespace LeanBlsSimd

open EthCryptographySpecs.Bls

theorem windows_lt : ∀ w ∈ List.range 95, P_MINUS_3_OVER_4_WINDOWS[w]! < 16 := by decide

/-- The exponent the window loop builds, high window first. -/
theorem windows_horner :
    (List.range 94).reverse.foldl (fun e w => 16 * e + P_MINUS_3_OVER_4_WINDOWS[w]!)
      P_MINUS_3_OVER_4_WINDOWS[94]! = (Fp.modulus - 3) / 4 := by
  decide +kernel

namespace Fp8

/-- The power table of `pow_p_minus_3_over_4` holds `x ^ k` at `k`, on lane `l`. -/
def PowTable (x : Fp8) (l : Fin 8) (table : Vector Fp8 16) : Prop :=
  ∀ k : Fin 16, Fp8Inv (table[k].lane l) ∧ decode (table[k].lane l) = decode (x.lane l) ^ k.val

/-- The table while it is built: entries above `m` still hold `one`. -/
def PartTable (x : Fp8) (l : Fin 8) (m : ℕ) (table : Vector Fp8 16) : Prop :=
  ∀ k : Fin 16, Fp8Inv (table[k].lane l) ∧
    decode (table[k].lane l) = if k.val ≤ m then decode (x.lane l) ^ k.val else 1

theorem drop_finRange_cons {n : ℕ} {k : Fin 16} {ks : List (Fin 16)}
    (h : (List.finRange 16).drop n = k :: ks) : k.val = n ∧ ks = (List.finRange 16).drop (n + 1) := by
  have hn : n < 16 := by
    by_contra hn
    rw [List.drop_eq_nil_of_le (by simp; omega)] at h
    cases h
  rw [List.drop_eq_getElem_cons (by simpa using hn)] at h
  obtain ⟨h1, h2⟩ := List.cons.inj h
  exact ⟨by rw [← h1]; simp, h2.symm⟩

theorem table_fold {x : Fp8} {l : Fin 8} (hx : Fp8Inv (x.lane l)) :
    ∀ (ks : List (Fin 16)) (m : ℕ) (table : Vector Fp8 16), 1 ≤ m →
      ks = (List.finRange 16).drop (m + 1) → PartTable x l m table →
      PowTable x l (ks.foldl (fun table (k : Fin 16) => table.set k (table[k.val - 1].mul x)) table)
  | [], m, table, _, hks, ht => by
    have hm : 15 ≤ m := by
      by_contra hm
      have : ((List.finRange 16).drop (m + 1)).length = 15 - m := by simp
      rw [← hks] at this
      simp at this
      omega
    intro k
    obtain ⟨h1, h2⟩ := ht k
    refine ⟨h1, ?_⟩
    rw [List.foldl_nil, h2, if_pos (by omega)]
  | k :: ks, m, table, hm, hks, ht => by
    obtain ⟨hk, hks'⟩ := drop_finRange_cons hks.symm
    rw [List.foldl_cons]
    refine table_fold hx ks (m + 1) _ (by omega) hks' fun j => ?_
    obtain ⟨hprev, hprevd⟩ := ht ⟨k.val - 1, by omega⟩
    rw [if_pos (by simp; omega)] at hprevd
    simp only [Fin.getElem_fin] at hprev hprevd ⊢
    rw [Vector.getElem_set]
    by_cases hjk : k.val = j.val
    · rw [if_pos hjk, if_pos (by omega)]
      refine ⟨inv_mul hprev hx, ?_⟩
      rw [decode_lane_mul hprev hx, hprevd, ← hjk, ← pow_succ]
      congr 1
      omega
    · rw [if_neg hjk]
      obtain ⟨h1, h2⟩ := ht j
      simp only [Fin.getElem_fin] at h1 h2
      refine ⟨h1, ?_⟩
      rw [h2]
      by_cases hjm : j.val ≤ m
      · rw [if_pos hjm, if_pos (by omega)]
      · rw [if_neg hjm, if_neg (by omega)]

theorem part_table_init {x : Fp8} {l : Fin 8} (hx : Fp8Inv (x.lane l)) :
    PartTable x l 1 ((Vector.replicate 16 one).set 1 x) := by
  intro k
  simp only [Fin.getElem_fin, Vector.getElem_set, Vector.getElem_replicate]
  by_cases hk : 1 = k.val
  · rw [if_pos hk, if_pos (by omega), ← hk, pow_one]
    exact ⟨hx, rfl⟩
  · rw [if_neg hk]
    refine ⟨inv_one l, ?_⟩
    rw [decode_lane_one]
    split_ifs with h
    · rw [show k.val = 0 by omega, pow_zero]
    · rfl

theorem inv_square {x : Fp8} {l : Fin 8} (hx : Fp8Inv (x.lane l)) : Fp8Inv (x.square.lane l) :=
  inv_mul hx hx

/-- The body of `pow_p_minus_3_over_4`'s window loop. -/
def windowStep (table : Vector Fp8 16) (r : Fp8) (w : ℕ) : Fp8 :=
  let r := r.square.square.square.square
  let digit := P_MINUS_3_OVER_4_WINDOWS[w]!
  if digit ≠ 0 then r.mul table[digit]! else r

theorem window_step {x : Fp8} {l : Fin 8} {table : Vector Fp8 16} (ht : PowTable x l table)
    {w e : ℕ} {r : Fp8} (hw : P_MINUS_3_OVER_4_WINDOWS[w]! < 16) (hr : Fp8Inv (r.lane l))
    (hd : decode (r.lane l) = decode (x.lane l) ^ e) :
    Fp8Inv ((windowStep table r w).lane l) ∧ decode ((windowStep table r w).lane l) =
      decode (x.lane l) ^ (16 * e + P_MINUS_3_OVER_4_WINDOWS[w]!) := by
  have hr4 : Fp8Inv (r.square.square.square.square.lane l) :=
    inv_square (inv_square (inv_square (inv_square hr)))
  have hd4 : decode (r.square.square.square.square.lane l) = decode (x.lane l) ^ (16 * e) := by
    rw [decode_lane_square (inv_square (inv_square (inv_square hr))),
      decode_lane_square (inv_square (inv_square hr)), decode_lane_square (inv_square hr),
      decode_lane_square hr, hd, ← pow_mul, ← pow_mul, ← pow_mul, ← pow_mul]
    ring_nf
  unfold windowStep
  dsimp only
  split_ifs with hdig
  · have htab := ht ⟨_, hw⟩
    simp only [Fin.getElem_fin] at htab
    rw [getElem!_pos table _ hw]
    refine ⟨inv_mul hr4 htab.1, ?_⟩
    rw [decode_lane_mul hr4 htab.1, hd4, htab.2, ← pow_add]
  · refine ⟨hr4, ?_⟩
    rw [hd4, show P_MINUS_3_OVER_4_WINDOWS[w]! = 0 by simpa using hdig, add_zero]

/-- The window loop: each window multiplies the exponent by 16 and adds the window. -/
theorem window_fold {x : Fp8} {l : Fin 8} {table : Vector Fp8 16} (ht : PowTable x l table) :
    ∀ (ws : List ℕ) (e : ℕ) (r : Fp8), (∀ w ∈ ws, P_MINUS_3_OVER_4_WINDOWS[w]! < 16) →
      Fp8Inv (r.lane l) → decode (r.lane l) = decode (x.lane l) ^ e →
      Fp8Inv ((ws.foldl (windowStep table) r).lane l) ∧
        decode ((ws.foldl (windowStep table) r).lane l) =
          decode (x.lane l) ^ ws.foldl (fun e w => 16 * e + P_MINUS_3_OVER_4_WINDOWS[w]!) e := by
  intro ws
  induction ws with
  | nil =>
    intro e r _ hr hd
    simp only [List.foldl_nil]
    exact ⟨hr, hd⟩
  | cons w ws ih =>
    intro e r hws hr hd
    obtain ⟨h1, h2⟩ := window_step ht (hws w (by simp)) hr hd
    simp only [List.foldl_cons]
    exact ih _ _ (fun w' hw' => hws w' (by simp [hw'])) h1 h2

theorem lane_pow_p_minus_3_over_4 {x : Fp8} {l : Fin 8} (hx : Fp8Inv (x.lane l)) :
    Fp8Inv (x.pow_p_minus_3_over_4.lane l) ∧
      decode (x.pow_p_minus_3_over_4.lane l) = decode (x.lane l) ^ ((Fp.modulus - 3) / 4) := by
  have ht := table_fold hx ((List.finRange 16).drop 2) 1 _ le_rfl rfl (part_table_init hx)
  unfold pow_p_minus_3_over_4
  dsimp only
  generalize ((List.finRange 16).drop 2).foldl _ _ = table at ht ⊢
  have h94 : P_MINUS_3_OVER_4_WINDOWS[94]! < 16 := by decide
  have ht94 := ht ⟨_, h94⟩
  simp only [Fin.getElem_fin] at ht94
  rw [← getElem!_pos table _ h94] at ht94
  have := window_fold ht ((List.range 94).reverse) _ _
    (fun w hw => windows_lt w (by simp at hw ⊢; omega)) ht94.1 ht94.2
  rw [windows_horner] at this
  exact this

theorem lane_sqrt_candidate {x : Fp8} {l : Fin 8} (hx : Fp8Inv (x.lane l)) :
    Fp8Inv (x.sqrt_candidate.lane l) ∧
      decode (x.sqrt_candidate.lane l) = decode (x.lane l) ^ ((Fp.modulus + 1) / 4) := by
  obtain ⟨h1, h2⟩ := lane_pow_p_minus_3_over_4 hx
  refine ⟨inv_mul h1 hx, ?_⟩
  rw [sqrt_candidate, decode_lane_mul h1 hx, h2, ← pow_succ,
    show (Fp.modulus - 3) / 4 + 1 = (Fp.modulus + 1) / 4 by have := p_mod_four; omega]

end Fp8
end LeanBlsSimd
