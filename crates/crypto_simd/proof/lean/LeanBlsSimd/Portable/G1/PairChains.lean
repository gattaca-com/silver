import LeanBlsSimd.Portable.G1.PairArithmetic

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.G1.Pair
set_option maxRecDepth 4096
set_option maxHeartbeats 2000000

abbrev LaneState := Bool × Bls.G1
abbrev State := LaneState × LaneState

def startBit : U32 := UScalar.ofNatCore Z_BITS[0]! (Z_BITS_lt 0 (by decide))

def encodeState (s : State) : Array Bool 2#usize × portable.g1_pair.G1Pair :=
  (flags s.1.1 s.2.1,encode s.1.2 s.2.2)

def step (P : Bls.G1) (s : LaneState) (bit : Nat) : LaneState :=
  let D := Kzg.PortableG1.doubleValues s.2
  if G1x8.is_lower_z_bit bit then (s.1 || addExceptional D P,sum D P) else (s.1,D)

def affineStep (x y : Bls.Fp) (s : LaneState) (bit : Nat) : LaneState :=
  let D := Kzg.PortableG1.doubleValues s.2
  if G1x8.is_lower_z_bit bit then (s.1 || affineExceptional D x y,affineSum D x y) else (s.1,D)

def pairStep (P Q : Bls.G1) (s : State) (bit : Nat) : State :=
  (step P s.1 bit,step Q s.2 bit)

def affinePairStep (x0 x1 y0 y1 : Bls.Fp) (s : State) (bit : Nat) : State :=
  (affineStep x0 y0 s.1 bit,affineStep x1 y1 s.2 bit)

theorem affine_loop_encoded [RuntimeFeatures] (x0 x1 y0 y1 : Bls.Fp) (s : State) (c : U32) (n : Nat)
    (hcn : c.val = n) :
    portable.g1_pair.G1Pair.in_g1_loop0 (fields x0 x1) (fields y0 y1)
      (encodeState s).1 (encodeState s).2 c =
      ok (encodeState ((List.range n).reverse.foldl (affinePairStep x0 x1 y0 y1) s)) := by
  unfold portable.g1_pair.G1Pair.in_g1_loop0
  refine loop_countdown _ (fun s c => ((encodeState s).1,(encodeState s).2,c))
    (affinePairStep x0 x1 y0 y1) encodeState n ?_ ?_ c s hcn
  · intro s c hc
    simp [portable.g1_pair.G1Pair.in_g1_loop0.body,hc]
  · intro s c c' hc _
    simp only [portable.g1_pair.G1Pair.in_g1_loop0.body]
    rw [if_pos (by simp; omega),sub_ok _ _ (by simp; omega)]
    have e : (UScalar.ofNatCore (c.val-(1#u32).val) (by have := c.hBounds; omega) : U32) =
        c' := UScalar.eq_of_val_eq (by simp; omega)
    rw [e]
    simp only [encodeState,bind_tc_ok,double_encoded,G1x8.is_lower_z_bit_refines,add_affine_encoded,
      flags_zero,flags_one,affinePairStep,affineStep]
    cases hb : G1x8.is_lower_z_bit c'.val <;>
      cases h0 : s.1.1 <;> cases h1 : s.2.1 <;>
        simp_all only [Bool.false_eq_true,if_false,if_true,Bool.false_or,Bool.true_or,
          bind_tc_ok] <;> rfl

theorem projective_loop_encoded [RuntimeFeatures] (P Q : Bls.G1) (s : State) (c : U32) (n : Nat)
    (hcn : c.val = n) :
    portable.g1_pair.G1Pair.in_g1_loop1 (encodeState s).1 (encodeState s).2 c
      (encode P Q).x (encode P Q).y (encode P Q).z =
      ok (encodeState ((List.range n).reverse.foldl (pairStep P Q) s)) := by
  unfold portable.g1_pair.G1Pair.in_g1_loop1
  refine loop_countdown _ (fun s c => ((encodeState s).1,(encodeState s).2,c))
    (pairStep P Q) encodeState n ?_ ?_ c s hcn
  · intro s c hc
    simp [portable.g1_pair.G1Pair.in_g1_loop1.body,hc]
  · intro s c c' hc _
    simp only [portable.g1_pair.G1Pair.in_g1_loop1.body]
    rw [if_pos (by simp; omega),sub_ok _ _ (by simp; omega)]
    have e : (UScalar.ofNatCore (c.val-(1#u32).val) (by have := c.hBounds; omega) : U32) =
        c' := UScalar.eq_of_val_eq (by simp; omega)
    rw [e]
    simp only [encodeState,bind_tc_ok,double_encoded,G1x8.is_lower_z_bit_refines,
      add_encoded (Kzg.PortableG1.doubleValues s.1.2) (Kzg.PortableG1.doubleValues s.2.2) P Q,
      flags_zero,flags_one,pairStep,step]
    cases hb : G1x8.is_lower_z_bit c'.val <;>
      cases h0 : s.1.1 <;> cases h1 : s.2.1 <;>
        simp_all only [Bool.false_eq_true,if_false,if_true,Bool.false_or,Bool.true_or,
          bind_tc_ok] <;> rfl

theorem step_unflagged (P : Bls.G1) (s : LaneState) (bit : Nat) (h : (step P s bit).1 = false) :
    s.1 = false ∧ (step P s bit).2 = G1.chainStep P s.2 bit := by
  unfold step at h ⊢
  unfold G1.chainStep
  split <;> rename_i hb
  · simp only [hb,if_true] at h
    have he := Bool.or_eq_false_iff.mp h
    exact ⟨he.1,sum_eq_add _ _ he.2⟩
  · simp only [hb,if_false] at h
    exact ⟨h,rfl⟩

theorem affineStep_unflagged (x y : Bls.Fp) (s : LaneState) (bit : Nat)
    (h : (affineStep x y s bit).1 = false) :
    s.1 = false ∧ (affineStep x y s bit).2 = G1.chainStep ⟨x,y,Bls.Fp.one⟩ s.2 bit := by
  unfold affineStep at h ⊢
  unfold G1.chainStep
  split <;> rename_i hb
  · simp only [hb,if_true] at h
    have he := Bool.or_eq_false_iff.mp h
    exact ⟨he.1,affineSum_eq_add _ _ _ he.2⟩
  · simp only [hb,if_false] at h
    exact ⟨h,rfl⟩

private theorem fold_unflagged (f : LaneState → Nat → LaneState) (g : Bls.G1 → Nat → Bls.G1)
    (hf : ∀ s bit, (f s bit).1 = false → s.1 = false ∧ (f s bit).2 = g s.2 bit)
    (bits : List Nat) (s : LaneState) :
    (bits.foldl f s).1 = false → s.1 = false ∧ (bits.foldl f s).2 = bits.foldl g s.2 := by
  have h := List.foldl_rel
    (fun (a : LaneState) (Q : Bls.G1) => a.1 = false → s.1 = false ∧ a.2 = Q)
    f g ?_ bits s s.2 (fun hs => ⟨hs,rfl⟩)
  · exact h
  · intro a Q bit hrel hout
    obtain ⟨ha,he⟩ := hf a bit hout
    obtain ⟨hs,hq⟩ := hrel ha
    exact ⟨hs,he.trans (congrArg (fun R => g R bit) hq)⟩

def affineChain (x y : Bls.Fp) : LaneState :=
  (List.range Z_BITS[0]!).reverse.foldl (affineStep x y) (false,⟨x,y,Bls.Fp.one⟩)

def projectiveChain (s : LaneState) : LaneState :=
  (List.range Z_BITS[0]!).reverse.foldl (step s.2) s

theorem affineChain_unflagged (x y : Bls.Fp) (h : (affineChain x y).1 = false) :
    (affineChain x y).2 = G1.timesZ ⟨x,y,Bls.Fp.one⟩ :=
  (fold_unflagged _ _ (affineStep_unflagged x y) _ _ h).2

theorem projectiveChain_unflagged (s : LaneState) (h : (projectiveChain s).1 = false) :
    s.1 = false ∧ (projectiveChain s).2 = G1.timesZ s.2 :=
  fold_unflagged _ _ (step_unflagged s.2) _ _ h

theorem bothChains_unflagged (x y : Bls.Fp) (h : (projectiveChain (affineChain x y)).1 = false) :
    (projectiveChain (affineChain x y)).2 = G1.timesZ (G1.timesZ ⟨x,y,Bls.Fp.one⟩) := by
  obtain ⟨ha,he⟩ := projectiveChain_unflagged _ h
  rw [he,affineChain_unflagged x y ha]

private theorem fold_pair {α β γ : Type} (f : α → γ → α) (g : β → γ → β)
    (l : List γ) (a : α) (b : β) :
    l.foldl (fun (s : α × β) c => (f s.1 c,g s.2 c)) (a,b) = (l.foldl f a,l.foldl g b) := by
  induction l generalizing a b with
  | nil => rfl
  | cons c l ih => exact ih (f a c) (g b c)

theorem affine_chains_encoded [RuntimeFeatures] (x0 x1 y0 y1 : Bls.Fp) :
    portable.g1_pair.G1Pair.in_g1_loop0 (fields x0 x1) (fields y0 y1)
      (flags false false) (encode ⟨x0,y0,Bls.Fp.one⟩ ⟨x1,y1,Bls.Fp.one⟩)
      startBit = ok (encodeState (affineChain x0 y0,affineChain x1 y1)) := by
  have h := affine_loop_encoded x0 x1 y0 y1
    ((false,⟨x0,y0,Bls.Fp.one⟩),(false,⟨x1,y1,Bls.Fp.one⟩))
    startBit Z_BITS[0]! (by simp [startBit])
  simpa only [affinePairStep,fold_pair,affineChain] using h

theorem projective_chains_encoded [RuntimeFeatures] (s0 s1 : LaneState) :
    portable.g1_pair.G1Pair.in_g1_loop1 (flags s0.1 s1.1) (encode s0.2 s1.2)
      startBit (fields s0.2.x s1.2.x) (fields s0.2.y s1.2.y) (fields s0.2.z s1.2.z) =
      ok (encodeState (projectiveChain s0,projectiveChain s1)) := by
  have h := projective_loop_encoded s0.2 s1.2 (s0,s1) startBit Z_BITS[0]! (by simp [startBit])
  simpa only [pairStep,fold_pair,projectiveChain] using h

end LeanBlsSimd.Portable.G1.Pair
