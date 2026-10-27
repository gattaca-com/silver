import LeanBlsSimd.PairingProduct.MillerSpec

open EthLib.Cryptography Bls
open LeanBlsSimd.Pairing

namespace LeanBlsSimd.PairingProduct.Miller

noncomputable section

set_option maxRecDepth 8000

abbrev Entries := List (Input × State)

def advance (xs : Entries) (add : Bool) : Entries :=
  xs.map fun x => (x.1, x.2.step x.1 add)

def valueProduct (xs : Entries) : Fp12Field := (xs.map fun x => x.2.value).prod

def lineProduct (xs : Entries) (add : Bool) : Fp12Field :=
  (xs.map fun x => Step.evaluatedLine (x.2.output x.1 add) x.1.xp x.1.yp).prod

def flags (xs : Entries) : Bool := xs.any fun x => x.2.flagged

def sharedStep (s : Entries × Fp12Field) (add : Bool) : Entries × Fp12Field :=
  (advance s.1 add, (if add then s.2 else s.2 * s.2) * lineProduct s.1 add)

def sharedRun (xs : Entries) (f : Fp12Field) (kinds : List Bool) : Entries × Fp12Field :=
  kinds.foldl sharedStep (xs, f)

def initialEntries (inputs : List Input) : Entries := inputs.map fun i => (i, i.initial)

def sharedMiller (inputs : List Input) : Entries × Fp12Field :=
  sharedRun (initialEntries inputs) 1 (lineKinds 63)

def sharedFactor (inputs : List Input) : Fp12Field :=
  (sharedMiller inputs).2 ^ (Fp.modulus ^ 6)

theorem advance_product (xs : Entries) (add : Bool) :
    valueProduct (advance xs add) =
      (if add then valueProduct xs else valueProduct xs * valueProduct xs) *
        lineProduct xs add := by
  induction xs with
  | nil => cases add <;> simp [advance, valueProduct, lineProduct]
  | cons x xs ih =>
    simp only [advance, List.map_cons, valueProduct, List.prod_cons] at ih ⊢
    rw [ih]
    cases add <;> simp only [State.step, Bool.false_eq_true, if_false, if_true,
      lineProduct, List.map_cons, List.prod_cons] <;> ring

theorem sharedRun_product (xs : Entries) (f : Fp12Field) (kinds : List Bool)
    (hf : f = valueProduct xs) :
    (sharedRun xs f kinds).2 = valueProduct (sharedRun xs f kinds).1 := by
  induction kinds generalizing xs f with
  | nil => exact hf
  | cons add kinds ih =>
    exact ih (advance xs add) _ (by rw [hf, ← advance_product])

theorem sharedRun_entries (xs : Entries) (f : Fp12Field) (kinds : List Bool) :
    (sharedRun xs f kinds).1 = xs.map (fun x => (x.1, x.2.run x.1 kinds)) := by
  induction kinds generalizing xs f with
  | nil => simp [sharedRun, State.run]
  | cons add kinds ih =>
    change (sharedRun (advance xs add) _ kinds).1 = _
    rw [ih]
    simp only [advance, List.map_map, Function.comp_def, State.run, List.foldl_cons]

theorem sharedRun_value (xs : Entries) (f : Fp12Field) (kinds : List Bool)
    (hf : f = valueProduct xs) :
    (sharedRun xs f kinds).2 = (xs.map fun x => (x.2.run x.1 kinds).value).prod := by
  rw [sharedRun_product xs f kinds hf, sharedRun_entries]
  simp only [valueProduct, List.map_map, Function.comp_def]

def sharedBitStep (s : Entries × Fp12Field) (n : Nat) : Entries × Fp12Field :=
  let doubled := sharedStep s false
  if blsX.testBit n then sharedStep doubled true else doubled

theorem sharedRun_bits (xs : Entries) (f : Fp12Field) (n : Nat) :
    sharedRun xs f (lineKinds (n + 1)) =
      sharedRun (sharedBitStep (xs, f) n).1 (sharedBitStep (xs, f) n).2 (lineKinds n) := by
  simp only [lineKinds, sharedRun, List.foldl_cons, List.foldl_append, sharedBitStep]
  split <;> simp only [List.foldl_cons, List.foldl_nil]

theorem initial_product (inputs : List Input) : valueProduct (initialEntries inputs) = 1 := by
  induction inputs with
  | nil => rfl
  | cons i inputs ih =>
    simpa only [initialEntries, valueProduct, List.map_cons, List.prod_cons,
      Input.initial, one_mul] using ih

theorem sharedMiller_entries (inputs : List Input) :
    (sharedMiller inputs).1 = inputs.map (fun i => (i, i.miller)) := by
  rw [sharedMiller, sharedRun_entries]
  simp only [initialEntries, List.map_map, Function.comp_def, Input.miller]

theorem sharedMiller_value (inputs : List Input) :
    (sharedMiller inputs).2 = (inputs.map fun i => i.miller.value).prod := by
  rw [sharedMiller, sharedRun_value _ _ _ (initial_product inputs).symm]
  simp only [initialEntries, List.map_map, Function.comp_def, Input.miller]

theorem sharedMiller_clear (inputs : List Input)
    (hc : flags (sharedMiller inputs).1 = false) :
    ∀ i ∈ inputs, i.miller.flagged = false := by
  simpa only [flags, sharedMiller_entries, List.any_map, Function.comp_def,
    List.any_eq_false, Bool.not_eq_true] using hc

theorem sharedFactor_product (inputs : List Input) :
    sharedFactor inputs = (inputs.map Input.factor).prod := by
  rw [sharedFactor, sharedMiller_value]
  simpa only [List.map_map, Function.comp_def, Input.factor, powMonoidHom_apply] using
    (List.prod_hom (inputs.map fun i => i.miller.value)
      (powMonoidHom (Fp.modulus ^ 6))).symm

theorem sharedFactor_spec (inputs : List Input)
    (hc : flags (sharedMiller inputs).1 = false) :
    sharedFactor inputs ^ finalExpExponent =
      (inputs.map fun i =>
        Fp12.toField (millerLoop blsX i.base i.evaluation).conjugate).prod ^
          finalExpExponent := by
  rw [sharedFactor_product]
  have hclear := sharedMiller_clear inputs hc
  clear hc
  induction inputs with
  | nil => simp only [List.map_nil, List.prod_nil]
  | cons i inputs ih =>
    simp only [List.map_cons, List.prod_cons, mul_pow]
    rw [factor_spec i (hclear i (by simp)), ih]
    exact fun j hj => hclear j (by simp [hj])

theorem finite_sharedFactor_spec (pairs : List (G1 × G2))
    (hp : ∀ pair ∈ pairs, pair.1.isInfinity = false)
    (hq : ∀ pair ∈ pairs, pair.2.isInfinity = false)
    (hc : flags (sharedMiller (pairs.map fun pair => Input.ofPoints pair.1 pair.2)).1 = false) :
    sharedFactor (pairs.map fun pair => Input.ofPoints pair.1 pair.2) ^ finalExpExponent =
      (pairs.map fun pair => Fp12.toField (pairingFactor pair)).prod ^ finalExpExponent := by
  rw [sharedFactor_spec _ hc, List.map_map]
  apply congrArg (fun xs : List Fp12Field => xs.prod ^ finalExpExponent)
  apply List.map_congr_left
  intro pair hm
  simp only [Function.comp_def, ofPoints_base _ _ (hq pair hm),
    ofPoints_evaluation _ _ (hp pair hm), pairingFactor, hp pair hm, hq pair hm,
    Bool.or_self, Bool.false_eq_true, if_false]

end

end LeanBlsSimd.PairingProduct.Miller
