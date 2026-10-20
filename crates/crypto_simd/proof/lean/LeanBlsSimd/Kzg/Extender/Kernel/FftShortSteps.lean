import LeanBlsSimd.Kzg.Extender.Kernel.FftShortModel

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel.ShortModel

theorem dit_zero_step (t : Array fr8.Fr8 8#usize) (h : Usize) (input : fr8.Fr8) (group : Usize) :
    fft8.Fft8.dit_short_loop0 t h input group = (do
      let flow ← fft8.Fft8.dit_short_loop0.body h input t group
      match flow with
      | cont (t1,g1) => fft8.Fft8.dit_short_loop0 t1 h input g1
      | done result => ok result) := by
  unfold fft8.Fft8.dit_short_loop0
  rw [loop.eq_1]
  dsimp only
  cases hflow : fft8.Fft8.dit_short_loop0.body h input t group with
  | ok flow =>
    cases flow with
    | cont state =>
      rcases state with ⟨x0,x1⟩
      rfl
    | done result => rfl
  | fail error => rfl
  | div => rfl


theorem dit_pipeline_step (v : alloc.vec.Vec fr8.Fr8) (t : Array fr8.Fr8 8#usize)
    (h : Usize) (bound : fr8.Fr8) (at1 : Usize) (pending : Array M512 11#usize)
    (group j : Usize) :
    fft8.Fft8.dit_short_loop1 v t h bound at1 pending group j = (do
      let flow ← fft8.Fft8.dit_short_loop1.body v h bound t at1 pending group j
      match flow with
      | cont (t1,at2,p2,g2,j2) => fft8.Fft8.dit_short_loop1 v t1 h bound at2 p2 g2 j2
      | done result => ok result) := by
  unfold fft8.Fft8.dit_short_loop1
  rw [loop.eq_1]
  dsimp only
  cases hflow : fft8.Fft8.dit_short_loop1.body v h bound t at1 pending group j with
  | ok flow =>
    cases flow with
    | cont state =>
      rcases state with ⟨x0,x1,x2,x3,x4⟩
      rfl
    | done result => rfl
  | fail error => rfl
  | div => rfl


theorem dit_outer_step (table : fft8.Fft8) (t : Array fr8.Fr8 8#usize) (h : Usize)
    (input : fr8.Fr8) (product : fr8.Fr8) (group : Usize) :
    dit_short_loop0 table t h input product group = (do
      let flow ← dit_short_loop0.body h input product table t group
      match flow with
      | cont (table1,t1,g1) => dit_short_loop0 table1 t1 h input product g1
      | done result => ok result) := by
  unfold dit_short_loop0
  rw [loop.eq_1]
  dsimp only
  cases hflow : dit_short_loop0.body h input product table t group with
  | ok flow =>
    cases flow with
    | cont state =>
      rcases state with ⟨x0,x1,x2⟩
      rfl
    | done result => rfl
  | fail error => rfl
  | div => rfl


theorem dit_inner_step (table : fft8.Fft8) (t : Array fr8.Fr8 8#usize) (h : Usize)
    (input : fr8.Fr8) (product : fr8.Fr8) (group j : Usize) :
    dit_short_loop0_loop0 table t h input product group j = (do
      let flow ← dit_short_loop0_loop0.body h input product group table t j
      match flow with
      | cont (table1,t1,j1) => dit_short_loop0_loop0 table1 t1 h input product group j1
      | done result => ok result) := by
  unfold dit_short_loop0_loop0
  rw [loop.eq_1]
  dsimp only
  cases hflow : dit_short_loop0_loop0.body h input product group table t j with
  | ok flow =>
    cases flow with
    | cont state =>
      rcases state with ⟨x0,x1,x2⟩
      rfl
    | done result => rfl
  | fail error => rfl
  | div => rfl


theorem dif_zero_step (t : Array fr8.Fr8 8#usize) (h : Usize) (group : Usize) :
    fft8.Fft8.dif_short_loop0 t h group = (do
      let flow ← fft8.Fft8.dif_short_loop0.body h t group
      match flow with
      | cont (t1,g1) => fft8.Fft8.dif_short_loop0 t1 h g1
      | done result => ok result) := by
  unfold fft8.Fft8.dif_short_loop0
  rw [loop.eq_1]
  dsimp only
  cases hflow : fft8.Fft8.dif_short_loop0.body h t group with
  | ok flow =>
    cases flow with
    | cont state =>
      rcases state with ⟨x0,x1⟩
      rfl
    | done result => rfl
  | fail error => rfl
  | div => rfl


theorem dif_pipeline_step (v : alloc.vec.Vec fr8.Fr8) (t : Array fr8.Fr8 8#usize)
    (h : Usize) (bound : fr8.Fr8) (at1 : Usize) (pending : Array M512 11#usize)
    (group j : Usize) :
    fft8.Fft8.dif_short_loop1 v t h bound at1 pending group j = (do
      let flow ← fft8.Fft8.dif_short_loop1.body v h bound t at1 pending group j
      match flow with
      | cont (t1,at2,p2,g2,j2) => fft8.Fft8.dif_short_loop1 v t1 h bound at2 p2 g2 j2
      | done result => ok result) := by
  unfold fft8.Fft8.dif_short_loop1
  rw [loop.eq_1]
  dsimp only
  cases hflow : fft8.Fft8.dif_short_loop1.body v h bound t at1 pending group j with
  | ok flow =>
    cases flow with
    | cont state =>
      rcases state with ⟨x0,x1,x2,x3,x4⟩
      rfl
    | done result => rfl
  | fail error => rfl
  | div => rfl


theorem dif_outer_step (table : fft8.Fft8) (t : Array fr8.Fr8 8#usize) (h : Usize)
    (input : fr8.Fr8) (group : Usize) :
    dif_short_loop0 table t h input group = (do
      let flow ← dif_short_loop0.body h input table t group
      match flow with
      | cont (table1,t1,g1) => dif_short_loop0 table1 t1 h input g1
      | done result => ok result) := by
  unfold dif_short_loop0
  rw [loop.eq_1]
  dsimp only
  cases hflow : dif_short_loop0.body h input table t group with
  | ok flow =>
    cases flow with
    | cont state =>
      rcases state with ⟨x0,x1,x2⟩
      rfl
    | done result => rfl
  | fail error => rfl
  | div => rfl


theorem dif_inner_step (table : fft8.Fft8) (t : Array fr8.Fr8 8#usize) (h : Usize)
    (input : fr8.Fr8) (group j : Usize) :
    dif_short_loop0_loop0 table t h input group j = (do
      let flow ← dif_short_loop0_loop0.body h input group table t j
      match flow with
      | cont (table1,t1,j1) => dif_short_loop0_loop0 table1 t1 h input group j1
      | done result => ok result) := by
  unfold dif_short_loop0_loop0
  rw [loop.eq_1]
  dsimp only
  cases hflow : dif_short_loop0_loop0.body h input group table t j with
  | ok flow =>
    cases flow with
    | cont state =>
      rcases state with ⟨x0,x1,x2⟩
      rfl
    | done result => rfl
  | fail error => rfl
  | div => rfl


end LeanBlsSimd.Kzg.Extender.Kernel.ShortModel
