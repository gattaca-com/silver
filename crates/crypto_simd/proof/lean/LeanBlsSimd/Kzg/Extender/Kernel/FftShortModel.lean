import LeanBlsSimd.Refines.Fr8Lazy

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.kzg

/- Sequential short-stage model: finish each butterfly before visiting the next pair.
The pipeline equality reuses the existing arithmetic and range proofs for this schedule. -/
namespace LeanBlsSimd.Kzg.Extender.Kernel.ShortModel

def dit_short_loop0_loop0.body
  (h : Std.Usize) (input_bound : kzg.fr8.Fr8) (product_bound : kzg.fr8.Fr8)
  (group : Std.Usize) (self : kzg.fft8.Fft8) (t : Array kzg.fr8.Fr8 8#usize)
  (j : Std.Usize) :
  Result (ControlFlow (kzg.fft8.Fft8 × (Array kzg.fr8.Fr8 8#usize) ×
    Std.Usize) (kzg.fft8.Fft8 × (Array kzg.fr8.Fr8 8#usize)))
  := do
  if j < h
  then
    let i ← group + j
    let a ← Array.index_usize t i
    let i1 ← i + h
    let b ← Array.index_usize t i1
    let (self1, product, bound) ←
      if j = 0#usize
      then ok (self, b, input_bound)
      else
        do
        let f ← kzg.fr8.Fr8.normalise b
        let i2 ← h - 1#usize
        let i3 ← i2 + j
        let f1 ←
          alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice
            kzg.fr8.Fr8) self.short i3
        let f2 ← kzg.fr8.Fr8.mul f f1
        ok (self, f2, product_bound)
    let f ← kzg.fr8.Fr8.add_raw a product
    let t1 ← Array.update t i f
    let f1 ← kzg.fr8.Fr8.sub_raw a product bound
    let i2 ← i + h
    let a1 ← Array.update t1 i2 f1
    let j1 ← j + 1#usize
    ok (cont (self1, a1, j1))
  else ok (done (self, t))

def dit_short_loop0_loop0
  (self : kzg.fft8.Fft8) (t : Array kzg.fr8.Fr8 8#usize) (h : Std.Usize)
  (input_bound : kzg.fr8.Fr8) (product_bound : kzg.fr8.Fr8) (group : Std.Usize)
  (j : Std.Usize) :
  Result (kzg.fft8.Fft8 × (Array kzg.fr8.Fr8 8#usize))
  := do
  loop
    (fun (self1, t1, j1) => dit_short_loop0_loop0.body h
      input_bound product_bound group self1 t1 j1)
    (self, t, j)

def dit_short_loop0.body
  (h : Std.Usize) (input_bound : kzg.fr8.Fr8) (product_bound : kzg.fr8.Fr8)
  (self : kzg.fft8.Fft8) (t : Array kzg.fr8.Fr8 8#usize) (group : Std.Usize) :
  Result (ControlFlow (kzg.fft8.Fft8 × (Array kzg.fr8.Fr8 8#usize) ×
    Std.Usize) (Array kzg.fr8.Fr8 8#usize))
  := do
  if group < kzg.fr8.LANES
  then
    let (self1, t1) ←
      dit_short_loop0_loop0 self t h input_bound product_bound
        group 0#usize
    let i ← 2#usize * h
    let group1 ← group + i
    ok (cont (self1, t1, group1))
  else ok (done t)

def dit_short_loop0
  (self : kzg.fft8.Fft8) (t : Array kzg.fr8.Fr8 8#usize) (h : Std.Usize)
  (input_bound : kzg.fr8.Fr8) (product_bound : kzg.fr8.Fr8) (group : Std.Usize)
  :
  Result (Array kzg.fr8.Fr8 8#usize)
  := do
  loop
    (fun (self1, t1, group1) => dit_short_loop0.body h
      input_bound product_bound self1 t1 group1)
    (self, t, group)

def dit_short
  (self : kzg.fft8.Fft8) (t : Array kzg.fr8.Fr8 8#usize) (h : Std.Usize) :
  Result (Array kzg.fr8.Fr8 8#usize)
  := do
  let i ← lift (UScalar.cast .U64 h)
  let i1 ← 2#u64 * i
  let input_bound ← kzg.fr8.Fr8.multiple_of_r i1
  let product_bound ← kzg.fr8.Fr8.multiple_of_r 2#u64
  dit_short_loop0 self t h input_bound product_bound 0#usize


def dif_short_loop0_loop0.body
  (h : Std.Usize) (input_bound : kzg.fr8.Fr8) (group : Std.Usize)
  (self : kzg.fft8.Fft8) (t : Array kzg.fr8.Fr8 8#usize) (j : Std.Usize) :
  Result (ControlFlow (kzg.fft8.Fft8 × (Array kzg.fr8.Fr8 8#usize) ×
    Std.Usize) (kzg.fft8.Fft8 × (Array kzg.fr8.Fr8 8#usize)))
  := do
  if j < h
  then
    let i ← group + j
    let a ← Array.index_usize t i
    let i1 ← i + h
    let b ← Array.index_usize t i1
    let f ← kzg.fr8.Fr8.add a b
    let t1 ← Array.update t i f
    let (self1, f1) ←
      if j = 0#usize
      then do
           let f2 ← kzg.fr8.Fr8.sub a b
           ok (self, f2)
      else
        do
        let f2 ← kzg.fr8.Fr8.sub_raw a b input_bound
        let f3 ← kzg.fr8.Fr8.normalise f2
        let i2 ← h - 1#usize
        let i3 ← i2 + j
        let f4 ←
          alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice
            kzg.fr8.Fr8) self.short i3
        let f5 ← kzg.fr8.Fr8.mul f3 f4
        ok (self, f5)
    let i2 ← i + h
    let a1 ← Array.update t1 i2 f1
    let j1 ← j + 1#usize
    ok (cont (self1, a1, j1))
  else ok (done (self, t))

def dif_short_loop0_loop0
  (self : kzg.fft8.Fft8) (t : Array kzg.fr8.Fr8 8#usize) (h : Std.Usize)
  (input_bound : kzg.fr8.Fr8) (group : Std.Usize) (j : Std.Usize) :
  Result (kzg.fft8.Fft8 × (Array kzg.fr8.Fr8 8#usize))
  := do
  loop
    (fun (self1, t1, j1) => dif_short_loop0_loop0.body h
      input_bound group self1 t1 j1)
    (self, t, j)

def dif_short_loop0.body
  (h : Std.Usize) (input_bound : kzg.fr8.Fr8) (self : kzg.fft8.Fft8)
  (t : Array kzg.fr8.Fr8 8#usize) (group : Std.Usize) :
  Result (ControlFlow (kzg.fft8.Fft8 × (Array kzg.fr8.Fr8 8#usize) ×
    Std.Usize) (Array kzg.fr8.Fr8 8#usize))
  := do
  if group < kzg.fr8.LANES
  then
    let (self1, t1) ←
      dif_short_loop0_loop0 self t h input_bound group 0#usize
    let i ← 2#usize * h
    let group1 ← group + i
    ok (cont (self1, t1, group1))
  else ok (done t)

def dif_short_loop0
  (self : kzg.fft8.Fft8) (t : Array kzg.fr8.Fr8 8#usize) (h : Std.Usize)
  (input_bound : kzg.fr8.Fr8) (group : Std.Usize) :
  Result (Array kzg.fr8.Fr8 8#usize)
  := do
  loop
    (fun (self1, t1, group1) => dif_short_loop0.body h
      input_bound self1 t1 group1)
    (self, t, group)

def dif_short
  (self : kzg.fft8.Fft8) (t : Array kzg.fr8.Fr8 8#usize) (h : Std.Usize) :
  Result (Array kzg.fr8.Fr8 8#usize)
  := do
  let input_bound ← kzg.fr8.Fr8.multiple_of_r 2#u64
  dif_short_loop0 self t h input_bound 0#usize


end LeanBlsSimd.Kzg.Extender.Kernel.ShortModel
