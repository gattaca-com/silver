import LeanBlsSimd.Model.G1x8

namespace LeanBlsSimd.Msm8

def batchInverse (values : Vector Fp8 4) : Vector Fp8 4 :=
  let p1 := values[0].mul values[1]
  let p2 := p1.mul values[2]
  let p3 := p2.mul values[3]
  let i3 := p3.inverse
  let i2 := i3.mul values[3]
  let i1 := i2.mul values[2]
  #v[i1.mul values[1], i1.mul values[0], i2.mul p1, i3.mul p2]

def affineAdd (xa ya xb yb inverse : Fp8) : Fp8 × Fp8 :=
  let o := G1x8.Offsets.new
  let dy := (yb.sub_raw ya o.two_p).normalise
  let slope := dy.mul inverse
  let squared := slope.square
  let x3 := o.reduced_from_8p ((squared.sub_raw xa o.two_p).sub_raw xb o.two_p)
  let product := slope.mul ((xa.sub_raw x3 o.two_p).normalise)
  let y3 := o.reduced_from_4p (product.sub_raw ya o.two_p)
  (x3, y3)

end LeanBlsSimd.Msm8
