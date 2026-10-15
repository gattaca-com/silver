import Differential.G2
import Differential.G1

def main (args : List String) : IO UInt32 :=
  match args with
  | [path] => DifferentialTest.run path
  | ["--g1", path] => DifferentialTest.G1.run path
  | [g2, "--g1", g1] => do
    let a ← DifferentialTest.run g2
    let b ← DifferentialTest.G1.run g1
    pure (max a b)
  | _ => do
    IO.eprintln "usage: differential <g2 vectors> [--g1 <g1 vectors>] | --g1 <g1 vectors>"
    pure 2
