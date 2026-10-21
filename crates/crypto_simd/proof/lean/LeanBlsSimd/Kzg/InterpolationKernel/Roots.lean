import LeanBlsSimd.Kzg.Extender.Kernel.Fft

open EthCryptographySpecs Bls Kzg

namespace LeanBlsSimd.Kzg.InterpolationKernel

open Extender.Kernel

theorem cell_roots_valid :
    RootsValid (Model.roots 6) ∧ RootsValid (Model.inverseRoots (Model.roots 6)) := by
  have hroots : RootsValid (Model.roots 6) := by
    refine ⟨domainRoot 64, 6, ?_, domainRoot_64_primitive, ?_⟩
    · exact size_computeRootsOfUnity _
    · intro i hi
      apply getElem!_computeRootsOfUnity_pow
      simpa [Model.roots, size_computeRootsOfUnity] using hi
  exact ⟨hroots, inverse_roots_valid _ hroots⟩

end LeanBlsSimd.Kzg.InterpolationKernel
