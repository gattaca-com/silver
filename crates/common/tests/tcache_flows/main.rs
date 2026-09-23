//! Deterministic consumer-tail flows over real TCaches. The spine is modelled
//! as FIFOs, tiles as scripted nodes; see `docs/tcache-tail-watermarks.md`.

mod model;
mod patterns;
