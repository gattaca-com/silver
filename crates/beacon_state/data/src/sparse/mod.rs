mod edits;
mod layer;

#[cfg(test)]
mod tests;

pub use edits::Edits;
pub(crate) use layer::{
    SparseLayer, install_against, lookup_sparse, rebase_and_prune_sparse, replace_against,
    set_against, sparse_merge_into, sweep,
};
