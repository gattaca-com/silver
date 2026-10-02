use rustc_hash::FxHashMap;
use silver_beacon_state_data::B256;
use silver_common::ssz_view::BUILDER_EXIT_REQUEST_SIZE;

type BuilderExits = Box<[[u8; BUILDER_EXIT_REQUEST_SIZE]]>;

/// Builder exit requests of verified payloads, by block root. A child building
/// on a payload applies them; its block's post-state never does. Payloads
/// without exits have no entry.
#[derive(Default)]
pub(super) struct PayloadBuilderExits(FxHashMap<B256, BuilderExits>);

impl PayloadBuilderExits {
    pub fn insert(&mut self, block_root: B256, exits: BuilderExits) {
        if !exits.is_empty() {
            self.0.insert(block_root, exits);
        }
    }

    pub fn get(&self, block_root: &B256) -> &[[u8; BUILDER_EXIT_REQUEST_SIZE]] {
        self.0.get(block_root).map_or(&[], |exits| exits)
    }

    pub fn drop_outdated(&mut self, is_live: impl Fn(&B256) -> bool) {
        self.0.retain(|block_root, _| is_live(block_root));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_payloads_with_exits_are_held() {
        let mut exits = PayloadBuilderExits::default();
        exits.insert([1; 32], Box::default());
        exits.insert([2; 32], Box::new([[7; BUILDER_EXIT_REQUEST_SIZE]]));
        assert!(exits.0.len() == 1 && exits.get(&[1; 32]).is_empty());
        assert_eq!(exits.get(&[2; 32]), [[7; BUILDER_EXIT_REQUEST_SIZE]]);

        exits.drop_outdated(|root| *root != [2; 32]);
        assert!(exits.get(&[2; 32]).is_empty());
    }
}
