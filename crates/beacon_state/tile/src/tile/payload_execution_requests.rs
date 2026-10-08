use rustc_hash::FxHashMap;
use silver_beacon_state_data::B256;
use silver_common::{
    ssz_hash_gloas::{EMPTY_EXECUTION_REQUESTS, ExecutionRequestsView},
    ssz_view::BUILDER_EXIT_REQUEST_SIZE,
};

/// Execution requests of verified payloads, by block root, as the SSZ
/// `ExecutionRequests` the envelope carried. A child building on a payload
/// applies them; its block's post-state never does. Payloads without requests
/// have no entry.
#[derive(Default)]
pub(super) struct PayloadExecutionRequests(FxHashMap<B256, Box<[u8]>>);

impl PayloadExecutionRequests {
    /// `requests` passed `verify_execution_payload_envelope`, which bounds
    /// and roots them.
    pub fn insert(&mut self, block_root: B256, requests: &[u8]) {
        if ExecutionRequestsView::sections(requests).iter().any(|section| !section.is_empty()) {
            self.0.insert(block_root, requests.into());
        }
    }

    /// The `parent_execution_requests` of a block building on this payload.
    pub fn get(&self, block_root: &B256) -> &[u8] {
        self.0.get(block_root).map_or(&EMPTY_EXECUTION_REQUESTS, |requests| requests)
    }

    pub fn builder_exits(
        &self,
        block_root: &B256,
    ) -> impl Iterator<Item = &[u8; BUILDER_EXIT_REQUEST_SIZE]> {
        let [.., builder_exits] = ExecutionRequestsView::sections(self.get(block_root));
        builder_exits
            .chunks_exact(BUILDER_EXIT_REQUEST_SIZE)
            .map(|request| request.try_into().expect("BUILDER_EXIT_REQUEST_SIZE bytes"))
    }

    pub fn drop_outdated(&mut self, is_live: impl Fn(&B256) -> bool) {
        self.0.retain(|block_root, _| is_live(block_root));
    }
}

#[cfg(test)]
mod tests {
    use silver_common::ssz_hash_gloas::EMPTY_EXECUTION_REQUESTS_ROOT;

    use super::*;

    /// One builder exit and nothing else: the first four sections empty.
    fn one_builder_exit(fill: u8) -> Vec<u8> {
        let mut ssz: Vec<u8> = [20u32; 5].iter().flat_map(|offset| offset.to_le_bytes()).collect();
        ssz.extend_from_slice(&[fill; BUILDER_EXIT_REQUEST_SIZE]);
        ssz
    }

    #[test]
    fn only_payloads_with_requests_are_held() {
        let mut requests = PayloadExecutionRequests::default();
        requests.insert([1; 32], &EMPTY_EXECUTION_REQUESTS);
        assert!(requests.0.is_empty());
        assert_eq!(requests.get(&[1; 32]), EMPTY_EXECUTION_REQUESTS);
        assert_eq!(requests.builder_exits(&[1; 32]).count(), 0);

        let exit = one_builder_exit(7);
        requests.insert([2; 32], &exit);
        assert_eq!(requests.get(&[2; 32]), exit);
        assert_eq!(requests.builder_exits(&[2; 32]).collect::<Vec<_>>(), [
            &[7; BUILDER_EXIT_REQUEST_SIZE]
        ]);

        requests.drop_outdated(|root| *root != [2; 32]);
        assert_eq!(requests.get(&[2; 32]), EMPTY_EXECUTION_REQUESTS);
    }

    #[test]
    fn the_empty_container_roots_to_the_empty_requests_root() {
        assert_eq!(
            ExecutionRequestsView::hash_tree_root(&EMPTY_EXECUTION_REQUESTS),
            *EMPTY_EXECUTION_REQUESTS_ROOT
        );
    }
}
