use std::time::{Duration, Instant};

use rustc_hash::FxHashMap;
use silver_common::NodeId;

use crate::message::{Distances, RequestId};

/// Our own responses never exceed this: at most 16 ENRs, at least one per
/// packet. A larger `total` is not trusted.
const MAX_RESPONSES: u8 = 16;

struct FindNodeRequest {
    to_id: NodeId,
    distances: Distances,
    responses: u8,
    sent_at: Instant,
}

#[derive(Default)]
pub struct FindNodeRequests(FxHashMap<RequestId, FindNodeRequest>);

impl FindNodeRequests {
    pub fn record(
        &mut self,
        request_id: RequestId,
        to_id: NodeId,
        distances: Distances,
        sent_at: Instant,
    ) {
        self.0.insert(request_id, FindNodeRequest { to_id, distances, responses: 0, sent_at });
    }

    /// Returns the requested distances when a NODES packet answers an
    /// outstanding request, and retires the request after its last packet.
    pub fn accept_response(
        &mut self,
        request_id: &RequestId,
        from: &NodeId,
        total: u8,
    ) -> Option<Distances> {
        let request = self.0.get_mut(request_id).filter(|r| r.to_id == *from)?;
        request.responses += 1;
        let distances = request.distances;
        if request.responses >= total.clamp(1, MAX_RESPONSES) {
            self.0.remove(request_id);
        }
        Some(distances)
    }

    pub fn is_outstanding_to(&self, id: &NodeId) -> bool {
        self.0.values().any(|r| r.to_id == *id)
    }

    pub fn forget(&mut self, id: &NodeId) {
        self.0.retain(|_, r| r.to_id != *id);
    }

    pub fn expire(&mut self, ttl: Duration) {
        self.0.retain(|_, r| r.sent_at.elapsed() < ttl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn distances(ds: &[u64]) -> Distances {
        let mut out = Distances::new();
        out.extend(ds.iter().copied());
        out
    }

    #[test]
    fn response_must_come_from_the_requested_node() {
        let mut requests = FindNodeRequests::default();
        let (to, other) = (NodeId::random(), NodeId::random());
        let rid = RequestId::from(1u64);
        requests.record(rid, to, distances(&[255, 256]), Instant::now());

        assert!(requests.accept_response(&rid, &other, 1).is_none());
        assert!(requests.accept_response(&RequestId::from(2u64), &to, 1).is_none());
        assert_eq!(requests.accept_response(&rid, &to, 1).unwrap().as_slice(), &[255, 256]);
        assert!(requests.accept_response(&rid, &to, 1).is_none(), "retired after total");
    }

    #[test]
    fn total_is_capped() {
        let mut requests = FindNodeRequests::default();
        let to = NodeId::random();
        let rid = RequestId::from(1u64);
        requests.record(rid, to, distances(&[256]), Instant::now());

        for _ in 0..MAX_RESPONSES {
            assert!(requests.accept_response(&rid, &to, u8::MAX).is_some());
        }
        assert!(requests.accept_response(&rid, &to, u8::MAX).is_none());
    }
}
