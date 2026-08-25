use std::time::{Duration, Instant};

use silver_common::{RpcSeverity, StreamProtocol, SyncRequest};

use crate::PeerManager;

impl PeerManager {
    pub(crate) fn track_outbound_attempt(&mut self, attempt: OutboundAttempt) {
        self.outbound_attempts.retain(|existing| {
            existing.request_id != attempt.request_id ||
                existing.peer_id != attempt.peer_id ||
                existing.request.protocol() != attempt.request.protocol()
        });
        self.outbound_attempts.push(attempt);
    }

    pub(super) fn progress_outbound_attempt(
        &mut self,
        request_id: u64,
        peer_id: usize,
        protocol: StreamProtocol,
        now: Instant,
    ) {
        if let Some(attempt) = self.outbound_attempts.iter_mut().find(|attempt| {
            attempt.request_id == request_id &&
                attempt.peer_id == peer_id &&
                attempt.request.protocol() == protocol
        }) {
            attempt.last_progress_at = now;
        }
    }

    fn finish_attempt_at(&mut self, pos: usize, delivered: bool) {
        let attempt = self.outbound_attempts.swap_remove(pos);
        let clean = delivered && attempt.siblings_clean;

        let mut last = true;
        for sibling in &mut self.outbound_attempts {
            if sibling.request_id == attempt.request_id {
                sibling.siblings_clean &= clean;
                last = false;
            }
        }
        tracing::debug!(
            request_id = attempt.request_id,
            peer_id = attempt.peer_id,
            protocol = ?attempt.request.protocol(),
            delivered,
            last,
            "outbound attempt finished"
        );
        if last {
            self.finished_requests.push((attempt.request_id, attempt.peer_id, clean));
        }
    }

    fn finish_attempts_where(
        &mut self,
        delivered: bool,
        mut pred: impl FnMut(&OutboundAttempt) -> bool,
    ) {
        while let Some(pos) = self.outbound_attempts.iter().position(&mut pred) {
            self.finish_attempt_at(pos, delivered);
        }
    }

    pub(crate) fn finish_attempt(
        &mut self,
        request_id: u64,
        peer_id: usize,
        protocol: StreamProtocol,
        delivered: bool,
    ) {
        if let Some(pos) = self.outbound_attempts.iter().position(|attempt| {
            attempt.request_id == request_id &&
                attempt.peer_id == peer_id &&
                attempt.request.protocol() == protocol
        }) {
            self.finish_attempt_at(pos, delivered);
        }
    }

    pub(crate) fn fail_attempt_on_stream_close(
        &mut self,
        peer_id: usize,
        protocol: StreamProtocol,
    ) {
        if let Some(pos) = self.outbound_attempts.iter().position(|attempt| {
            attempt.peer_id == peer_id && attempt.request.protocol() == protocol
        }) {
            self.finish_attempt_at(pos, false);
        }
    }

    pub(crate) fn fail_attempts_on_disconnect(&mut self, peer_id: usize) {
        self.finish_attempts_where(false, |attempt| attempt.peer_id == peer_id);
    }

    pub(crate) fn sweep_stalled_attempts(&mut self, now: Instant) {
        let timeout = Duration::from_millis(self.syncing.inflight_progress_timeout_ms);
        while let Some(pos) = self
            .outbound_attempts
            .iter()
            .position(|attempt| now.saturating_duration_since(attempt.last_progress_at) >= timeout)
        {
            let (peer_id, protocol) = (
                self.outbound_attempts[pos].peer_id,
                self.outbound_attempts[pos].request.protocol(),
            );
            self.finish_attempt_at(pos, false);

            if let Some(peer) = self.peers.get_mut(&peer_id) {
                let ord = protocol.ordinal() as usize;
                peer.outbound_in_flight[ord] = peer.outbound_in_flight[ord].saturating_sub(1);
            }
            self.on_rpc_misbehaviour(
                peer_id,
                RpcSeverity::HighTolerance,
                "outbound request progress stall",
            );
        }
    }

    /// An admitted request never reached the wire:
    /// no response terminator or stream close will ever fire for it, so the
    /// in-flight slot must be released here or it leaks until disconnect
    /// (2 leaks brick the peer for that protocol —
    /// `MAX_RPC_PROTOCOL_IN_FLIGHT`).
    pub(super) fn release_outbound_in_flight(&mut self, conn: usize, protocol: StreamProtocol) {
        if let Some(peer) = self.peers.get_mut(&conn) {
            let ord = protocol.ordinal() as usize;
            peer.outbound_in_flight[ord] = peer.outbound_in_flight[ord].saturating_sub(1);
            tracing::debug!(
                conn,
                ?protocol,
                in_flight = peer.outbound_in_flight[ord],
                "released in-flight slot for failed send"
            );
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct OutboundAttempt {
    pub request_id: u64,
    pub peer_id: usize,
    /// What was asked for. `protocol` is derived, and the scope is what lets
    /// the by-root column cap tell one root from another.
    pub request: SyncRequest,
    pub last_progress_at: Instant,
    /// Cleared when any attempt under this `request_id` ends badly, so
    /// whichever attempt finishes last reports the outcome for all of them.
    pub siblings_clean: bool,
}
