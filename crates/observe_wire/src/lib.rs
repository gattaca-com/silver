//! Datagram format between the node-side exporter and the dashboard. All
//! integers little-endian. Every datagram is self-contained: no reassembly,
//! and loss costs only the points it carried.
//!
//! Header (`HEADER_LEN` = 40):
//!
//! | off | field       | type |
//! |-----|-------------|------|
//! | 0   | magic       | u32  |
//! | 4   | version     | u16  |
//! | 6   | kind        | u16  |
//! | 8   | instance_id | u64  |
//! | 16  | boot_id     | u64  |
//! | 24  | seq         | u64  |
//! | 32  | ts_ns       | u64  |
//!
//! Payload by kind, offsets from payload start:
//!
//! | kind          | prefix                                          | entry                                                                 |
//! |---------------|-------------------------------------------------|-----------------------------------------------------------------------|
//! | Sources       | count u16                                       | id u16, class u8, len u8, name[len]                                   |
//! | SlotNames     | source_id u16, count u16, first_slot u32        | len u8, name[len]                                                     |
//! | BuildInfo     | —                                               | utf-8 text to end of datagram                                         |
//! | CounterValues | source_id u16, count u16, first_slot u32        | value u64                                                             |
//! | TileUtils     | count u16, pad[6]                               | source_id u16, pad[6], busy u64, total u64, busy_count u64, busy_max u64 |
//! | Timings       | count u16, pad[6]                               | source_id u16, channel u8, pad[5], count u64, p50_ns u64, p99_ns u64, max_ns u64 |
//! | Instance      | —                                               | utf-8 label to end of datagram                                        |
//! | Chain         | genesis_unix_secs u64, slot_ms u64, gloas_fork_epoch u64 | —                                                            |
//! | PeerP2p       | count u16, pad[6]                               | peer[48], connection u64, addr[24], connected_ms u64, rtt_us u64, lost_packets u64, rx_blocking u64, tx_blocking u64, rx_datagrams u64, tx_datagrams u64, streams u64 |
//! | PeerScores    | count u16, pad[6]                               | peer[48], agent[72], mesh_count u32, pad[4], p1 p2 p3 p3b p4 p5 p6 p7 total f64 |
//! | PeerTopic     | count u16, pad[6]                               | peer[48], topic_slot u16, p3_scored u8, mesh_active u8, pad[4], meshed_secs u64, fanout_total u64, fanout_sent u64, first_deliveries f64, mesh_deliveries f64, mesh_failure_penalty f64, invalid_deliveries f64 |
//! | Stages        | count u16, pad[6]                               | block_root[32], ts_ns u64, slot u64, column_index u64, stage u8, detail u8, pad[6] |
//! | CounterChanges | source_id u16, count u16, pad[4]               | slot u32, pad[4], value u64                                           |
//! | ClusterPeer   | count u16, pad[6]                               | node_id u64, is_leader u8, progress u8, has_link u8, connected u8, pad[4], last_contact_us u64, match_index u64, next_index u64, inflight u64, raft_rtt_us u64, messages_out u64, messages_in u64, rtt_us u64, out_queue_len u64, overwrites u64 |
//! | ClusterCommit | count u16, pad[6]                               | slot u64, slot_offset_us u64, total_us u64, append_us u64, persist_us u64, quorum_us u64, duty u8, leader_origin u8, outcome u8, pad[5] |
//!
//! Composite fields:
//!
//! - `peer[48]`: len u8, id bytes[44] zero-padded, pad[3].
//! - `addr[24]`: family u8 (4 or 6), inbound u8, port u16, pad[4], ip[16] (v4
//!   in the first 4 bytes).
//! - `agent[72]`: len u8, pad[7], utf-8 bytes[64] zero-padded.
//! - `slot`, `column_index`, `last_contact_us`, `raft_rtt_us`, `append_us`,
//!   `persist_us`, `quorum_us`: u64::MAX when absent.
//! - `gloas_fork_epoch`: u64::MAX when Gloas is not scheduled.
//! - `progress`: 0 follower, 1 probe, 2 replicate, 3 snapshot.
//! - `duty`: 0 attestation, 1 block. `outcome`: 0 accepted, 1 same, 2
//!   conflicting, 3 surrounding, 4 too old, 5 invalid, 6 timed out.
//!
//! `CounterChanges` carries only the slots that moved since the source's
//! previous datagram; every source re-sends all its values as
//! `CounterValues` periodically, so a late joiner or a lost datagram leaves a
//! slot unknown or stale for at most that period.
//!
//! Peer and stage kinds are streamed: entries accumulate until the datagram
//! is full, the kind changes, or the exporter flushes.
//!
//! Prefixes before u64 arrays are 8 bytes, so every u64 sits at a multiple of
//! 8 from datagram start.

mod encoder;
mod header;
mod records;

pub use encoder::Encoder;
pub use header::{HEADER_LEN, Header, Kind, MAGIC, MAX_DATAGRAM, VERSION};
pub use records::{
    ClusterCommit, ClusterDutyCode, ClusterLink, ClusterOutcomeCode, ClusterPeer,
    ClusterProgressCode, PEER_ID_MAX, PeerP2p, PeerScores, PeerTopic, Source, SourceClass,
    StageCode, StageRecord, TileUtil, TimingChannel, TimingStats, USER_AGENT_MAX,
};
