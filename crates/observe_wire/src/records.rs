use std::net::SocketAddr;

/// Longer ids are truncated; libp2p ids top out at 42 bytes in practice.
pub const PEER_ID_MAX: usize = 44;
pub const USER_AGENT_MAX: usize = 64;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceClass {
    Counters = 0,
    TCache = 1,
    Timing = 2,
    Tile = 3,
}

/// `id` is assigned by the exporter and stable for one `boot_id`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Source<'a> {
    pub id: u16,
    pub class: SourceClass,
    pub name: &'a str,
}

/// One bucket of one tile's loop: busy/total ticks summed, plus
/// work-iteration count and the longest iteration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TileUtil {
    pub source_id: u16,
    pub busy: u64,
    pub total: u64,
    pub busy_count: u64,
    pub busy_max: u64,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimingChannel {
    Latency = 0,
    Processing = 1,
}

/// One bucket of one timing channel's distribution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimingStats {
    pub source_id: u16,
    pub channel: TimingChannel,
    pub count: u64,
    pub p50_ns: u64,
    pub p99_ns: u64,
    pub max_ns: u64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PeerP2p<'a> {
    pub peer: &'a [u8],
    pub connection: u64,
    pub addr: SocketAddr,
    pub inbound: bool,
    pub connected_ms: u64,
    pub rtt_us: u64,
    pub lost_packets: u64,
    pub rx_blocking: u64,
    pub tx_blocking: u64,
    pub rx_datagrams: u64,
    pub tx_datagrams: u64,
    pub streams: u64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PeerScores<'a> {
    pub peer: &'a [u8],
    pub user_agent: &'a str,
    pub mesh_count: u32,
    pub p1_time_in_mesh: f64,
    pub p2_first_deliveries: f64,
    pub p3_mesh_deficit: f64,
    pub p3b_mesh_failure: f64,
    pub p4_invalid: f64,
    pub p5_application: f64,
    pub p6_ip_colocation: f64,
    pub p7_behaviour: f64,
    pub total: f64,
}

/// `topic_slot` indexes the `gossip_topics` counter source: its slot names
/// `4 * topic_slot ..` are `{topic}_sent`, `_recv`, `_mesh`, `_subs`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PeerTopic<'a> {
    pub peer: &'a [u8],
    pub topic_slot: u16,
    pub p3_scored: bool,
    pub mesh_active: bool,
    pub meshed_secs: u64,
    pub fanout_total: u64,
    pub fanout_sent: u64,
    pub first_deliveries: f64,
    pub mesh_deliveries: f64,
    pub mesh_failure_penalty: f64,
    pub invalid_deliveries: f64,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StageCode {
    Received = 0,
    ColumnRecv = 1,
    ColumnValidated = 2,
    ElSent = 3,
    ElVerdict = 4,
    DaAvailable = 5,
    CustodyDone = 6,
    StfDone = 7,
    Attestable = 8,
}

/// `detail` by stage: `Received`/`ElSent` block source (0 gossip, 1 rpc);
/// `Column*` origin (0 gossip, 1 rpc, 2 el, 3 assembly); `ElVerdict` status
/// (0 valid, 1 invalid, 2 syncing, 3 accepted); 0 otherwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StageRecord {
    pub block_root: [u8; 32],
    pub ts_ns: u64,
    pub slot: Option<u64>,
    pub column_index: Option<u64>,
    pub stage: StageCode,
    pub detail: u8,
}
