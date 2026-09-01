use flux::timing::Nanos;
use silver_common::{BlockSource, ColumnSource, PayloadValidationStatus};

/// Where in the node's pipeline the event was taken, carrying that point's
/// own data.
#[derive(Clone, Copy, Debug)]
pub enum Stage {
    /// A root's first `BlockReceived`, at its ingestion from gossip
    Received {
        source: BlockSource,
    },
    /// A data-column sidecar's arrival on the wire.
    ColumnRecv {
        index: u64,
        source: ColumnSource,
    },
    /// The same sidecar past validation; the gap from `ColumnRecv` is the
    /// columns tile's queue delay.
    ColumnValidated {
        index: u64,
        source: ColumnSource,
    },
    /// `NewPayload` publish: CL validated, dispatched to the EL
    ElSent {
        source: BlockSource,
    },
    ElVerdict {
        verdict: PayloadValidationStatus,
    },
    /// The block's data exists and its DA gate opens.
    DaAvailable,
    /// An FCU naming the root: state transition + commit. Repeat-head and
    /// tick FCUs re-emit it; a root's first `Applied` is the apply.
    Applied,
}

impl Stage {
    pub fn name(self) -> &'static str {
        match self {
            Self::Received { .. } => "received",
            Self::ColumnValidated { .. } => "column_validated",
            Self::ColumnRecv { .. } => "column_recv",
            Self::ElSent { .. } => "el_sent",
            Self::ElVerdict { .. } => "el_verdict",
            Self::DaAvailable => "da_available",
            Self::Applied => "applied",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct StageEvent {
    pub stage: Stage,
    /// Wall clock of the event (unix epoch).
    pub ts: Nanos,
    pub block_root: [u8; 32],
    /// `None` when the message carries no slot and the root was first seen
    /// before the reader attached.
    pub slot: Option<u64>,
}
