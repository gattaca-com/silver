use flux::timing::Nanos;
use silver_common::{BlockSource, ColumnSource, PayloadValidationStatus};

#[derive(Clone, Copy, Debug)]
pub enum Stage {
    /// A root's first `BlockReceived`, at its ingestion.
    Received {
        source: BlockSource,
    },
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
    DaAvailable,
    /// Every column this node custodies is held: the 64 → 128 tail past the
    /// gate, a duty of the node rather than a wait of the block.
    CustodyDone,
    /// Post-state committed: publish of the root's first `BlockReceived`
    /// past `AwaitParent`. Precedes `Attestable` when data gated the import.
    StfDone,
    /// Imported into fork choice with the new head published: publish of the
    /// root's first `BlockReceived { stage: Applied }`, ahead of the FCU.
    Attestable,
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
            Self::CustodyDone => "custody_done",
            Self::StfDone => "stf_done",
            Self::Attestable => "attestable",
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
