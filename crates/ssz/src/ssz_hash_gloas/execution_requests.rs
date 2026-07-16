use std::sync::LazyLock;

use flux_profiler::timed;

use crate::{
    merkle::{B256, FixedContainer, ZERO_HASH, hash_fixed_bytes, merkleize, uint64_chunk},
    progressive::{ProgressiveContainer, ProgressiveHasher, packed_active_fields},
    ssz_view::{
        BUILDER_DEPOSIT_REQUEST_SIZE, BUILDER_EXIT_REQUEST_SIZE, BuilderDepositRequestView,
        BuilderExitRequestView, ConsolidationRequestView, DepositRequestView,
        WithdrawalRequestView,
    },
};

/// `ExecutionRequests` (five ProgressiveLists) has no wire-view type; this unit
/// struct owns splitting the container into its list bodies and hashing them.
pub struct ExecutionRequestsView;

impl ProgressiveContainer for ExecutionRequestsView {
    const ACTIVE_FIELDS: B256 = packed_active_fields(5);
}

/// `hash_tree_root(ExecutionRequests())` — a program constant (empty-parent
/// checks and the fork block's placeholder bid both compare against it).
pub static EMPTY_EXECUTION_REQUESTS_ROOT: LazyLock<B256> =
    LazyLock::new(|| ExecutionRequestsView::hash_tree_root(&[]));

impl ExecutionRequestsView {
    /// Split the serialized container into its five list bodies: deposits,
    /// withdrawals, consolidations, builder deposits, builder exits.
    pub fn sections(data: &[u8]) -> [&[u8]; 5] {
        let mut out: [&[u8]; 5] = [&[]; 5];
        if data.len() < 20 {
            return out;
        }
        let off = |pos: usize| u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        let bounds = [off(0), off(4), off(8), off(12), off(16)];
        for i in 0..5 {
            let start = bounds[i];
            let end = if i + 1 < 5 { bounds[i + 1] } else { data.len() };
            if start <= end && end <= data.len() {
                out[i] = &data[start..end];
            }
        }
        out
    }

    #[timed]
    pub fn hash_tree_root(data: &[u8]) -> B256 {
        let [deposits, withdrawals, consolidations, builder_deposits, builder_exits] =
            Self::sections(data);
        let fields = [
            DepositRequestView::hash_list(ProgressiveHasher::new(), deposits),
            WithdrawalRequestView::hash_list(ProgressiveHasher::new(), withdrawals),
            ConsolidationRequestView::hash_list(ProgressiveHasher::new(), consolidations),
            BuilderDepositRequestView::hash_list(ProgressiveHasher::new(), builder_deposits),
            BuilderExitRequestView::hash_list(ProgressiveHasher::new(), builder_exits),
        ];
        Self::progressive_root(&fields)
    }
}

impl FixedContainer for BuilderDepositRequestView {
    const SSZ_SIZE: usize = BUILDER_DEPOSIT_REQUEST_SIZE;

    #[timed]
    fn hash_tree_root(bytes: &[u8]) -> B256 {
        let d: &[u8; BUILDER_DEPOSIT_REQUEST_SIZE] = bytes.try_into().unwrap();
        merkleize(&[
            hash_fixed_bytes(Self::pubkey(d)),
            *Self::withdrawal_credentials(d),
            uint64_chunk(Self::amount(d)),
            hash_fixed_bytes(Self::signature(d)),
        ])
    }
}

impl FixedContainer for BuilderExitRequestView {
    const SSZ_SIZE: usize = BUILDER_EXIT_REQUEST_SIZE;

    #[timed]
    fn hash_tree_root(bytes: &[u8]) -> B256 {
        let d: &[u8; BUILDER_EXIT_REQUEST_SIZE] = bytes.try_into().unwrap();
        let mut addr = ZERO_HASH;
        addr[..20].copy_from_slice(Self::source_address(d));
        merkleize(&[addr, hash_fixed_bytes(Self::pubkey(d))])
    }
}
