use std::sync::LazyLock;

use flux_profiler::timed;

use crate::{
    merkle::{B256, FixedContainer, ZERO_HASH, hash_fixed_bytes, merkleize, uint64_chunk},
    progressive::{ProgressiveContainer, ProgressiveHasher, packed_active_fields},
    ssz_view::{
        BUILDER_DEPOSIT_REQUEST_SIZE, BUILDER_EXIT_REQUEST_SIZE, BuilderDepositRequestView,
        BuilderExitRequestView, CONSOLIDATION_REQUEST_SIZE, ConsolidationRequestView,
        DEPOSIT_REQUEST_SIZE, DepositRequestView, MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD, MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD, WITHDRAWAL_REQUEST_SIZE, WithdrawalRequestView,
        fixed_list_ok, offsets_ok, variable_field,
    },
};

/// A request list longer than its `MAX_*_REQUESTS_PER_PAYLOAD` preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestCountOutOfBounds {
    pub kind: &'static str,
    pub count: usize,
    pub max: usize,
}

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
    /// Spec `verify_execution_requests_limits`. EIP-7688 progressive lists
    /// carry no type-level bound, so the presets are enforced here; deposits
    /// are unbounded per consensus-specs #5436.
    pub fn check_counts(data: &[u8]) -> Result<(), RequestCountOutOfBounds> {
        let [_deposits, withdrawals, consolidations, builder_deposits, builder_exits] =
            Self::sections(data);
        let check = |kind, bytes: &[u8], size: usize, max: usize| {
            let count = bytes.len() / size;
            if count > max { Err(RequestCountOutOfBounds { kind, count, max }) } else { Ok(()) }
        };
        check(
            "withdrawal",
            withdrawals,
            WITHDRAWAL_REQUEST_SIZE,
            MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        )?;
        check(
            "consolidation",
            consolidations,
            CONSOLIDATION_REQUEST_SIZE,
            MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
        )?;
        check(
            "builder_deposit",
            builder_deposits,
            BUILDER_DEPOSIT_REQUEST_SIZE,
            MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD,
        )?;
        check(
            "builder_exit",
            builder_exits,
            BUILDER_EXIT_REQUEST_SIZE,
            MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD,
        )
    }

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

    pub fn check_canonical(data: &[u8]) -> bool {
        const OFFSETS: [usize; 5] = [0, 4, 8, 12, 16];
        const ELEMENT_SIZES: [usize; 5] = [
            DEPOSIT_REQUEST_SIZE,
            WITHDRAWAL_REQUEST_SIZE,
            CONSOLIDATION_REQUEST_SIZE,
            BUILDER_DEPOSIT_REQUEST_SIZE,
            BUILDER_EXIT_REQUEST_SIZE,
        ];
        data.len() >= 20 &&
            offsets_ok(data, &OFFSETS, 20) &&
            ELEMENT_SIZES.iter().enumerate().all(|(i, &elem)| {
                fixed_list_ok(variable_field(data, &OFFSETS, i), elem, usize::MAX)
            })
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
