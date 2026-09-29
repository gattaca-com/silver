use crate::{
    ssz_hash_gloas::{ExecutionRequestsView, RequestCountOutOfBounds},
    ssz_view::{
        BEACON_BLOCK_BODY_FIXED, BeaconBlockBodyFuluView, BeaconBlockBodyGloasView, DEPOSIT_SIZE,
        EXECUTION_PAYLOAD_FIXED, MAX_ATTESTATIONS_ELECTRA, MAX_ATTESTER_SLASHINGS_ELECTRA,
        MAX_BLS_TO_EXECUTION_CHANGES, MAX_PAYLOAD_ATTESTATIONS, MAX_PROPOSER_SLASHINGS,
        MAX_VOLUNTARY_EXITS, PAYLOAD_ATTESTATION_SIZE, PROPOSER_SLASHING_SIZE,
        SIGNED_BLS_CHANGE_SIZE, SIGNED_VOLUNTARY_EXIT_SIZE,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationKind {
    ProposerSlashings,
    AttesterSlashings,
    Attestations,
    Deposits,
    VoluntaryExits,
    BlsToExecutionChanges,
    PayloadAttestations,
}

impl core::fmt::Display for OperationKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::ProposerSlashings => "proposer_slashings",
            Self::AttesterSlashings => "attester_slashings",
            Self::Attestations => "attestations",
            Self::Deposits => "deposits",
            Self::VoluntaryExits => "voluntary_exits",
            Self::BlsToExecutionChanges => "bls_to_execution_changes",
            Self::PayloadAttestations => "payload_attestations",
        };
        f.write_str(s)
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum BlockBodyError {
    #[error("block body too short: len={len} min={min}")]
    BodyTooShort { len: usize, min: usize },
    #[error("execution payload too short: len={len} min={min}")]
    PayloadTooShort { len: usize, min: usize },
    #[error("{op} count {count} exceeds max {max}")]
    OperationCountOutOfBounds { op: OperationKind, count: usize, max: usize },
    #[error("parent {kind} request count {count} exceeds max {max}")]
    RequestCountOutOfBounds { kind: &'static str, count: usize, max: usize },
    #[error(
        "body offset malformed: {field} off={off} body_len={body_len} \
         (next_field_off={next_off:?})"
    )]
    BodyOffsetOutOfRange {
        field: &'static str,
        off: usize,
        next_off: Option<usize>,
        body_len: usize,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyFork {
    Fulu,
    Gloas,
}

impl From<RequestCountOutOfBounds> for BlockBodyError {
    fn from(e: RequestCountOutOfBounds) -> Self {
        Self::RequestCountOutOfBounds { kind: e.kind, count: e.count, max: e.max }
    }
}

/// Payload bytes with the fixed prefix present, so every `ExecutionPayloadView`
/// accessor is in bounds.
#[derive(Clone, Copy)]
pub struct Payload<'a>(&'a [u8]);

impl<'a> Payload<'a> {
    pub fn new(bytes: &'a [u8]) -> Result<Self, BlockBodyError> {
        if bytes.len() < EXECUTION_PAYLOAD_FIXED {
            return Err(BlockBodyError::PayloadTooShort {
                len: bytes.len(),
                min: EXECUTION_PAYLOAD_FIXED,
            });
        }
        Ok(Self(bytes))
    }

    #[inline]
    pub fn bytes(self) -> &'a [u8] {
        self.0
    }
}

/// A body's fixed part and variable fields, which need not share one buffer:
/// a proposer assembles its body from the pieces it holds.
#[derive(Clone, Copy)]
pub struct BodyOffsets<'a> {
    fork: BodyFork,
    fixed: &'a [u8],
    /// `None` for a field whose offsets do not bound a slice of the body.
    fields: [Option<&'a [u8]>; 9],
    len: usize,
    serialized: Option<&'a [u8]>,
}

impl<'a> BodyOffsets<'a> {
    pub fn new(body: &'a [u8], fork: BodyFork) -> Result<Self, BlockBodyError> {
        if body.len() < BEACON_BLOCK_BODY_FIXED {
            return Err(BlockBodyError::BodyTooShort {
                len: body.len(),
                min: BEACON_BLOCK_BODY_FIXED,
            });
        }
        let fixed = &body[..BEACON_BLOCK_BODY_FIXED];
        let offset = |i: usize| {
            let at = BeaconBlockBodyFuluView::VARIABLE_OFFSETS[i];
            u32::from_le_bytes(fixed[at..at + 4].try_into().expect("4 bytes")) as usize
        };
        let fields = std::array::from_fn(|i| {
            let (start, end) = (offset(i), if i + 1 < 9 { offset(i + 1) } else { body.len() });
            (start <= end && end <= body.len()).then(|| &body[start..end])
        });
        let offsets = Self { fork, fixed, fields, len: body.len(), serialized: Some(body) };
        if fork == BodyFork::Fulu {
            Payload::new(offsets.payload_bytes())?;
        }
        Ok(offsets)
    }

    /// A Fulu body from its fixed part and each variable field in
    /// serialization order.
    pub(crate) fn from_parts(
        fixed: &'a [u8],
        fields: [&'a [u8]; 9],
    ) -> Result<Self, BlockBodyError> {
        assert_eq!(fixed.len(), BEACON_BLOCK_BODY_FIXED, "the fixed part is exactly fixed-size");
        let len = BEACON_BLOCK_BODY_FIXED + fields.iter().map(|field| field.len()).sum::<usize>();
        let offsets =
            Self { fork: BodyFork::Fulu, fixed, fields: fields.map(Some), len, serialized: None };
        Payload::new(offsets.payload_bytes())?;
        Ok(offsets)
    }

    pub fn validated(body: &'a [u8], fork: BodyFork) -> Result<Self, BlockBodyError> {
        let offsets = Self::new(body, fork)?;
        offsets.validate()?;
        Ok(offsets)
    }

    #[inline]
    pub fn fork(&self) -> BodyFork {
        self.fork
    }

    /// `randao_reveal`, `eth1_data`, `graffiti`, the offsets and
    /// `sync_aggregate`: every accessor of the fixed layout reads it.
    #[inline]
    pub fn fixed(&self) -> &'a [u8] {
        self.fixed
    }

    /// The body as one buffer, when it was parsed from one.
    #[inline]
    pub fn serialized(&self) -> Option<&'a [u8]> {
        self.serialized
    }

    #[inline]
    pub fn proposer_slashings(&self) -> Option<&'a [u8]> {
        self.fields[0]
    }
    #[inline]
    pub fn attester_slashings(&self) -> Option<&'a [u8]> {
        self.fields[1]
    }
    #[inline]
    pub fn attestations(&self) -> Option<&'a [u8]> {
        self.fields[2]
    }
    #[inline]
    pub fn deposits(&self) -> Option<&'a [u8]> {
        self.fields[3]
    }
    #[inline]
    pub fn voluntary_exits(&self) -> Option<&'a [u8]> {
        self.fields[4]
    }
    #[inline]
    pub fn bls_changes(&self) -> Option<&'a [u8]> {
        match self.fork {
            BodyFork::Fulu => self.fields[6],
            BodyFork::Gloas => self.fields[5],
        }
    }
    #[inline]
    pub fn sync_aggregate(&self) -> &'a [u8] {
        &BeaconBlockBodyFuluView::sync_aggregate(self.fixed)[..]
    }

    #[inline]
    pub fn payload(&self) -> Payload<'a> {
        debug_assert_eq!(self.fork, BodyFork::Fulu);
        Payload(self.payload_bytes())
    }

    fn payload_bytes(&self) -> &'a [u8] {
        self.fields[5].unwrap_or(&[])
    }

    #[inline]
    pub fn blob_commitments_fulu(&self) -> &'a [u8] {
        self.fields[7].unwrap_or(&[])
    }

    #[inline]
    pub fn execution_requests(&self) -> &'a [u8] {
        self.fields[8].unwrap_or(&[])
    }

    #[inline]
    pub fn signed_bid(&self) -> Option<&'a [u8]> {
        self.fields[6]
    }
    #[inline]
    pub fn payload_attestations(&self) -> Option<&'a [u8]> {
        self.fields[7]
    }

    #[inline]
    pub fn parent_execution_requests(&self) -> &'a [u8] {
        self.fields[8].unwrap_or(&[])
    }

    /// `(field_name, offset)` of every variable field, in serialization order.
    /// Names track the fork; byte positions stay inside `ssz_view`'s accessors.
    fn variable_offsets(&self) -> [(&'static str, usize); 9] {
        let b = self.fixed;
        let f = |name, off: u32| (name, off as usize);
        match self.fork {
            BodyFork::Fulu => [
                f("proposer_slashings", BeaconBlockBodyFuluView::proposer_slashings_offset(b)),
                f("attester_slashings", BeaconBlockBodyFuluView::attester_slashings_offset(b)),
                f("attestations", BeaconBlockBodyFuluView::attestations_offset(b)),
                f("deposits", BeaconBlockBodyFuluView::deposits_offset(b)),
                f("voluntary_exits", BeaconBlockBodyFuluView::voluntary_exits_offset(b)),
                f("execution_payload", BeaconBlockBodyFuluView::execution_payload_offset(b)),
                f(
                    "bls_to_execution_changes",
                    BeaconBlockBodyFuluView::bls_to_execution_changes_offset(b),
                ),
                f("blob_kzg_commitments", BeaconBlockBodyFuluView::blob_kzg_commitments_offset(b)),
                f("execution_requests", BeaconBlockBodyFuluView::execution_requests_offset(b)),
            ],
            BodyFork::Gloas => [
                f("proposer_slashings", BeaconBlockBodyGloasView::proposer_slashings_offset(b)),
                f("attester_slashings", BeaconBlockBodyGloasView::attester_slashings_offset(b)),
                f("attestations", BeaconBlockBodyGloasView::attestations_offset(b)),
                f("deposits", BeaconBlockBodyGloasView::deposits_offset(b)),
                f("voluntary_exits", BeaconBlockBodyGloasView::voluntary_exits_offset(b)),
                f(
                    "bls_to_execution_changes",
                    BeaconBlockBodyGloasView::bls_to_execution_changes_offset(b),
                ),
                f(
                    "signed_execution_payload_bid",
                    BeaconBlockBodyGloasView::signed_execution_payload_bid_offset(b),
                ),
                f("payload_attestations", BeaconBlockBodyGloasView::payload_attestations_offset(b)),
                f(
                    "parent_execution_requests",
                    BeaconBlockBodyGloasView::parent_execution_requests_offset(b),
                ),
            ],
        }
    }

    /// Offset-table (in-bounds + monotone) and operation-count validation. The
    /// structural and shared-cap checks run for both forks; Gloas additionally
    /// caps payload attestations.
    pub fn validate(&self) -> Result<(), BlockBodyError> {
        let body_len = self.len;
        let table = self.variable_offsets();
        for (i, &(field, off)) in table.iter().enumerate() {
            let next_off = table.get(i + 1).map(|&(_, o)| o);
            if off > body_len || next_off.is_some_and(|n| n < off) {
                return Err(BlockBodyError::BodyOffsetOutOfRange { field, off, next_off, body_len });
            }
        }

        let check = |op: OperationKind, count: usize, max: usize| -> Result<(), BlockBodyError> {
            if count > max {
                Err(BlockBodyError::OperationCountOutOfBounds { op, count, max })
            } else {
                Ok(())
            }
        };
        let fixed_count = |s: Option<&[u8]>, elem: usize| s.map_or(0, |s| s.len() / elem);
        // Variable-size list count read from its offset table: first entry / 4.
        let var_count = |s: Option<&[u8]>| {
            s.map_or(0, |s| {
                if s.len() < 4 {
                    return 0;
                }
                let first = u32::from_le_bytes(s[..4].try_into().unwrap()) as usize;
                if first > 0 && first.is_multiple_of(4) { first / 4 } else { 0 }
            })
        };

        check(
            OperationKind::ProposerSlashings,
            fixed_count(self.proposer_slashings(), PROPOSER_SLASHING_SIZE),
            MAX_PROPOSER_SLASHINGS,
        )?;
        check(
            OperationKind::AttesterSlashings,
            var_count(self.attester_slashings()),
            MAX_ATTESTER_SLASHINGS_ELECTRA,
        )?;
        check(
            OperationKind::Attestations,
            var_count(self.attestations()),
            MAX_ATTESTATIONS_ELECTRA,
        )?;
        check(
            OperationKind::VoluntaryExits,
            fixed_count(self.voluntary_exits(), SIGNED_VOLUNTARY_EXIT_SIZE),
            MAX_VOLUNTARY_EXITS,
        )?;
        check(
            OperationKind::BlsToExecutionChanges,
            fixed_count(self.bls_changes(), SIGNED_BLS_CHANGE_SIZE),
            MAX_BLS_TO_EXECUTION_CHANGES,
        )?;

        // Fulu removed the eth1 bridge deposit; the field must be empty.
        if self.deposits().is_some_and(|d| !d.is_empty()) {
            return Err(BlockBodyError::OperationCountOutOfBounds {
                op: OperationKind::Deposits,
                count: fixed_count(self.deposits(), DEPOSIT_SIZE).max(1),
                max: 0,
            });
        }

        if self.fork == BodyFork::Gloas {
            check(
                OperationKind::PayloadAttestations,
                fixed_count(self.payload_attestations(), PAYLOAD_ATTESTATION_SIZE),
                MAX_PAYLOAD_ATTESTATIONS,
            )?;
            ExecutionRequestsView::check_counts(self.parent_execution_requests())?;
        }

        Ok(())
    }
}
