use silver_ssz::ssz_view::{
    BEACON_BLOCK_BODY_FIXED, BeaconBlockBodyFuluView, BeaconBlockBodyGloasView, DEPOSIT_SIZE,
    MAX_ATTESTATIONS_ELECTRA, MAX_ATTESTER_SLASHINGS_ELECTRA, MAX_BLS_TO_EXECUTION_CHANGES,
    MAX_DEPOSITS, MAX_PAYLOAD_ATTESTATIONS, MAX_PROPOSER_SLASHINGS, MAX_VOLUNTARY_EXITS,
    PAYLOAD_ATTESTATION_SIZE, PROPOSER_SLASHING_SIZE, SIGNED_BLS_CHANGE_SIZE,
    SIGNED_VOLUNTARY_EXIT_SIZE,
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

#[derive(Debug, thiserror::Error)]
pub enum BlockBodyError {
    #[error("block body too short: len={len} min={min}")]
    BodyTooShort { len: usize, min: usize },
    #[error("{op} count {count} exceeds max {max}")]
    OperationCountOutOfBounds { op: OperationKind, count: usize, max: usize },
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BodyFork {
    Fulu,
    Gloas,
}

pub struct BodyOffsets<'a> {
    body: &'a [u8],
    fork: BodyFork,
}

impl<'a> BodyOffsets<'a> {
    #[inline]
    pub fn new(body: &'a [u8], fork: BodyFork) -> Option<Self> {
        (body.len() >= BEACON_BLOCK_BODY_FIXED).then_some(Self { body, fork })
    }

    #[inline]
    pub fn body(&self) -> &'a [u8] {
        self.body
    }

    #[inline]
    fn slice(&self, start: u32, end: u32) -> Option<&'a [u8]> {
        let (start, end) = (start as usize, end as usize);
        (start <= end && end <= self.body.len()).then(|| &self.body[start..end])
    }

    // Operation lists — identical byte positions in both forks.
    #[inline]
    pub fn proposer_slashings(&self) -> Option<&'a [u8]> {
        self.slice(
            BeaconBlockBodyFuluView::proposer_slashings_offset(self.body),
            BeaconBlockBodyFuluView::attester_slashings_offset(self.body),
        )
    }
    #[inline]
    pub fn attester_slashings(&self) -> Option<&'a [u8]> {
        self.slice(
            BeaconBlockBodyFuluView::attester_slashings_offset(self.body),
            BeaconBlockBodyFuluView::attestations_offset(self.body),
        )
    }
    #[inline]
    pub fn attestations(&self) -> Option<&'a [u8]> {
        self.slice(
            BeaconBlockBodyFuluView::attestations_offset(self.body),
            BeaconBlockBodyFuluView::deposits_offset(self.body),
        )
    }
    #[inline]
    pub fn deposits(&self) -> Option<&'a [u8]> {
        self.slice(
            BeaconBlockBodyFuluView::deposits_offset(self.body),
            BeaconBlockBodyFuluView::voluntary_exits_offset(self.body),
        )
    }
    #[inline]
    pub fn voluntary_exits(&self) -> Option<&'a [u8]> {
        // Bounded by the first post-`sync_aggregate` offset (byte 380):
        // Fulu execution_payload, Gloas bls_to_execution_changes.
        let end = match self.fork {
            BodyFork::Fulu => BeaconBlockBodyFuluView::execution_payload_offset(self.body),
            BodyFork::Gloas => BeaconBlockBodyGloasView::bls_to_execution_changes_offset(self.body),
        };
        self.slice(BeaconBlockBodyFuluView::voluntary_exits_offset(self.body), end)
    }
    #[inline]
    pub fn bls_changes(&self) -> Option<&'a [u8]> {
        match self.fork {
            BodyFork::Fulu => self.slice(
                BeaconBlockBodyFuluView::bls_to_execution_changes_offset(self.body),
                BeaconBlockBodyFuluView::blob_kzg_commitments_offset(self.body),
            ),
            BodyFork::Gloas => self.slice(
                BeaconBlockBodyGloasView::bls_to_execution_changes_offset(self.body),
                BeaconBlockBodyGloasView::signed_execution_payload_bid_offset(self.body),
            ),
        }
    }
    #[inline]
    pub fn sync_aggregate(&self) -> &'a [u8] {
        &BeaconBlockBodyFuluView::sync_aggregate(self.body)[..]
    }

    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        self.slice(
            BeaconBlockBodyFuluView::execution_payload_offset(self.body),
            BeaconBlockBodyFuluView::bls_to_execution_changes_offset(self.body),
        )
        .unwrap_or(&[])
    }

    #[inline]
    pub fn blob_commitments_fulu(&self) -> &'a [u8] {
        self.slice(
            BeaconBlockBodyFuluView::blob_kzg_commitments_offset(self.body),
            BeaconBlockBodyFuluView::execution_requests_offset(self.body),
        )
        .unwrap_or(&[])
    }

    #[inline]
    pub fn execution_requests(&self) -> &'a [u8] {
        self.slice(
            BeaconBlockBodyFuluView::execution_requests_offset(self.body),
            self.body.len() as u32,
        )
        .unwrap_or(&[])
    }

    #[inline]
    pub fn signed_bid(&self) -> Option<&'a [u8]> {
        self.slice(
            BeaconBlockBodyGloasView::signed_execution_payload_bid_offset(self.body),
            BeaconBlockBodyGloasView::payload_attestations_offset(self.body),
        )
    }
    #[inline]
    pub fn payload_attestations(&self) -> Option<&'a [u8]> {
        self.slice(
            BeaconBlockBodyGloasView::payload_attestations_offset(self.body),
            BeaconBlockBodyGloasView::parent_execution_requests_offset(self.body),
        )
    }

    /// `(field_name, offset)` of every variable field, in serialization order.
    /// Names track the fork; byte positions stay inside `ssz_view`'s accessors.
    fn variable_offsets(&self) -> [(&'static str, usize); 9] {
        let b = self.body;
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
    /// forbids eth1 deposits and caps payload attestations.
    pub fn validate(&self) -> Result<(), BlockBodyError> {
        let body_len = self.body.len();
        if body_len < BEACON_BLOCK_BODY_FIXED {
            return Err(BlockBodyError::BodyTooShort {
                len: body_len,
                min: BEACON_BLOCK_BODY_FIXED,
            });
        }

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

        match self.fork {
            BodyFork::Fulu => check(
                OperationKind::Deposits,
                fixed_count(self.deposits(), DEPOSIT_SIZE),
                MAX_DEPOSITS,
            )?,
            BodyFork::Gloas => {
                // EIP-7732 deprecates eth1 deposits; the field must be empty.
                if self.deposits().is_some_and(|d| !d.is_empty()) {
                    return Err(BlockBodyError::OperationCountOutOfBounds {
                        op: OperationKind::Deposits,
                        count: 1,
                        max: 0,
                    });
                }
                check(
                    OperationKind::PayloadAttestations,
                    fixed_count(self.payload_attestations(), PAYLOAD_ATTESTATION_SIZE),
                    MAX_PAYLOAD_ATTESTATIONS,
                )?;
            }
        }

        Ok(())
    }
}
