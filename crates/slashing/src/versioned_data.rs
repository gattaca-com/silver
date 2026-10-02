use std::borrow::Borrow;

use silver_beacon_state_data::{Epoch, Version};
use silver_ssz::ssz_view::{ATTESTATION_DATA_SIZE, AttestationDataView};

pub(crate) struct VersionedData<D = [u8; ATTESTATION_DATA_SIZE]> {
    data: D,
    version: Version,
}

impl<D: Borrow<[u8; ATTESTATION_DATA_SIZE]>> VersionedData<D> {
    pub(crate) fn new(data: D, version: Version) -> Self {
        Self { data, version }
    }

    pub(crate) fn is_double_vote_with(&self, data: &AttestationDataView) -> bool {
        let recorded = AttestationDataView::new(self.data.borrow());
        recorded.as_bytes() != data.as_bytes() && recorded.target_epoch() == data.target_epoch()
    }

    /// A fork upgrade can change the head's version for the same target epoch.
    /// This compares versions without rechecking the signature.
    pub(crate) fn verifies_under(&self, signing_version: impl Fn(Epoch) -> Version) -> bool {
        self.version == signing_version(AttestationDataView::new(self.data.borrow()).target_epoch())
    }
}
