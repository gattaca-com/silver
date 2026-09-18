use std::str;

pub use silver_common::cell_store::ColumnGroupKey;
use silver_common::{
    ForkName, GossipTopic, P2pStreamId,
    ssz_view::partial_column::{
        FULU_GROUP_ID_SIZE, GLOAS_GROUP_ID_SIZE, PARTIAL_COLUMNS_VERSION_BYTE,
        PartialDataColumnPartsMetadataView,
    },
};

use super::PartsMetadata;
use crate::{generated::PartialMessagesExtensionView, handler::ActiveDomains};

pub(super) struct PartialGroup {
    pub group: ColumnGroupKey,
    pub slot: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
pub struct PartialMetadataReceived {
    pub stream_id: P2pStreamId,
    pub group: ColumnGroupKey,
    pub slot: Option<u64>,
    pub metadata: PartsMetadata,
}

impl PartialMetadataReceived {
    pub(crate) fn decode(
        partial: &PartialMessagesExtensionView<'_>,
        stream_id: P2pStreamId,
        domains: &ActiveDomains,
    ) -> Option<Self> {
        let PartialGroup { group, slot } = PartialGroup::decode(partial, domains)?;
        let (available, requests, n_rows) =
            PartialDataColumnPartsMetadataView::decode(partial.parts_metadata?)?;
        Some(Self {
            stream_id,
            group,
            slot,
            metadata: PartsMetadata { available, requests, n_rows },
        })
    }
}

impl PartialGroup {
    pub(super) fn decode(
        partial: &PartialMessagesExtensionView<'_>,
        domains: &ActiveDomains,
    ) -> Option<Self> {
        let (topic, domain) = domains.parse(str::from_utf8(partial.topic_id?).ok()?).ok()?;
        let GossipTopic::DataColumnSidecar(column) = topic else { return None };
        if column >= 128 {
            return None;
        }
        let group_id = partial.group_id?;
        if group_id.first().copied()? != PARTIAL_COLUMNS_VERSION_BYTE {
            return None;
        }
        let slot = match domain.format() {
            ForkName::Fulu if group_id.len() == FULU_GROUP_ID_SIZE => None,
            ForkName::Gloas if group_id.len() == GLOAS_GROUP_ID_SIZE => {
                Some(u64::from_le_bytes(group_id[33..].try_into().ok()?))
            }
            _ => return None,
        };
        Some(Self {
            group: ColumnGroupKey { domain, block_root: group_id[1..33].try_into().ok()?, column },
            slot,
        })
    }
}

#[cfg(test)]
mod tests {
    use silver_common::{
        GossipDomain, StreamProtocol,
        ssz_view::partial_column::{
            fulu_group_id, gloas_group_id, parts_metadata_len, write_parts_metadata,
        },
    };

    use super::*;

    #[test]
    fn decodes_both_group_formats_and_rejects_wrong_domains_versions_and_lengths() {
        for format in [ForkName::Fulu, ForkName::Gloas] {
            let domain = GossipDomain::new([1, 2, 3, 4], format);
            let domains = ActiveDomains::new(Some(domain));
            let mut metadata = [0; parts_metadata_len(4)];
            write_parts_metadata(0b0101, 0b1110, 4, &mut metadata);
            let root = [7; 32];
            let fulu = fulu_group_id(&root);
            let gloas = gloas_group_id(&root, 123);
            let group = if format == ForkName::Fulu { &fulu[..] } else { &gloas[..] };
            let mut partial = PartialMessagesExtensionView {
                topic_id: Some(b"/eth2/01020304/data_column_sidecar_7/ssz_snappy"),
                group_id: Some(group),
                parts_metadata: Some(&metadata),
                ..Default::default()
            };
            let stream = P2pStreamId::new(1, 3, StreamProtocol::GossipSubV13, true);
            let decoded = PartialMetadataReceived::decode(&partial, stream, &domains).unwrap();
            assert_eq!(decoded.group.domain, domain);
            assert_eq!(decoded.group.column, 7);
            assert_eq!(decoded.group.block_root, root);
            assert_eq!(decoded.metadata, PartsMetadata { available: 5, requests: 14, n_rows: 4 });
            assert_eq!(decoded.slot, (format == ForkName::Gloas).then_some(123));
            partial.topic_id = Some(b"/eth2/00000000/data_column_sidecar_7/ssz_snappy");
            assert!(PartialMetadataReceived::decode(&partial, stream, &domains).is_none());
            partial.topic_id = Some(b"/eth2/01020304/data_column_sidecar_7/ssz_snappy");
            partial.group_id = Some(&group[..group.len() - 1]);
            assert!(PartialMetadataReceived::decode(&partial, stream, &domains).is_none());
            let mut unknown = group.to_vec();
            unknown[0] = 1;
            partial.group_id = Some(&unknown);
            assert!(PartialMetadataReceived::decode(&partial, stream, &domains).is_none());
        }
    }
}
