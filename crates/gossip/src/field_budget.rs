use buffa::{
    encoding::{Tag, WireType, skip_field},
    types::borrow_bytes,
};

/// The view decoder pushes one vector element per repeated or unknown field,
/// so this bounds its heap use regardless of frame size. Unmeasured against
/// live traffic: one publish entry costs 3 fields, one IHAVE id costs 1.
pub(crate) const MAX_RPC_FIELDS: u32 = 16 * 1024;

/// Field numbers of a message that hold nested messages.
struct Message(&'static [(u32, &'static Message)]);

const LEAF: Message = Message(&[]);
const PRUNE: Message = Message(&[(2, &LEAF)]);
const CONTROL: Message =
    Message(&[(1, &LEAF), (2, &LEAF), (3, &LEAF), (4, &PRUNE), (5, &LEAF), (6, &LEAF)]);
const RPC: Message = Message(&[(1, &LEAF), (2, &LEAF), (3, &CONTROL), (10, &LEAF)]);

impl Message {
    /// Malformed input ends the walk as `true`: the decoder reports it, after
    /// pushing at most `budget` elements.
    fn fits(&self, mut buf: &[u8], budget: &mut u32) -> bool {
        while !buf.is_empty() {
            let Some(left) = budget.checked_sub(1) else {
                return false;
            };
            *budget = left;

            let Ok(tag) = Tag::decode(&mut buf) else {
                return true;
            };
            let nested = self.0.iter().find(|(number, _)| *number == tag.field_number());
            match nested {
                Some((_, message)) if tag.wire_type() == WireType::LengthDelimited => {
                    let Ok(body) = borrow_bytes(&mut buf) else {
                        return true;
                    };
                    if !message.fits(body, budget) {
                        return false;
                    }
                }
                _ => {
                    if skip_field(tag, &mut buf).is_err() {
                        return true;
                    }
                }
            }
        }
        true
    }
}

pub(crate) fn rpc_within_field_budget(rpc: &[u8]) -> bool {
    RPC.fits(rpc, &mut { MAX_RPC_FIELDS })
}

#[cfg(test)]
mod tests {
    use buffa::Message as _;

    use super::*;
    use crate::generated::{ControlIHave, ControlMessage, Message as Publish, RPC as Rpc};

    #[test]
    fn empty_publish_entries_exceed_the_budget() {
        // Field 2, length 0.
        let frame = [0x12, 0x00].repeat(MAX_RPC_FIELDS as usize + 1);
        assert!(!rpc_within_field_budget(&frame));
        assert!(rpc_within_field_budget(&frame[..2 * MAX_RPC_FIELDS as usize]));
    }

    #[test]
    fn nested_fields_count_toward_the_budget() {
        let ihave = |ids| ControlIHave {
            topic_id: Some("t".into()),
            message_ids: vec![vec![0; 20]; ids],
            ..Default::default()
        };
        let rpc = |ids| {
            let control = ControlMessage { ihave: vec![ihave(ids)], ..Default::default() };
            Rpc { control: control.into(), ..Default::default() }.encode_to_vec()
        };
        // control + ihave + topic_id precede the ids.
        let ids = MAX_RPC_FIELDS as usize - 3;
        assert!(rpc_within_field_budget(&rpc(ids)));
        assert!(!rpc_within_field_budget(&rpc(ids + 1)));
    }

    #[test]
    fn publish_payload_is_skipped_not_walked() {
        let publish = Publish {
            data: Some([0x12, 0x00].repeat(MAX_RPC_FIELDS as usize)),
            topic: "t".into(),
            ..Default::default()
        };
        let frame = Rpc { publish: vec![publish], ..Default::default() }.encode_to_vec();
        assert!(rpc_within_field_budget(&frame));
    }
}
