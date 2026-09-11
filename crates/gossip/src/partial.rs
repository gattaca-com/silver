#[cfg(test)]
mod tests {
    use buffa::{Message, MessageField, MessageView};

    use crate::generated::{
        ControlExtensions, ControlMessage, PartialMessagesExtension, RPC, RPCView, rpc::SubOpts,
    };

    fn encode(rpc: &RPC) -> Vec<u8> {
        rpc.encode_to_vec()
    }

    /// Registry wire numbers: SubOpts.requestsPartial=3,
    /// supportsSendingPartial=4, ControlMessage.extensions=6,
    /// ControlExtensions.partialMessages=10, RPC.partial=10.
    #[test]
    fn partial_fields_round_trip() {
        let rpc = RPC {
            subscriptions: vec![SubOpts {
                subscribe: Some(true),
                topic_id: Some("col_topic".into()),
                requests_partial: Some(true),
                supports_sending_partial: None,
                ..Default::default()
            }],
            control: MessageField::some(ControlMessage {
                extensions: MessageField::some(ControlExtensions {
                    partial_messages: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            partial: MessageField::some(PartialMessagesExtension {
                topic_id: Some(b"col_topic".to_vec()),
                group_id: Some(vec![0u8; 33]),
                partial_message: Some(vec![0xab; 64]),
                parts_metadata: None,
                ..Default::default()
            }),
            ..Default::default()
        };

        let bytes = encode(&rpc);
        let view = RPCView::decode_view(&bytes).unwrap();

        let sub = view.subscriptions.iter().next().unwrap();
        assert_eq!(sub.requests_partial, Some(true));
        // requestsPartial implies sending support; the flag itself stays
        // absent on the wire and normalization happens at the consumer.
        assert_eq!(sub.supports_sending_partial, None);

        assert_eq!(
            view.control.as_option().unwrap().extensions.as_option().unwrap().partial_messages,
            Some(true)
        );

        let partial = view.partial.as_option().unwrap();
        assert_eq!(partial.topic_id, Some(&b"col_topic"[..]));
        assert_eq!(partial.group_id.unwrap().len(), 33);
        assert_eq!(partial.partial_message, Some(&[0xab; 64][..]));
        assert_eq!(partial.parts_metadata, None);
    }

    #[test]
    fn legacy_frames_decode_with_partial_fields_unset() {
        let rpc = RPC {
            subscriptions: vec![SubOpts {
                subscribe: Some(true),
                topic_id: Some("t".into()),
                ..Default::default()
            }],
            control: MessageField::some(ControlMessage::default()),
            ..Default::default()
        };

        let bytes = encode(&rpc);
        let view = RPCView::decode_view(&bytes).unwrap();

        let sub = view.subscriptions.iter().next().unwrap();
        assert_eq!(sub.requests_partial, None);
        assert_eq!(sub.supports_sending_partial, None);
        assert!(!view.control.as_option().unwrap().extensions.is_set());
        assert!(!view.partial.is_set());
    }
}
