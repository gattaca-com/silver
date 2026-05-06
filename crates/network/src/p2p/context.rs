use silver_common::{
    ProtoIdentify, TProducer, TRandomAccess
};

pub struct Context {
    pub gossip_producer: TProducer,
    pub gossip_consumer: TRandomAccess,
    pub rpc_producer: TProducer,
    pub rpc_consumer: TRandomAccess,
    /// Local identify record.
    pub identify: Option<ProtoIdentify>,
}
