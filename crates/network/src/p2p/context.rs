use silver_common::{
    P2pStreamId, RpcOutbound, RpcRequest, RpcResponse, TCacheRead, TProducer, TRandomAccess,
};

pub struct Context {
    pub gossip_producer: TProducer,
    pub gossip_consumer: TRandomAccess,
    pub rpc_producer: TProducer,
    pub rpc_consumer: TRandomAccess,
}

trait HasSeq {
    fn seq(&self) -> u64;
}

impl HasSeq for TCacheRead {
    fn seq(&self) -> u64 {
        self.seq()
    }
}

impl HasSeq for RpcOutbound {
    fn seq(&self) -> u64 {
        match self {
            RpcOutbound::Request(req) => match &req.request {
                RpcRequest::BlockByRoot(tcache_read) => tcache_read.seq(),
                RpcRequest::DataColumnsByRoot(tcache_read) => tcache_read.seq(),
                _ => u64::MAX,
            },
            RpcOutbound::Response(rsp) => match &rsp.response {
                RpcResponse::BeaconBlock { fork_digest: _, ssz } => ssz.seq(),
                RpcResponse::DataColumnSidecar { fork_digest: _, ssz } => ssz.seq(),
                _ => u64::MAX,
            },
        }
    }
}

struct OutBuffer<T: HasSeq + Clone> {
    stream_id: P2pStreamId,
    cache_tail: u64,
    msgs: Box<[Option<T>]>,
    len: usize,
    head: usize,
    tail: usize,
}

impl<T: HasSeq + Clone> OutBuffer<T> {
    fn new(id: P2pStreamId, len: usize) -> Self {
        assert!(len.is_power_of_two());
        Self {
            stream_id: id,
            cache_tail: u64::MAX,
            msgs: vec![None; len].into_boxed_slice(),
            len,
            head: 0,
            tail: 0,
        }
    }

    fn pos(&self, seq: usize) -> usize {
        seq & (self.len - 1)
    }

    /// Returns `true` if adding the new message overwrote an old message.
    fn add_msg(&mut self, msg: T) -> bool {
        if self.cache_tail == u64::MAX {
            self.cache_tail = msg.seq();
        }

        let old_msg = self.msgs[self.pos(self.head)].replace(msg);
        self.head += 1;
        old_msg.is_some()
    }

    /// Called when the current read is complete.
    fn pop(&mut self) -> Option<T> {
        match self.msgs[self.pos(self.tail)].take() {
            Some(msg) => {
                if msg.seq() != u64::MAX {
                    self.cache_tail = msg.seq();
                }
                //println!("popped - cache tail is {}", self.cache_tail);
                self.tail += 1;
                Some(msg)
            }
            None => {
                //self.cache_tail = u64::MAX;
                None
            }
        }
    }

    /// Moves the cache tail to the next message - if any
    fn send_complete(&mut self) {
        match &self.msgs[self.pos(self.tail)] {
            Some(msg) => {
                if msg.seq() != u64::MAX {
                    self.cache_tail = msg.seq();
                }
            }
            None => {
                self.cache_tail = u64::MAX;
            }
        }
    }
}
