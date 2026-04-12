use std::{fmt::Debug, io::Error};

use silver_common::{P2pStreamId, StreamProtocol};

pub trait StreamHandler: Send {
    type BufferId: Clone + Debug + Send;

    fn recv_new(&mut self, length: usize, stream: P2pStreamId) -> Result<Self::BufferId, Error>;
    fn recv(&mut self, buffer_id: &Self::BufferId, data: &[u8]) -> Result<usize, Error>;
    fn recv_buffer(&mut self, buffer_id: &Self::BufferId) -> Result<&mut [u8], Error>;
    fn recv_buffer_written(&mut self, buffer_id: &Self::BufferId, written: usize) -> Result<(), Error>;

    fn poll_new_stream(&mut self, peer: usize) -> Option<StreamProtocol>;
    fn poll_new_send(&mut self, stream: &P2pStreamId) -> Option<(Self::BufferId, usize)>;
    fn poll_send(&mut self, buffer_id: &Self::BufferId, offset: usize) -> Option<&[u8]>;
}
