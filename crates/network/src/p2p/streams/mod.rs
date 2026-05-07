use std::{array::TryFromSliceError, fmt, net::SocketAddr};

use buffa::DecodeError;
use quinn_proto::{FinishError, ReadError, ReadableError, StreamId, WriteError};
use silver_common::{RpcOutbound, TCacheError, TCacheRead};
use thiserror::Error;

use crate::p2p::streams::snappy::SnappyError;

mod gossip_in;
mod gossip_out;
mod identify_in;
mod identify_out;
mod negotiate;
mod rpc;
mod snappy;
mod state;

pub use state::StreamState;

#[derive(Debug, Error)]
pub enum StreamError {
    StreamWriteError(#[from] WriteError),
    StreamReadError(#[from] ReadError),
    StreamReadAbleError(#[from] ReadableError),
    StreamFinishError(#[from] FinishError),
    InvalidMultiStreamHeader,
    InvalidRpc,
    StreamRejected,
    StreamClosed,
    InvalidMultiStreamProtocol,
    InternalError(#[from] silver_common::Error),
    IoError(#[from] std::io::Error),
    TCacheError(#[from] TCacheError),
    SnappyError(#[from] SnappyError),
    ProtobufDecodeError(#[from] DecodeError),
    InvalidPubkey(#[from] TryFromSliceError),
    IdentifyTooBig,
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

pub trait StreamIo {
    fn write_to_stream(&mut self, id: StreamId, data: &[u8]) -> Result<usize, StreamError>;
    fn read_from_stream(&mut self, id: StreamId, data: &mut [u8]) -> Result<usize, StreamError>;
    fn close_write(&mut self, id: StreamId) -> Result<(), StreamError>;
    fn rpc_next(&mut self) -> Option<RpcOutbound>;
    fn gossip_next(&mut self) -> Option<TCacheRead>;
    fn remote_addr(&self) -> SocketAddr;
}
