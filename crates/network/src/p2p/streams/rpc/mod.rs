mod request_in;
mod request_out;
mod reservation;
mod response_in;
mod response_out;

pub use request_in::RpcReadRequest;
pub use request_out::RpcWriteRequest;
use reservation::{Rpc, RpcReservation, alloc_incoming_rpc};
pub use response_in::RpcReadResponse;
pub use response_out::RpcWriteResponse;

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum RpcIn {
    ReadRequest(RpcReadRequest),
    WriteResponse(RpcWriteResponse),
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum RpcOut {
    WriteRequest(RpcWriteRequest),
    ReadResponse(RpcReadResponse),
}
