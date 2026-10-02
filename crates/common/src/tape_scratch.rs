use std::{
    io::{self, Write},
    mem,
    ops::{Deref, DerefMut},
};

use flux_profiler::timed;
use simd_json::{Buffers, Tape, value::tape::Value as TapeValue};

use crate::{TCacheProducer, TCacheRead, TProducer};

#[derive(Debug)]
pub enum TapeError {
    Json(simd_json::Error),
    /// The frame outgrew even the response's own length.
    Overflow,
    Reservation(io::Error),
}

/// Parser buffers reused across JSON responses, so a response of a size
/// already seen allocates nothing. Each response is framed straight into its
/// tcache slot.
pub struct TapeScratch {
    buffers: Buffers,
    tape: Tape<'static>,
    frame_slack: usize,
}

impl TapeScratch {
    /// `frame_slack` bounds the frame bytes that do not decode from hex.
    pub fn new(frame_slack: usize) -> Self {
        Self { buffers: Buffers::default(), tape: Tape(Vec::new()), frame_slack }
    }

    /// `None` when the tcache has no room for the frame.
    #[timed]
    pub fn encode<T, E: From<TapeError>>(
        &mut self,
        raw: &mut [u8],
        producer: &mut TProducer,
        mut to_frame: impl FnMut(TapeValue<'_, '_>, &mut FrameOut<'_>) -> Result<T, E>,
    ) -> Result<Option<(T, TCacheRead)>, E> {
        // Hex, most of any response, decodes to half its length. The few
        // frames that outgrow that are rewritten under the loose bound: every
        // frame byte decodes from at least one JSON character.
        let tight = raw.len() / 2 + self.frame_slack;
        let loose = raw.len();
        let mut tape = mem::replace(&mut self.tape, Tape(Vec::new())).reset();
        let encoded = simd_json::fill_tape(raw, &mut self.buffers, &mut tape)
            .map_err(|e| E::from(TapeError::Json(e)))
            .and_then(|()| {
                let mut write =
                    |bound| write_frame(producer, bound, |out| to_frame(tape.as_value(), out));
                match write(tight.min(loose)) {
                    Err(WriteError::Overflow) if tight < loose => write(loose),
                    written => written,
                }
                .map_err(|error| match error {
                    WriteError::Overflow => E::from(TapeError::Overflow),
                    WriteError::Frame(e) => e,
                })
            });
        self.tape = tape.reset();
        encoded
    }
}

enum WriteError<E> {
    Overflow,
    Frame(E),
}

fn write_frame<T, E: From<TapeError>>(
    producer: &mut TProducer,
    bound: usize,
    to_frame: impl FnOnce(&mut FrameOut<'_>) -> Result<T, E>,
) -> Result<Option<(T, TCacheRead)>, WriteError<E>> {
    let reservation_error = |e| WriteError::Frame(E::from(TapeError::Reservation(e)));
    let Some(mut reservation) =
        producer.reserve(bound, false).or_else(|| producer.reserve(bound, false))
    else {
        return Ok(None);
    };
    let buffer = reservation.buffer().map_err(reservation_error)?;
    let mut out = FrameOut { buffer, len: 0, overflowed: false };
    let encoded = to_frame(&mut out);
    // An overflow surfaces as a decode error into the dropped bytes.
    if out.overflowed {
        return Err(WriteError::Overflow);
    }
    let encoded = encoded.map_err(WriteError::Frame)?;
    let len = out.len;
    reservation.truncate(len);
    reservation.flush().map_err(reservation_error)?;
    Ok(Some((encoded, reservation.read())))
}

/// A frame written into its tcache reservation. Writes past the end are
/// dropped and fail the frame once it is complete.
pub struct FrameOut<'a> {
    buffer: &'a mut [u8],
    len: usize,
    overflowed: bool,
}

impl FrameOut<'_> {
    pub fn grow(&mut self, len: usize) -> Option<&mut [u8]> {
        let end = self.len + len;
        let Some(tail) = self.buffer.get_mut(self.len..end) else {
            self.overflowed = true;
            return None;
        };
        self.len = end;
        Some(tail)
    }

    pub fn push(&mut self, byte: u8) {
        self.extend_from_slice(&[byte]);
    }

    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        if let Some(tail) = self.grow(bytes.len()) {
            tail.copy_from_slice(bytes);
        }
    }

    pub fn zeroed(&mut self, len: usize) {
        if let Some(tail) = self.grow(len) {
            tail.fill(0);
        }
    }
}

impl Deref for FrameOut<'_> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.buffer[..self.len]
    }
}

impl DerefMut for FrameOut<'_> {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[..self.len]
    }
}
