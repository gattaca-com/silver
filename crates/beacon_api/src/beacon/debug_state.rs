use silver_beacon_state_data::{
    B256, BeaconStateReader, CheckpointChunk, CheckpointCursor, SLOTS_PER_HISTORICAL_ROOT,
};
use silver_common::json_fields::parse_uint64;

use crate::{
    ctx::ApiCtx,
    http::{
        ids::parse_root,
        response::{Batch, MAX_DOWNLOADS, Response},
        router::{Request, SSZ_MEDIA_TYPE},
    },
};

/// Each part fits one chunk of the send buffer, so a pump renders and frames
/// at most this much of the state.
const PART_BYTES: usize = 256 << 10;

const ONLY_FINALIZED: &str = "only the finalized state is served";

/// Only the finalized base is held whole; other states are deltas over it.
pub(crate) fn debug_state(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let state_id = req.params.get("state_id").expect("{state_id} in the route pattern");
    let requested = match StateRequest::parse(state_id) {
        Ok(requested) => requested,
        Err((status, message)) => return resp.error(status, message),
    };
    if !req.accepts_ssz() {
        return resp.error(406, "only application/octet-stream is served");
    }
    if ctx.downloads >= MAX_DOWNLOADS {
        return resp.error(503, "too many downloads in progress");
    }
    let Some(cursor) = ctx.state.begin_checkpoint_in(PART_BYTES) else {
        return resp.error(503, "no finalized state published yet");
    };
    if !requested.names(cursor.slot(), &ctx.state) {
        return resp.error(404, ONLY_FINALIZED);
    }
    let version = ctx.spec.fork_at_slot(cursor.slot()).name();
    resp.begin_download(SSZ_MEDIA_TYPE, &[("Eth-Consensus-Version", version)], StateStream {
        cursor,
        part: Vec::new(),
        sent: 0,
    });
}

enum StateRequest {
    Finalized,
    Slot(u64),
    Root(B256),
}

impl StateRequest {
    fn parse(state_id: &str) -> Result<Self, (u16, &'static str)> {
        match state_id {
            "finalized" => Ok(Self::Finalized),
            "genesis" => Ok(Self::Slot(0)),
            "head" | "justified" => Err((404, ONLY_FINALIZED)),
            _ => parse_uint64(state_id)
                .map(Self::Slot)
                .or_else(|| parse_root(state_id).map(Self::Root))
                .ok_or((400, "invalid state_id")),
        }
    }

    /// The base's root is known once the head has moved past its slot and
    /// recorded it in `state_roots`.
    fn names(&self, finalized_slot: u64, state: &BeaconStateReader) -> bool {
        match *self {
            Self::Finalized => true,
            Self::Slot(slot) => slot == finalized_slot,
            Self::Root(root) => {
                state
                    .read(|view| {
                        let behind = view.slot.state().slot.checked_sub(finalized_slot)?;
                        (1..=SLOTS_PER_HISTORICAL_ROOT as u64).contains(&behind).then(|| {
                            view.state_roots
                                .get(finalized_slot as usize % SLOTS_PER_HISTORICAL_ROOT)
                        })
                    })
                    .flatten() ==
                    Some(root)
            }
        }
    }
}

/// The finalized state's SSZ, encoded a part at a time. A finalize during the
/// download supersedes it: the bytes sent so far belong to the older state.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct StateStream {
    cursor: CheckpointCursor,
    part: Vec<u8>,
    sent: usize,
}

impl StateStream {
    pub(crate) fn render_next(&mut self, state: &BeaconStateReader, out: &mut Vec<u8>) -> Batch {
        if self.sent == self.part.len() {
            // Past the SSZ the cursor encodes the pubkeys sidecar, which a
            // download never sends.
            if self.cursor.section_index().is_none() {
                return Batch::Last;
            }
            match state.checkpoint_chunk(&mut self.cursor, &mut self.part) {
                Ok(CheckpointChunk::Ssz) => self.sent = 0,
                Ok(CheckpointChunk::Pubkeys | CheckpointChunk::Done) => return Batch::Last,
                Ok(CheckpointChunk::Restarted) | Err(_) => return Batch::Superseded,
            }
        }
        let end = self.part.len().min(self.sent + PART_BYTES);
        out.extend_from_slice(&self.part[self.sent..end]);
        self.sent = end;
        Batch::More
    }
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::{
        BeaconState, BeaconStateOwner, EpochStateFinalized, SpecConfig, ValSeed,
    };
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        ctx::test_ctx,
        http::{response::DownloadBody, router::Outcome},
        testing::{dispatch, request, status_code},
    };

    /// Mainnet's first Fulu slot, so the version header names the fork.
    const FULU_SLOT: u64 = 411_392 * 32;

    fn owner() -> BeaconStateOwner {
        let seeds: Vec<_> =
            (0..301u64).map(|i| ValSeed { balance: i * 1_000 + 7, ..ValSeed::default() }).collect();
        let mut owner = BeaconStateOwner::new(BeaconState::for_test(
            EpochStateFinalized::default(),
            &seeds,
            FULU_SLOT,
        ));
        let anchor = owner.roll_fresh();
        owner.publish_state_id(anchor);
        owner
    }

    fn get(ctx: &ApiCtx, state_id: &str, accept: Option<&str>) -> (Outcome, Vec<u8>) {
        let path = format!("/eth/v2/debug/beacon/states/{state_id}");
        dispatch(ctx, &ParsedRequest { accept, ..request("GET", &path) })
    }

    #[test]
    fn the_finalized_state_streams_as_its_ssz() {
        let owner = owner();
        let ctx = test_ctx(&SpecConfig::mainnet(), owner.reader());
        let (outcome, head) = get(&ctx, "finalized", Some("application/octet-stream"));
        let head = String::from_utf8(head).unwrap();
        assert!(head.starts_with("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"));
        assert!(head.contains("Eth-Consensus-Version: fulu\r\n"), "{head}");
        let Outcome::Download(mut body) = outcome else { panic!("a download, got {outcome:?}") };
        assert!(matches!(body, DownloadBody::State(_)));

        let mut streamed = Vec::new();
        let mut batches = 0;
        loop {
            let before = streamed.len();
            match body.render_next(&ctx, &mut streamed) {
                Batch::More => assert!(streamed.len() - before <= PART_BYTES),
                Batch::Last => break,
                Batch::Superseded => panic!("nothing finalized during the download"),
            }
            batches += 1;
        }
        let mut expected = Vec::new();
        owner.state().encode_ssz(&mut expected).unwrap();
        assert_eq!(streamed, expected);
        assert!(batches > expected.len() / PART_BYTES, "the fixed part spans several batches");
    }

    #[test]
    fn the_finalized_state_is_named_by_slot_and_by_root_once_recorded() {
        let mut owner = owner();
        let ctx = test_ctx(&SpecConfig::mainnet(), owner.reader());
        let ssz = Some("application/octet-stream");
        let root = format!("0x{}", hex::encode([0x5a; 32]));
        assert_eq!(status_code(&get(&ctx, &FULU_SLOT.to_string(), ssz).1), "200");
        assert_eq!(status_code(&get(&ctx, &root, ssz).1), "404", "head still at the base slot");

        let parent = owner.roll_fresh();
        let mut fork = owner.apply_block_view(parent);
        fork.view
            .state_roots
            .set((FULU_SLOT % SLOTS_PER_HISTORICAL_ROOT as u64) as u32, [0x5a; 32]);
        fork.view.slot.state_mut().slot = FULU_SLOT + 1;
        let child = fork.commit();
        owner.publish_state_id(child);
        assert_eq!(status_code(&get(&ctx, &root, ssz).1), "200");
        let other = format!("0x{}", hex::encode([0x5b; 32]));
        assert_eq!(status_code(&get(&ctx, &other, ssz).1), "404");
    }

    #[test]
    fn genesis_names_a_finalized_state_at_slot_zero() {
        let mut owner = BeaconStateOwner::new(BeaconState::for_test(
            EpochStateFinalized::default(),
            &[ValSeed::default()],
            0,
        ));
        let anchor = owner.roll_fresh();
        owner.publish_state_id(anchor);
        let ctx = test_ctx(&SpecConfig::mainnet(), owner.reader());
        let ssz = Some("application/octet-stream");
        assert_eq!(status_code(&get(&ctx, "genesis", ssz).1), "200");
        assert_eq!(status_code(&get(&ctx, "0", ssz).1), "200");
    }

    #[test]
    fn other_states_ids_and_media_types_are_refused() {
        let owner = owner();
        let mut ctx = test_ctx(&SpecConfig::mainnet(), owner.reader());
        let ssz = Some("application/octet-stream");
        assert_eq!(status_code(&get(&ctx, "head", ssz).1), "404");
        assert_eq!(status_code(&get(&ctx, "justified", ssz).1), "404");
        assert_eq!(status_code(&get(&ctx, "genesis", ssz).1), "404");
        assert_eq!(status_code(&get(&ctx, &(FULU_SLOT - 1).to_string(), ssz).1), "404");
        assert_eq!(status_code(&get(&ctx, "current", ssz).1), "400");
        assert_eq!(status_code(&get(&ctx, "finalized", Some("application/json")).1), "406");
        ctx.downloads = MAX_DOWNLOADS;
        assert_eq!(status_code(&get(&ctx, "finalized", ssz).1), "503");
    }
}
