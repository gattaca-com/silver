pub const MAGIC: u32 = u32::from_le_bytes(*b"SLVO");
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 40;
/// Ethernet MTU 1500 minus IP/UDP headers is 1472; the rest is headroom for
/// tunnel encapsulation, so no datagram is IP-fragmented.
pub const MAX_DATAGRAM: usize = 1400;

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Sources = 1,
    SlotNames = 2,
    BuildInfo = 3,
    CounterValues = 4,
    TileUtils = 5,
    Timings = 6,
    Instance = 7,
}

impl Kind {
    fn from_u16(v: u16) -> Option<Self> {
        Some(match v {
            1 => Kind::Sources,
            2 => Kind::SlotNames,
            3 => Kind::BuildInfo,
            4 => Kind::CounterValues,
            5 => Kind::TileUtils,
            6 => Kind::Timings,
            7 => Kind::Instance,
            _ => return None,
        })
    }

    /// Needed to interpret the other kinds. Re-sent periodically, so a relay
    /// can hold the latest of each for clients that join late.
    pub fn is_descriptor(self) -> bool {
        matches!(self, Kind::Sources | Kind::SlotNames | Kind::BuildInfo | Kind::Instance)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: Kind,
    pub instance_id: u64,
    /// Changes on node restart; counter deltas must not span a change.
    pub boot_id: u64,
    /// Per `(instance_id, boot_id)`, +1 per datagram; gaps are loss.
    pub seq: u64,
    pub ts_ns: u64,
}

impl Header {
    pub fn parse(dgram: &[u8]) -> Option<Self> {
        if dgram.len() < HEADER_LEN || dgram.len() > MAX_DATAGRAM {
            return None;
        }
        let u16_at = |off: usize| u16::from_le_bytes([dgram[off], dgram[off + 1]]);
        let u64_at = |off: usize| u64::from_le_bytes(dgram[off..off + 8].try_into().unwrap());
        if u32::from_le_bytes(dgram[0..4].try_into().unwrap()) != MAGIC || u16_at(4) != VERSION {
            return None;
        }
        Some(Self {
            kind: Kind::from_u16(u16_at(6))?,
            instance_id: u64_at(8),
            boot_id: u64_at(16),
            seq: u64_at(24),
            ts_ns: u64_at(32),
        })
    }

    pub(crate) fn write(&self, out: &mut [u8; HEADER_LEN]) {
        out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&VERSION.to_le_bytes());
        out[6..8].copy_from_slice(&(self.kind as u16).to_le_bytes());
        out[8..16].copy_from_slice(&self.instance_id.to_le_bytes());
        out[16..24].copy_from_slice(&self.boot_id.to_le_bytes());
        out[24..32].copy_from_slice(&self.seq.to_le_bytes());
        out[32..40].copy_from_slice(&self.ts_ns.to_le_bytes());
    }
}
