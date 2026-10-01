use std::{fs::File, io::Read, path::Path};

use silver_common::Error;

/// `BeaconState`'s first two fields are fixed-size, so its `genesis_time` and
/// `genesis_validators_root` sit at the head of any state's SSZ.
const HEAD_BYTES: usize = 8 + 32;

#[derive(Clone, Copy, Debug)]
pub struct Genesis {
    pub unix_secs: u64,
    pub validators_root: [u8; 32],
}

impl Genesis {
    pub fn from_state(ssz: &[u8]) -> Result<Self, Error> {
        let Some(head) = ssz.first_chunk::<HEAD_BYTES>() else {
            return Err(Error::ConfigError(format!(
                "state is {} bytes, too short to read its genesis",
                ssz.len()
            )));
        };
        let (unix_secs, validators_root) = head.split_at(8);
        Ok(Self {
            unix_secs: u64::from_le_bytes(unix_secs.try_into().unwrap()),
            validators_root: validators_root.try_into().unwrap(),
        })
    }

    pub fn from_state_file(path: &Path) -> Result<Self, Error> {
        let mut head = [0u8; HEAD_BYTES];
        File::open(path)?.read_exact(&mut head).map_err(|e| {
            Error::ConfigError(format!(
                "state {} is too short to read its genesis: {e}",
                path.display()
            ))
        })?;
        Self::from_state(&head)
    }
}
