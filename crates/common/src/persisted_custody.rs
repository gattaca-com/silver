use std::{
    io::{self, ErrorKind, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RaisedCustody {
    pub custody_group_count: u64,
    pub from_slot: u64,
}

pub struct PersistedCustody {
    dir: PathBuf,
}

impl PersistedCustody {
    const FILE: &str = "custody_group_count";

    pub fn new(data_dir: &Path) -> Self {
        Self { dir: data_dir.to_path_buf() }
    }

    pub fn load(&self) -> io::Result<Option<RaisedCustody>> {
        let path = self.dir.join(Self::FILE);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut fields = text.split_whitespace().map(str::parse::<u64>);
        match (fields.next(), fields.next(), fields.next()) {
            (Some(Ok(custody_group_count)), Some(Ok(from_slot)), None) => {
                Ok(Some(RaisedCustody { custody_group_count, from_slot }))
            }
            _ => Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("{} is not a custody group count and slot", path.display()),
            )),
        }
    }

    pub fn store(&self, raised: RaisedCustody) -> io::Result<()> {
        let staged = self.dir.join(format!("{}.partial", Self::FILE));
        let mut file = std::fs::File::create(&staged)?;
        write!(file, "{} {}", raised.custody_group_count, raised.from_slot)?;
        file.sync_all()?;
        std::fs::rename(&staged, self.dir.join(Self::FILE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_count_survives_a_reload() {
        let dir = std::env::temp_dir().join(format!("silver_custody_{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        let persisted = PersistedCustody::new(&dir);

        assert_eq!(persisted.load().unwrap(), None);
        let raised = RaisedCustody { custody_group_count: 100, from_slot: 64 };
        persisted.store(RaisedCustody { custody_group_count: 32, from_slot: 32 }).unwrap();
        persisted.store(raised).unwrap();
        assert_eq!(PersistedCustody::new(&dir).load().unwrap(), Some(raised));

        std::fs::write(dir.join(PersistedCustody::FILE), "garbage").unwrap();
        assert_eq!(persisted.load().unwrap_err().kind(), ErrorKind::InvalidData);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
