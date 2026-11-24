use std::{
    io::{self, ErrorKind, Write},
    path::{Path, PathBuf},
};

pub struct PersistedCustody {
    dir: PathBuf,
}

impl PersistedCustody {
    const FILE: &str = "custody_group_count";

    pub fn new(data_dir: &Path) -> Self {
        Self { dir: data_dir.to_path_buf() }
    }

    pub fn load(&self) -> io::Result<Option<u64>> {
        let path = self.dir.join(Self::FILE);
        match std::fs::read_to_string(&path) {
            Ok(text) => text.trim().parse().map(Some).map_err(|e| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    format!("{} is not a custody group count: {e}", path.display()),
                )
            }),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn store(&self, custody_group_count: u64) -> io::Result<()> {
        let staged = self.dir.join(format!("{}.partial", Self::FILE));
        let mut file = std::fs::File::create(&staged)?;
        file.write_all(custody_group_count.to_string().as_bytes())?;
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
        persisted.store(32).unwrap();
        persisted.store(100).unwrap();
        assert_eq!(PersistedCustody::new(&dir).load().unwrap(), Some(100));

        std::fs::write(dir.join(PersistedCustody::FILE), "garbage").unwrap();
        assert_eq!(persisted.load().unwrap_err().kind(), ErrorKind::InvalidData);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
