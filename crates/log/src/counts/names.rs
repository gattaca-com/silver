use std::{fs, io, path::Path};

use crate::LogSite;

/// The label of `counters-log` index `i` is line `i` of the names file:
/// `level \t file \t line \t template`.
pub struct LogName {
    pub level: String,
    pub file: String,
    pub line: u32,
    pub template: String,
}

impl LogName {
    /// Written under a temporary name and renamed into place, so a reader
    /// finds either the previous run's names or these.
    pub(super) fn write(path: &Path, sites: &[LogSite]) -> io::Result<()> {
        let clean = |s: &str| s.replace(['\t', '\n'], " ");
        let mut text = String::new();
        for site in sites {
            let (level, file, line) = (site.level, site.file, site.line);
            text += &format!("{level}\t{file}\t{line}\t{}\n", clean(site.template));
        }
        let staging = path.with_extension(std::process::id().to_string());
        fs::write(&staging, text)?;
        fs::rename(&staging, path)
    }

    pub fn read(path: &Path) -> io::Result<Vec<Self>> {
        let text = fs::read_to_string(path)?;
        let names = text.lines().filter_map(|line| {
            let mut fields = line.splitn(4, '\t');
            Some(Self {
                level: fields.next()?.to_owned(),
                file: fields.next()?.to_owned(),
                line: fields.next()?.parse().ok()?,
                template: fields.next()?.to_owned(),
            })
        });
        Ok(names.collect())
    }
}
