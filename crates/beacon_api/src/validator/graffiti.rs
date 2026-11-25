use silver_common::ClientVersion;

/// Client versions appended to the proposer's graffiti in the space it leaves,
/// in Prysm's layout:
/// <https://github.com/OffchainLabs/prysm/blob/develop/beacon-chain/execution/graffiti_info.go>.
pub(crate) struct Graffiti {
    cl: ClientVersion,
    pub(crate) el: Option<ClientVersion>,
}

impl Graffiti {
    pub(crate) fn new(cl: ClientVersion) -> Self {
        Self { cl, el: None }
    }

    /// The tiers by free bytes, with no EL known its parts left out:
    ///
    /// | free | appended |
    /// |---|---|
    /// | 12+ | EL code, 4 commit hex, CL code, 4 commit hex |
    /// | 8+ | EL code, 2 commit hex, CL code, 2 commit hex |
    /// | 4+ | EL code, CL code |
    /// | 2+ | EL code, or CL code with no EL |
    ///
    /// A space separates them from the user's text when it fits too.
    pub(crate) fn stamp(&self, mut graffiti: [u8; 32]) -> [u8; 32] {
        let mut len = graffiti.iter().rposition(|&byte| byte != 0).map_or(0, |last| last + 1);
        let free = graffiti.len() - len;
        let (needed, commit_len) = match free {
            12.. => (12, 4),
            8.. => (8, 2),
            4.. => (4, 0),
            2.. => (2, 0),
            _ => return graffiti,
        };
        if len > 0 && free > needed {
            graffiti[len] = b' ';
            len += 1;
        }

        let mut put = |bytes: &[u8]| {
            graffiti[len..len + bytes.len()].copy_from_slice(bytes);
            len += bytes.len();
        };
        if let Some(el) = &self.el {
            put(&el.code);
            put(&el.commit[..commit_len]);
        }
        if needed > 2 || self.el.is_none() {
            put(&self.cl.code);
            put(&self.cl.commit[..commit_len]);
        }
        graffiti
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graffiti(el: Option<&str>) -> Graffiti {
        Graffiti {
            cl: ClientVersion::silver("e4f61234"),
            el: el.map(|code| ClientVersion::parse(code, "0xabcd5678").unwrap()),
        }
    }

    fn user(text: &str) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[..text.len()].copy_from_slice(text.as_bytes());
        bytes
    }

    fn text(bytes: [u8; 32]) -> String {
        String::from_utf8(bytes.to_vec()).unwrap().trim_end_matches('\0').to_owned()
    }

    #[test]
    fn each_tier_fills_the_space_the_user_leaves() {
        let stamp = |text_in: &str| text(graffiti(Some("GE")).stamp(user(text_in)));
        assert_eq!(stamp(""), "GEabcdSVe4f6");
        assert_eq!(stamp("Sushi"), "Sushi GEabcdSVe4f6");
        assert_eq!(stamp(&"x".repeat(20)), format!("{}GEabcdSVe4f6", "x".repeat(20)));
        assert_eq!(stamp(&"x".repeat(23)), format!("{} GEabSVe4", "x".repeat(23)));
        assert_eq!(stamp(&"x".repeat(27)), format!("{} GESV", "x".repeat(27)));
        assert_eq!(stamp(&"x".repeat(29)), format!("{} GE", "x".repeat(29)));
        assert_eq!(stamp(&"x".repeat(31)), "x".repeat(31));
    }

    #[test]
    fn no_el_leaves_its_parts_out() {
        let stamp = |text_in: &str| text(graffiti(None).stamp(user(text_in)));
        assert_eq!(stamp(""), "SVe4f6");
        assert_eq!(stamp(&"x".repeat(29)), format!("{} SV", "x".repeat(29)));
    }
}
