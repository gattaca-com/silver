use silver_beacon_state_data::{BLSPubkey, Slot};

pub(crate) const MAX_BUILDER_ENTRIES: usize = 64;
pub(crate) const MAX_BUILDER_URL_SIZE: usize = 2048;
const MAX_BUILDER_PUBKEYS: usize = 64;
pub(crate) const MAX_BUILDER_AUTH_DATA_SIZE: usize = 4096;

/// `min_bid`, `builder_boost_factor`, `builders` offset.
const CONFIG_FIXED: usize = 8 + 8 + 4;
/// `url`, `auth`, `builder_pubkeys` offsets, then `max_execution_payment`,
/// `min_bid`, `builder_boost_factor`.
const ENTRY_FIXED: usize = 4 + 4 + 4 + 8 + 8 + 8;
/// `SignedBuilderRequestAuth`: `message` offset, `signature`.
const AUTH_FIXED: usize = 4 + 96;
/// `BuilderRequestAuth`: `data` offset, `slot`.
const AUTH_MESSAGE_FIXED: usize = 4 + 8;

/// An SSZ `BuilderConfig` from a `produceBlockV4` body. `parse` checks every
/// offset and list bound, so the accessors index without failing. What the
/// entries say (an empty `url`, another slot) is left to their consumer: the
/// spec fails only a body that does not decode.
#[derive(Clone, Copy, Debug)]
pub struct BuilderConfig<'a> {
    bytes: &'a [u8],
}

impl<'a> BuilderConfig<'a> {
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        let fixed = bytes.get(..CONFIG_FIXED)?;
        if offset_at(fixed, 16) != CONFIG_FIXED {
            return None;
        }
        let config = Self { bytes };
        let mut entries = ListElements::parse(&bytes[CONFIG_FIXED..], MAX_BUILDER_ENTRIES)?;
        entries.all(|entry| BuilderEntry::parse(entry).is_some()).then_some(config)
    }

    pub fn min_bid(&self) -> u64 {
        u64_at(self.bytes, 0)
    }

    pub fn builder_boost_factor(&self) -> u64 {
        u64_at(self.bytes, 8)
    }

    pub fn entries(&self) -> impl Iterator<Item = BuilderEntry<'a>> {
        ListElements::parse(&self.bytes[CONFIG_FIXED..], MAX_BUILDER_ENTRIES)
            .expect("checked at parse")
            .map(|entry| BuilderEntry::parse(entry).expect("checked at parse"))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BuilderEntry<'a> {
    url: &'a [u8],
    auth: &'a [u8],
    builder_pubkeys: &'a [u8],
    fixed: &'a [u8],
}

impl<'a> BuilderEntry<'a> {
    fn parse(bytes: &'a [u8]) -> Option<Self> {
        let fixed = bytes.get(..ENTRY_FIXED)?;
        let [url_at, auth_at, pubkeys_at] = [0, 4, 8].map(|at| offset_at(fixed, at));
        if url_at != ENTRY_FIXED || auth_at < url_at || pubkeys_at < auth_at {
            return None;
        }
        let entry = Self {
            url: bytes.get(url_at..auth_at)?,
            auth: bytes.get(auth_at..pubkeys_at)?,
            builder_pubkeys: bytes.get(pubkeys_at..)?,
            fixed,
        };
        let pubkeys_framed = entry.builder_pubkeys.len().is_multiple_of(size_of::<BLSPubkey>()) &&
            entry.builder_pubkeys.len() / size_of::<BLSPubkey>() <= MAX_BUILDER_PUBKEYS;
        let auth_framed = SignedRequestAuth::parse(entry.auth).is_some();
        (entry.url.len() <= MAX_BUILDER_URL_SIZE && pubkeys_framed && auth_framed).then_some(entry)
    }

    /// UTF-8 bytes of the builder's URL, exactly as the VC sent them.
    pub fn url(&self) -> &'a [u8] {
        self.url
    }

    /// The SSZ `SignedBuilderRequestAuth`, which the builder requires forwarded
    /// byte for byte.
    pub fn auth(&self) -> &'a [u8] {
        self.auth
    }

    pub fn auth_data(&self) -> &'a [u8] {
        SignedRequestAuth(self.auth).data()
    }

    pub fn auth_slot(&self) -> Slot {
        SignedRequestAuth(self.auth).slot()
    }

    /// Empty accepts any builder.
    pub fn builder_pubkeys(&self) -> impl Iterator<Item = &'a BLSPubkey> {
        self.builder_pubkeys
            .chunks_exact(size_of::<BLSPubkey>())
            .map(|pubkey| pubkey.try_into().expect("chunk is one pubkey"))
    }

    pub fn max_execution_payment(&self) -> u64 {
        u64_at(self.fixed, 12)
    }

    pub fn min_bid(&self) -> u64 {
        u64_at(self.fixed, 20)
    }

    pub fn builder_boost_factor(&self) -> u64 {
        u64_at(self.fixed, 28)
    }
}

/// An SSZ `SignedBuilderRequestAuth` whose offsets and data bound `parse`
/// checked.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SignedRequestAuth<'a>(&'a [u8]);

impl<'a> SignedRequestAuth<'a> {
    pub(crate) fn parse(auth: &'a [u8]) -> Option<Self> {
        let message = auth.get(AUTH_FIXED..)?;
        let framed = offset_at(auth, 0) == AUTH_FIXED &&
            message.len() >= AUTH_MESSAGE_FIXED &&
            offset_at(message, 0) == AUTH_MESSAGE_FIXED &&
            message.len() - AUTH_MESSAGE_FIXED <= MAX_BUILDER_AUTH_DATA_SIZE;
        framed.then_some(Self(auth))
    }

    pub(crate) fn encode(data: &[u8], slot: Slot, signature: &[u8; 96], out: &mut Vec<u8>) {
        out.extend_from_slice(&(AUTH_FIXED as u32).to_le_bytes());
        out.extend_from_slice(signature);
        out.extend_from_slice(&(AUTH_MESSAGE_FIXED as u32).to_le_bytes());
        out.extend_from_slice(&slot.to_le_bytes());
        out.extend_from_slice(data);
    }

    pub(crate) fn bytes(&self) -> &'a [u8] {
        self.0
    }

    pub(crate) fn signature(&self) -> &'a [u8] {
        &self.0[4..AUTH_FIXED]
    }

    pub(crate) fn data(&self) -> &'a [u8] {
        &self.message()[AUTH_MESSAGE_FIXED..]
    }

    pub(crate) fn slot(&self) -> Slot {
        u64_at(self.message(), 4)
    }

    fn message(&self) -> &'a [u8] {
        &self.0[AUTH_FIXED..]
    }
}

/// The elements of an SSZ list of variable-size elements: an offset per
/// element, each in bounds and none before the last.
pub(crate) struct ListElements<'a> {
    list: &'a [u8],
    count: usize,
    next: usize,
}

impl<'a> ListElements<'a> {
    pub(crate) fn parse(list: &'a [u8], max: usize) -> Option<Self> {
        if list.is_empty() {
            return Some(Self { list, count: 0, next: 0 });
        }
        let first = offset_at(list.get(..4)?, 0);
        if first == 0 || !first.is_multiple_of(4) || first > list.len() || first / 4 > max {
            return None;
        }
        let count = first / 4;
        let mut previous = first;
        let ordered = (1..count).all(|i| {
            let offset = offset_at(list, i * 4);
            let ordered = previous <= offset && offset <= list.len();
            previous = offset;
            ordered
        });
        ordered.then_some(Self { list, count, next: 0 })
    }
}

impl<'a> Iterator for ListElements<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        if self.next == self.count {
            return None;
        }
        let start = offset_at(self.list, self.next * 4);
        self.next += 1;
        let end = if self.next == self.count {
            self.list.len()
        } else {
            offset_at(self.list, self.next * 4)
        };
        Some(&self.list[start..end])
    }
}

pub(crate) fn offset_at(bytes: &[u8], at: usize) -> usize {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes")) as usize
}

pub(crate) fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8 bytes"))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) struct Entry<'a> {
        pub(crate) url: &'a [u8],
        pub(crate) data: &'a [u8],
        pub(crate) slot: u64,
        pub(crate) pubkeys: &'a [BLSPubkey],
        /// `max_execution_payment`, `min_bid`, `builder_boost_factor`.
        pub(crate) terms: [u64; 3],
    }

    /// A `SignedBuilderRequestAuth` signed with `0xAA` bytes.
    pub(crate) fn auth_ssz(data: &[u8], slot: u64) -> Vec<u8> {
        let mut auth = Vec::new();
        SignedRequestAuth::encode(data, slot, &[0xAA; 96], &mut auth);
        auth
    }

    impl Entry<'_> {
        pub(crate) fn ssz(&self) -> Vec<u8> {
            let auth = auth_ssz(self.data, self.slot);
            let url_at = ENTRY_FIXED;
            let auth_at = url_at + self.url.len();
            let pubkeys_at = auth_at + auth.len();
            let mut ssz = Vec::new();
            for offset in [url_at, auth_at, pubkeys_at] {
                ssz.extend_from_slice(&(offset as u32).to_le_bytes());
            }
            for term in self.terms {
                ssz.extend_from_slice(&term.to_le_bytes());
            }
            ssz.extend_from_slice(self.url);
            ssz.extend_from_slice(&auth);
            ssz.extend(self.pubkeys.iter().flatten());
            ssz
        }
    }

    pub(crate) fn config(min_bid: u64, boost: u64, entries: &[Vec<u8>]) -> Vec<u8> {
        let mut ssz = [min_bid.to_le_bytes(), boost.to_le_bytes()].concat();
        ssz.extend_from_slice(&(CONFIG_FIXED as u32).to_le_bytes());
        let mut offset = entries.len() * 4;
        for entry in entries {
            ssz.extend_from_slice(&(offset as u32).to_le_bytes());
            offset += entry.len();
        }
        entries.iter().for_each(|entry| ssz.extend_from_slice(entry));
        ssz
    }

    fn entry(url: &[u8]) -> Entry<'_> {
        Entry { url, data: b"auth", slot: 9, pubkeys: &[], terms: [1, 2, 3] }
    }

    #[test]
    fn entries_read_back_every_field() {
        let pubkeys = [[1; 48], [2; 48]];
        let first = Entry { pubkeys: &pubkeys, ..entry(b"http://a") }.ssz();
        let second = Entry { data: b"other", slot: 10, ..entry(b"http://b:9000") }.ssz();
        let ssz = config(7, 150, &[first.clone(), second]);

        let config = BuilderConfig::parse(&ssz).expect("decodes");
        assert_eq!((config.min_bid(), config.builder_boost_factor()), (7, 150));
        let entries: Vec<_> = config.entries().collect();
        assert_eq!(entries.len(), 2);

        let [a, b] = [entries[0], entries[1]];
        assert_eq!(a.url(), b"http://a");
        assert_eq!(a.auth_data(), b"auth");
        assert_eq!(a.auth_slot(), 9);
        assert_eq!(a.builder_pubkeys().copied().collect::<Vec<_>>(), pubkeys);
        assert_eq!([a.max_execution_payment(), a.min_bid(), a.builder_boost_factor()], [1, 2, 3]);
        assert_eq!(a.auth(), &first[ENTRY_FIXED + 8..first.len() - 96]);
        assert_eq!(
            (b.url(), b.auth_data(), b.auth_slot()),
            (&b"http://b:9000"[..], &b"other"[..], 10)
        );
        assert_eq!(b.builder_pubkeys().count(), 0);
    }

    #[test]
    fn empty_builders_is_p2p_only() {
        let ssz = config(0, 100, &[]);
        assert_eq!(BuilderConfig::parse(&ssz).unwrap().entries().count(), 0);
    }

    /// Only framing fails the body; an empty URL or another slot is the
    /// entry's own problem.
    #[test]
    fn entry_content_does_not_fail_the_body() {
        let ssz = config(0, 100, &[Entry { data: b"", slot: 0, ..entry(b"") }.ssz()]);
        let config = BuilderConfig::parse(&ssz).expect("decodes");
        let entry = config.entries().next().unwrap();
        assert!(entry.url().is_empty() && entry.auth_data().is_empty());
    }

    #[test]
    fn framing_errors_fail_the_body() {
        let good = entry(b"http://a").ssz();
        let long_url = vec![b'a'; MAX_BUILDER_URL_SIZE + 1];
        let long_data = vec![0; MAX_BUILDER_AUTH_DATA_SIZE + 1];
        let many_pubkeys = vec![[0; 48]; MAX_BUILDER_PUBKEYS + 1];
        let mut torn_pubkey = good.clone();
        torn_pubkey.push(0);
        let mut bad_url_offset = good.clone();
        bad_url_offset[..4].copy_from_slice(&(ENTRY_FIXED as u32 + 1).to_le_bytes());

        let bodies = [
            config(0, 100, &[good.clone()])[..CONFIG_FIXED - 1].to_vec(),
            config(0, 100, &vec![good.clone(); MAX_BUILDER_ENTRIES + 1]),
            config(0, 100, &[good[..ENTRY_FIXED - 1].to_vec()]),
            config(0, 100, &[Entry { url: &long_url, ..entry(b"") }.ssz()]),
            config(0, 100, &[Entry { data: &long_data, ..entry(b"http://a") }.ssz()]),
            config(0, 100, &[Entry { pubkeys: &many_pubkeys, ..entry(b"http://a") }.ssz()]),
            config(0, 100, &[torn_pubkey]),
            config(0, 100, &[bad_url_offset]),
        ];
        for (i, body) in bodies.iter().enumerate() {
            assert!(BuilderConfig::parse(body).is_none(), "case {i}");
        }
    }
}
