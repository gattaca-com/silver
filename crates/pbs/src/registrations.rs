use std::fmt;

use rustc_hash::FxHashMap;
use serde::{
    Deserialize, Deserializer,
    de::{Error, SeqAccess, Visitor},
};
use silver_beacon_state_data::BLSPubkey;
use silver_common::json_fields::parse_hex;

#[derive(Default)]
pub(crate) struct Registrations {
    gas_limit_by_pubkey: FxHashMap<BLSPubkey, u64>,
}

impl Registrations {
    pub(crate) fn store(&mut self, json: &[u8]) {
        let mut deserializer = serde_json::Deserializer::from_slice(json);
        if let Err(error) = deserializer.deserialize_seq(RegistrationsVisitor(self)) {
            silver_log::warn!(%error, "validator registrations not stored");
        }
    }

    pub(crate) fn gas_limit(&self, pubkey: &BLSPubkey) -> Option<u64> {
        self.gas_limit_by_pubkey.get(pubkey).copied()
    }
}

struct RegistrationsVisitor<'a>(&'a mut Registrations);

impl<'de> Visitor<'de> for RegistrationsVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an array of signed validator registrations")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while let Some(SignedRegistration { message }) = seq.next_element()? {
            let (Some(pubkey), Ok(gas_limit)) =
                (parse_hex(message.pubkey), message.gas_limit.parse())
            else {
                return Err(A::Error::custom("invalid field in registration"));
            };
            self.0.gas_limit_by_pubkey.insert(pubkey, gas_limit);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct SignedRegistration<'a> {
    #[serde(borrow)]
    message: RegistrationMessage<'a>,
}

#[derive(Deserialize)]
struct RegistrationMessage<'a> {
    gas_limit: &'a str,
    pubkey: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registrations_json(entries: &[(u8, u64)]) -> String {
        let entries: Vec<_> = entries
            .iter()
            .map(|&(pubkey, gas_limit)| {
                format!(
                    "{{\"message\":{{\"fee_recipient\":\"0x{}\",\"gas_limit\":\"{gas_limit}\",\
                     \"timestamp\":\"1606824023\",\"pubkey\":\"0x{}\"}},\"signature\":\"0x{}\"}}",
                    hex::encode([0xa1; 20]),
                    hex::encode([pubkey; 48]),
                    hex::encode([0xef; 96]),
                )
            })
            .collect();
        format!("[{}]", entries.join(","))
    }

    #[test]
    fn latest_registration_per_pubkey_wins() {
        let mut registrations = Registrations::default();
        registrations.store(registrations_json(&[(1, 30_000_000), (2, 36_000_000)]).as_bytes());
        registrations.store(registrations_json(&[(1, 60_000_000)]).as_bytes());
        let gas_limit = |pubkey| registrations.gas_limit(&[pubkey; 48]);
        assert_eq!(gas_limit(1), Some(60_000_000));
        assert_eq!(gas_limit(2), Some(36_000_000));
        assert_eq!(gas_limit(3), None);
    }
}
