use std::fmt;

use rustc_hash::FxHashMap;
use serde::{
    Deserialize, Deserializer,
    de::{Error, SeqAccess, Visitor},
};
use silver_beacon_state_data::{BLSPubkey, ExecutionAddress};
use silver_common::json_fields::parse_hex;

#[derive(Default)]
pub(crate) struct Registrations {
    by_pubkey: FxHashMap<BLSPubkey, Registration>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Registration {
    pub(crate) fee_recipient: ExecutionAddress,
    pub(crate) gas_limit: u64,
}

impl Registrations {
    pub(crate) fn store(&mut self, json: &[u8]) {
        let mut deserializer = serde_json::Deserializer::from_slice(json);
        if let Err(error) = deserializer.deserialize_seq(RegistrationsVisitor(self)) {
            silver_log::warn!(%error, "validator registrations not stored");
        }
    }

    pub(crate) fn get(&self, pubkey: &BLSPubkey) -> Option<Registration> {
        self.by_pubkey.get(pubkey).copied()
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
            let (Some(pubkey), Some(fee_recipient), Ok(gas_limit)) = (
                parse_hex(message.pubkey),
                parse_hex(message.fee_recipient),
                message.gas_limit.parse(),
            ) else {
                return Err(A::Error::custom("invalid field in registration"));
            };
            self.0.by_pubkey.insert(pubkey, Registration { fee_recipient, gas_limit });
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
    fee_recipient: &'a str,
    gas_limit: &'a str,
    pubkey: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registrations_json(entries: &[(u8, u8)]) -> String {
        let entries: Vec<_> = entries
            .iter()
            .map(|&(pubkey, fee_recipient)| {
                format!(
                    "{{\"message\":{{\"fee_recipient\":\"0x{}\",\"gas_limit\":\"30000000\",\
                     \"timestamp\":\"1606824023\",\"pubkey\":\"0x{}\"}},\"signature\":\"0x{}\"}}",
                    hex::encode([fee_recipient; 20]),
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
        registrations.store(registrations_json(&[(1, 0xa1), (2, 0xa2)]).as_bytes());
        registrations.store(registrations_json(&[(1, 0xb1)]).as_bytes());
        let fee_recipient = |pubkey| registrations.get(&[pubkey; 48]).map(|r| r.fee_recipient);
        assert_eq!(fee_recipient(1), Some([0xb1; 20]));
        assert_eq!(fee_recipient(2), Some([0xa2; 20]));
        assert_eq!(fee_recipient(3), None);
        assert_eq!(registrations.get(&[1; 48]).unwrap().gas_limit, 30_000_000);
    }
}
