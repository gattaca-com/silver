// Adapted from https://github.com/sigp/enr (MIT License)

use std::{
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use alloy_rlp::{Encodable, Header};
use bytes::BytesMut;

use super::{
    ENR_VERSION, Enr, EnrKey, EnrPublicKey, ID_ENR_KEY, IP_ENR_KEY, IP6_ENR_KEY, MAX_ENR_SIZE,
    NodeId, UDP_ENR_KEY, UDP6_ENR_KEY,
};

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[error("enr exceeds max size")]
    ExceedsMaxSize,
    #[error("sequence number too large")]
    SequenceNumberTooHigh,
    #[error("signing error")]
    SigningError,
    #[error("unsupported identity scheme")]
    UnsupportedIdentityScheme,
    #[error("invalid rlp data {0}")]
    InvalidRlpData(#[from] alloy_rlp::Error),
}

pub struct Builder<K: EnrKey> {
    seq: u64,
    ip4: Option<Ipv4Addr>,
    ip6: Option<Ipv6Addr>,
    udp4: Option<u16>,
    udp6: Option<u16>,
    phantom: PhantomData<K>,
}

impl<K: EnrKey> Default for Builder<K> {
    fn default() -> Self {
        Self { seq: 1, ip4: None, ip6: None, udp4: None, udp6: None, phantom: PhantomData }
    }
}

impl<K: EnrKey> Builder<K> {
    pub fn seq(&mut self, seq: u64) -> &mut Self {
        self.seq = seq;
        self
    }

    pub fn ip(&mut self, ip: IpAddr) -> &mut Self {
        match ip {
            IpAddr::V4(addr) => self.ip4(addr),
            IpAddr::V6(addr) => self.ip6(addr),
        }
    }

    pub fn ip4(&mut self, ip: Ipv4Addr) -> &mut Self {
        self.ip4 = Some(ip);
        self
    }

    pub fn ip6(&mut self, ip: Ipv6Addr) -> &mut Self {
        self.ip6 = Some(ip);
        self
    }

    pub fn udp4(&mut self, udp: u16) -> &mut Self {
        self.udp4 = Some(udp);
        self
    }

    pub fn udp6(&mut self, udp: u16) -> &mut Self {
        self.udp6 = Some(udp);
        self
    }

    // Produces the RLP list content used for signing (no signature prefix).
    // Key order matches the sorted order required by the ENR spec.
    fn rlp_content(&self, public_key: &K::PublicKey) -> BytesMut {
        let mut list = BytesMut::with_capacity(MAX_ENR_SIZE);
        self.seq.encode(&mut list);

        let pk_key = public_key.enr_key();
        let pk_encoded = public_key.encode();

        if pk_key == b"ed25519" {
            pk_key.encode(&mut list);
            pk_encoded.as_ref().encode(&mut list);
        }
        ID_ENR_KEY.encode(&mut list);
        ENR_VERSION.encode(&mut list);
        if let Some(ip4) = self.ip4 {
            IP_ENR_KEY.encode(&mut list);
            ip4.octets().as_ref().encode(&mut list);
        }
        if let Some(ip6) = self.ip6 {
            IP6_ENR_KEY.encode(&mut list);
            ip6.octets().as_ref().encode(&mut list);
        }
        if pk_key == b"secp256k1" {
            pk_key.encode(&mut list);
            pk_encoded.as_ref().encode(&mut list);
        }
        if let Some(udp4) = self.udp4 {
            UDP_ENR_KEY.encode(&mut list);
            udp4.encode(&mut list);
        }
        if let Some(udp6) = self.udp6 {
            UDP6_ENR_KEY.encode(&mut list);
            udp6.encode(&mut list);
        }

        let header = Header { list: true, payload_length: list.len() };
        let mut out = BytesMut::with_capacity(header.length() + list.len());
        header.encode(&mut out);
        out.extend_from_slice(&list);
        out
    }

    pub fn build(&mut self, key: &K) -> Result<Enr<K>, Error> {
        let public_key = key.public();
        let rlp_content = self.rlp_content(&public_key);

        let sig_bytes = key.sign_v4(&rlp_content).map_err(|_| Error::SigningError)?;
        if sig_bytes.len() != 64 {
            return Err(Error::SigningError);
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&sig_bytes);

        let node_id = NodeId::from(public_key.clone());

        let enr = Enr {
            seq: self.seq,
            node_id,
            ip4: self.ip4,
            ip6: self.ip6,
            udp4: self.udp4,
            udp6: self.udp6,
            eth2: None,
            attnets: None,
            syncnets: None,
            public_key,
            signature,
        };

        if enr.size() > MAX_ENR_SIZE {
            return Err(Error::ExceedsMaxSize);
        }

        Ok(enr)
    }
}
