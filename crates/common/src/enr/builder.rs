// Adapted from https://github.com/sigp/enr (MIT License)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use alloy_rlp::{Encodable, Header};
use bytes::BytesMut;
use secp256k1::{SECP256K1, SecretKey};

use super::{
    ATTNETS_ENR_KEY, ENR_VERSION, ETH2_ENR_KEY, Enr, ID_ENR_KEY, IP_ENR_KEY, IP6_ENR_KEY,
    MAX_ENR_SIZE, NodeId, QUIC_ENR_KEY, QUIC6_ENR_KEY, SYNCNETS_ENR_KEY, TCP_ENR_KEY, TCP6_ENR_KEY,
    UDP_ENR_KEY, UDP6_ENR_KEY, keys,
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

pub struct Builder {
    seq: u64,
    ip4: Option<Ipv4Addr>,
    ip6: Option<Ipv6Addr>,
    udp4: Option<u16>,
    udp6: Option<u16>,
    tcp4: Option<u16>,
    tcp6: Option<u16>,
    quic4: Option<u16>,
    quic6: Option<u16>,
    eth2: Option<[u8; 16]>,
    attnets: Option<[u8; 8]>,
    syncnets: Option<u8>,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            seq: 1,
            ip4: None,
            ip6: None,
            udp4: None,
            udp6: None,
            tcp4: None,
            tcp6: None,
            quic4: None,
            quic6: None,
            eth2: None,
            attnets: None,
            syncnets: None,
        }
    }
}

impl Builder {
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

    pub fn tcp4(&mut self, port: u16) -> &mut Self {
        self.tcp4 = Some(port);
        self
    }

    pub fn tcp6(&mut self, port: u16) -> &mut Self {
        self.tcp6 = Some(port);
        self
    }

    pub fn quic4(&mut self, port: u16) -> &mut Self {
        self.quic4 = Some(port);
        self
    }

    pub fn quic6(&mut self, port: u16) -> &mut Self {
        self.quic6 = Some(port);
        self
    }

    pub fn eth2(&mut self, eth2: [u8; 16]) -> &mut Self {
        self.eth2 = Some(eth2);
        self
    }

    pub fn attnets(&mut self, attnets: [u8; 8]) -> &mut Self {
        self.attnets = Some(attnets);
        self
    }

    pub fn syncnets(&mut self, syncnets: u8) -> &mut Self {
        self.syncnets = Some(syncnets);
        self
    }

    // Keys in lexicographic order:
    //   attnets < eth2 < id < ip < ip6 < quic < quic6 < secp256k1 < syncnets <
    //   tcp < tcp6 < udp < udp6
    fn rlp_content(&self, public_key: &secp256k1::PublicKey) -> BytesMut {
        let mut list = BytesMut::with_capacity(MAX_ENR_SIZE);
        self.seq.encode(&mut list);

        if let Some(attnets) = self.attnets {
            ATTNETS_ENR_KEY.encode(&mut list);
            attnets.as_ref().encode(&mut list);
        }
        if let Some(eth2) = self.eth2 {
            ETH2_ENR_KEY.encode(&mut list);
            eth2.as_ref().encode(&mut list);
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
        if let Some(quic4) = self.quic4 {
            QUIC_ENR_KEY.encode(&mut list);
            quic4.encode(&mut list);
        }
        if let Some(quic6) = self.quic6 {
            QUIC6_ENR_KEY.encode(&mut list);
            quic6.encode(&mut list);
        }
        keys::ENR_KEY.encode(&mut list);
        public_key.serialize().as_ref().encode(&mut list);
        if let Some(syncnets) = self.syncnets {
            SYNCNETS_ENR_KEY.encode(&mut list);
            [syncnets].as_ref().encode(&mut list);
        }
        if let Some(tcp4) = self.tcp4 {
            TCP_ENR_KEY.encode(&mut list);
            tcp4.encode(&mut list);
        }
        if let Some(tcp6) = self.tcp6 {
            TCP6_ENR_KEY.encode(&mut list);
            tcp6.encode(&mut list);
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

    pub fn build(&mut self, key: &SecretKey) -> Result<Enr, Error> {
        let public_key = key.public_key(SECP256K1);
        let rlp_content = self.rlp_content(&public_key);

        let signature = keys::sign_v4(key, &rlp_content).map_err(|_| Error::SigningError)?;
        let node_id = NodeId::from(public_key);
        let enr = Enr {
            seq: self.seq,
            node_id,
            ip4: self.ip4,
            ip6: self.ip6,
            udp4: self.udp4,
            udp6: self.udp6,
            tcp4: self.tcp4,
            tcp6: self.tcp6,
            quic4: self.quic4,
            quic6: self.quic6,
            eth2: self.eth2,
            attnets: self.attnets,
            syncnets: self.syncnets,
            public_key,
            signature,
        };

        if enr.size() > MAX_ENR_SIZE {
            return Err(Error::ExceedsMaxSize);
        }

        Ok(enr)
    }
}
