use std::{io, time::Duration};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(tag = "backend", rename_all = "snake_case", deny_unknown_fields)]
pub enum NetworkConfig {
    #[default]
    Mio,
    IoUring(UringConfig),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct UringConfig {
    pub sq_entries: u32,
    /// Multishot receives and zero-copy sends can produce multiple completions
    /// per submission.
    pub cq_entries: u32,
    #[serde(with = "milliseconds", rename = "sqpoll_idle_ms")]
    pub sqpoll_idle: Duration,
    pub sqpoll_cpu: Option<u32>,
    pub quic_rx_buffers: u16,
    pub discovery_rx_buffers: u16,
    pub quic_tx_buffers: u16,
    pub discovery_tx_buffers: u16,
    /// Smaller transmits use SENDMSG. Zero selects SENDMSG_ZC for every
    /// transmit.
    pub send_zc_min_size: usize,
}

impl Default for UringConfig {
    fn default() -> Self {
        Self {
            sq_entries: 1024,
            cq_entries: 4096,
            sqpoll_idle: Duration::from_millis(10),
            sqpoll_cpu: None,
            quic_rx_buffers: 1024,
            discovery_rx_buffers: 256,
            quic_tx_buffers: 256,
            discovery_tx_buffers: 64,
            send_zc_min_size: 0,
        }
    }
}

impl UringConfig {
    pub fn validate(&self) -> io::Result<u32> {
        if self.quic_tx_buffers == 0 || self.discovery_tx_buffers == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "transmit pools must be nonempty",
            ));
        }
        for entries in [self.quic_rx_buffers, self.discovery_rx_buffers] {
            if !entries.is_power_of_two() || entries > 32768 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "provided-buffer counts must be powers of two in 1..=32768",
                ));
            }
        }
        if !self.sq_entries.is_power_of_two() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "io_uring SQ entries must be a nonzero power of two",
            ));
        }
        if !self.cq_entries.is_power_of_two() || self.cq_entries < self.sq_entries {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "io_uring CQ entries must be a power of two at least as large as the SQ",
            ));
        }
        let idle_millis = self.sqpoll_idle.as_nanos().div_ceil(1_000_000);
        u32::try_from(idle_millis).ok().filter(|millis| *millis != 0).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "SQPOLL idle duration must round up to 1..=u32::MAX milliseconds",
            )
        })
    }
}

mod milliseconds {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer, ser::Error};

    pub(super) fn serialize<S: Serializer>(
        duration: &Duration,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let millis =
            u64::try_from(duration.as_nanos().div_ceil(1_000_000)).map_err(S::Error::custom)?;
        serializer.serialize_u64(millis)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Duration, D::Error> {
        u64::deserialize(deserializer).map(Duration::from_millis)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;

    #[test]
    fn backend_selection_defaults_to_mio_and_round_trips_uring_settings() {
        let defaults: Config = toml::from_str("").unwrap();
        assert!(matches!(defaults.network_config(), NetworkConfig::Mio));
        let config: Config = toml::from_str(
            r#"
            [network]
            backend = "io_uring"
            sqpoll_idle_ms = 25
            sqpoll_cpu = 3
            discovery_rx_buffers = 128
            quic_tx_buffers = 32
            send_zc_min_size = 1200
        "#,
        )
        .unwrap();
        let encoded = toml::to_string(config.network_config()).unwrap();
        let decoded: NetworkConfig = toml::from_str(&encoded).unwrap();
        let NetworkConfig::IoUring(config) = decoded else { panic!("wrong backend") };
        assert_eq!(config.validate().unwrap(), 25);
        assert_eq!(config.sqpoll_cpu, Some(3));
        assert_eq!(config.sq_entries, 1024);
        assert_eq!(config.discovery_rx_buffers, 128);
        assert_eq!(config.quic_tx_buffers, 32);
        assert_eq!(config.send_zc_min_size, 1200);
    }

    #[test]
    fn rejects_unknown_backends_and_misspelled_uring_options() {
        for text in [
            "backend = 'uring'",
            "backend = 'io_uring'\nsqpoll_cp = 2",
            "backend = 'io_uring'\nsqpoll_idle_ms = -1",
        ] {
            assert!(toml::from_str::<NetworkConfig>(text).is_err(), "{text}");
        }
    }
}
