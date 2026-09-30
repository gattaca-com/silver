//! Datagram format between the node-side exporter and the dashboard. All
//! integers little-endian. Every datagram is self-contained: no reassembly,
//! and loss costs only the points it carried.
//!
//! Header (`HEADER_LEN` = 40):
//!
//! | off | field       | type |
//! |-----|-------------|------|
//! | 0   | magic       | u32  |
//! | 4   | version     | u16  |
//! | 6   | kind        | u16  |
//! | 8   | instance_id | u64  |
//! | 16  | boot_id     | u64  |
//! | 24  | seq         | u64  |
//! | 32  | ts_ns       | u64  |
//!
//! Payload by kind, offsets from payload start:
//!
//! | kind          | prefix                                          | entry                                                                 |
//! |---------------|-------------------------------------------------|-----------------------------------------------------------------------|
//! | Sources       | count u16                                       | id u16, class u8, len u8, name[len]                                   |
//! | SlotNames     | source_id u16, count u16, first_slot u32        | len u8, name[len]                                                     |
//! | BuildInfo     | —                                               | utf-8 text to end of datagram                                         |
//! | Instance      | —                                               | utf-8 label to end of datagram                                        |
//! | CounterValues | source_id u16, count u16, first_slot u32        | value u64                                                             |
//! | TileUtils     | count u16, pad[6]                               | source_id u16, pad[6], busy u64, total u64, busy_count u64, busy_max u64 |
//! | Timings       | count u16, pad[6]                               | source_id u16, channel u8, pad[5], count u64, p50_ns u64, p99_ns u64, max_ns u64 |
//!
//! Prefixes before u64 arrays are 8 bytes, so every u64 sits at a multiple of
//! 8 from datagram start.

mod encoder;
mod header;
mod records;

pub use encoder::Encoder;
pub use header::{HEADER_LEN, Header, Kind, MAGIC, MAX_DATAGRAM, VERSION};
pub use records::{Source, SourceClass, TileUtil, TimingChannel, TimingStats};
