// Decoder for silver_observe_wire datagrams. The layout table in
// crates/observe_wire/src/lib.rs is the contract.

export const HEADER_LEN = 40;
const MAGIC = 0x4f564c53; // "SLVO" little-endian
const VERSION = 1;
const U64_MAX = 0xffffffffffffffffn;

export const Kind = {
  Sources: 1,
  SlotNames: 2,
  BuildInfo: 3,
  CounterValues: 4,
  TileUtils: 5,
  Timings: 6,
  Instance: 7,
  Chain: 8,
  PeerP2p: 9,
  PeerScores: 10,
  PeerTopic: 11,
  Stages: 12,
};

export const SourceClass = { Counters: 0, TCache: 1, Timing: 2, Tile: 3 };
export const TimingChannel = { Latency: 0, Processing: 1 };
export const Stage = {
  Received: 0,
  ColumnRecv: 1,
  ColumnValidated: 2,
  ElSent: 3,
  ElVerdict: 4,
  DaAvailable: 5,
  CustodyDone: 6,
  StfDone: 7,
  Attestable: 8,
};
export const BLOCK_SOURCE = ['gossip', 'rpc', 'local'];
export const COLUMN_ORIGIN = ['gossip', 'rpc', 'el', 'assembly'];
export const EL_VERDICT = ['valid', 'invalid', 'syncing', 'accepted'];

const PEER_LEN = 48;
const USER_AGENT_MAX = 64;

const utf8 = new TextDecoder();

class Reader {
  constructor(buf) {
    this.view = new DataView(buf);
    this.bytes = new Uint8Array(buf);
    this.at = HEADER_LEN;
  }
  u8() { return this.view.getUint8(this.at++); }
  u16() { const v = this.view.getUint16(this.at, true); this.at += 2; return v; }
  u32() { const v = this.view.getUint32(this.at, true); this.at += 4; return v; }
  // u64::MAX is the unused-slot sentinel; Number past 2^53 loses precision,
  // which no displayed quantity reaches.
  u64() {
    const v = this.view.getBigUint64(this.at, true);
    this.at += 8;
    return v === U64_MAX ? null : Number(v);
  }
  /** Wall-clock ns exceed 2^53; kept exact for trace arithmetic. */
  u64Big() {
    const v = this.view.getBigUint64(this.at, true);
    this.at += 8;
    return v;
  }
  f64() { const v = this.view.getFloat64(this.at, true); this.at += 8; return v; }
  skip(n) { this.at += n; }
  hex(n) {
    let s = '';
    for (let i = 0; i < n; i++) s += this.bytes[this.at + i].toString(16).padStart(2, '0');
    this.at += n;
    return s;
  }
  peer() {
    const start = this.at;
    const len = this.u8();
    const id = this.hex(len);
    this.at = start + PEER_LEN;
    return id;
  }
  addr() {
    const family = this.u8();
    const inbound = this.u8() === 1;
    const port = this.u16();
    this.skip(4);
    const ip = this.bytes.subarray(this.at, this.at + 16);
    this.at += 16;
    if (family === 4) return { addr: `${[...ip.subarray(0, 4)].join('.')}:${port}`, inbound };
    const groups = [];
    for (let i = 0; i < 16; i += 2) groups.push(((ip[i] << 8) | ip[i + 1]).toString(16));
    return { addr: `[${groups.join(':')}]:${port}`, inbound };
  }
  agent() {
    const len = this.u8();
    this.skip(7);
    const s = utf8.decode(this.bytes.subarray(this.at, this.at + len));
    this.at += USER_AGENT_MAX;
    return s;
  }
  entries(read) {
    const n = this.u16();
    this.skip(6);
    const out = [];
    for (let i = 0; i < n; i++) out.push(read());
    return out;
  }
  name() { const len = this.u8(); return this.text(len); }
  text(len = this.bytes.length - this.at) {
    const s = utf8.decode(this.bytes.subarray(this.at, this.at + len));
    this.at += len;
    return s;
  }
}

/** Returns null for anything that is not a datagram of this version. */
export function decode(buf) {
  if (buf.byteLength < HEADER_LEN) return null;
  const view = new DataView(buf);
  if (view.getUint32(0, true) !== MAGIC || view.getUint16(4, true) !== VERSION) return null;
  const d = {
    kind: view.getUint16(6, true),
    instanceId: view.getBigUint64(8, true),
    bootId: view.getBigUint64(16, true),
    seq: view.getBigUint64(24, true),
    tsNs: view.getBigUint64(32, true),
  };
  const r = new Reader(buf);
  switch (d.kind) {
    case Kind.Sources: {
      d.sources = [];
      for (let n = r.u16(); n > 0; n--) {
        d.sources.push({ id: r.u16(), cls: r.u8(), name: r.name() });
      }
      break;
    }
    case Kind.SlotNames: {
      d.sourceId = r.u16();
      const count = r.u16();
      d.firstSlot = r.u32();
      d.names = [];
      for (let i = 0; i < count; i++) d.names.push(r.name());
      break;
    }
    case Kind.BuildInfo:
    case Kind.Instance:
      d.text = r.text();
      break;
    case Kind.CounterValues: {
      d.sourceId = r.u16();
      const count = r.u16();
      d.firstSlot = r.u32();
      d.values = [];
      for (let i = 0; i < count; i++) d.values.push(r.u64());
      break;
    }
    case Kind.TileUtils: {
      d.utils = [];
      const n = r.u16();
      r.skip(6);
      for (let i = 0; i < n; i++) {
        const sourceId = r.u16();
        r.skip(6);
        d.utils.push({ sourceId, busy: r.u64(), total: r.u64(), busyCount: r.u64(), busyMax: r.u64() });
      }
      break;
    }
    case Kind.Timings: {
      d.timings = [];
      const n = r.u16();
      r.skip(6);
      for (let i = 0; i < n; i++) {
        const sourceId = r.u16();
        const channel = r.u8();
        r.skip(5);
        d.timings.push({
          sourceId, channel, count: r.u64(), p50Ns: r.u64(), p99Ns: r.u64(), maxNs: r.u64(),
        });
      }
      break;
    }
    case Kind.Chain:
      d.genesisUnixSecs = r.u64();
      d.slotMs = r.u64();
      break;
    case Kind.PeerP2p:
      d.entries = r.entries(() => ({
        peer: r.peer(),
        connection: r.u64(),
        ...r.addr(),
        connectedMs: r.u64(),
        rttUs: r.u64(),
        lostPackets: r.u64(),
        rxBlocking: r.u64(),
        txBlocking: r.u64(),
        rxDatagrams: r.u64(),
        txDatagrams: r.u64(),
        streams: r.u64(),
      }));
      break;
    case Kind.PeerScores:
      d.entries = r.entries(() => {
        const e = { peer: r.peer(), agent: r.agent(), meshCount: r.u32() };
        r.skip(4);
        e.p = [r.f64(), r.f64(), r.f64(), r.f64(), r.f64(), r.f64(), r.f64(), r.f64()];
        e.total = r.f64();
        return e;
      });
      break;
    case Kind.PeerTopic:
      d.entries = r.entries(() => {
        const e = { peer: r.peer(), topicSlot: r.u16(), p3Scored: r.u8() === 1, meshActive: r.u8() === 1 };
        r.skip(4);
        e.meshedSecs = r.u64();
        e.fanoutTotal = r.u64();
        e.fanoutSent = r.u64();
        e.firstDeliveries = r.f64();
        e.meshDeliveries = r.f64();
        e.meshFailurePenalty = r.f64();
        e.invalidDeliveries = r.f64();
        return e;
      });
      break;
    case Kind.Stages:
      d.entries = r.entries(() => {
        const e = { root: r.hex(32), ts: r.u64Big(), slot: r.u64(), columnIndex: r.u64() };
        e.stage = r.u8();
        e.detail = r.u8();
        r.skip(6);
        return e;
      });
      break;
    default:
      return null;
  }
  return d;
}
