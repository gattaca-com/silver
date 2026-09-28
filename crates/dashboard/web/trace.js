// One block's pipeline as one node saw it; a port of surfer's
// sources/events model. Times are ns on that node's wall clock, held as
// Number offsets from the trace's BigInt `base` so they stay exact.

import { Stage } from './wire.js';

export const Origin = { Gossip: 0, Rpc: 1, El: 2, Assembly: 3 };
export const Verdict = { Valid: 0, Invalid: 1, Syncing: 2, Accepted: 3 };
/** The gate-opener search order. */
const ORIGINS = [Origin.Gossip, Origin.El, Origin.Rpc, Origin.Assembly];
/** Columns of one KZG verification land microseconds apart; separate
 *  verifications are at least a round apart. */
const BATCH_GAP_NS = 1e6;
/** Replay ingests historical blocks at the current wall clock; beyond this
 *  many slots an arrival says nothing about its slot. */
const LIVE_ARRIVAL_SLOTS = 2;

export class SlotClock {
  constructor(genesisUnixSecs, slotMs) {
    this.genesisNs = BigInt(genesisUnixSecs) * 1_000_000_000n;
    this.slotNs = Math.max(slotMs, 1) * 1e6;
  }

  /** BigInt wall-clock ns. */
  slotStart(slot) {
    return this.genesisNs + BigInt(this.slotNs) * BigInt(slot);
  }

  /** null once the wall clock no longer belongs to the slot. */
  liveOffset(sinceSlotStart) {
    return sinceSlotStart >= 0 && sinceSlotStart < this.slotNs * LIVE_ARRIVAL_SLOTS ? sinceSlotStart : null;
  }

  offsetInSlot(ts, slot) {
    return this.liveOffset(Number(ts - this.slotStart(slot)));
  }

  /** Pre-Gloas attestation deadline. */
  deadline() {
    return this.slotNs / 3;
  }
}

const iv = (start, end) => ({ start, end });
const colEnd = (c) => c.validatedAt ?? c.receivedAt;
const minOf = (xs) => (xs.length ? Math.min(...xs) : null);
const maxOf = (xs) => (xs.length ? Math.max(...xs) : null);

export class BlockTrace {
  constructor(slot, root, base) {
    this.slot = slot;
    this.root = root;
    this.base = base;
    this.source = null;
    this.receivedAt = null;
    this.elSentAt = null;
    /** One entry per sidecar, in persist order. */
    this.columns = [];
    this.available = null;
    this.custodyDone = null;
    this.stfDone = null;
    this.attestable = null;
    this.verdict = null;
  }

  /** First-wins: duplicate sidecars and re-announced imports re-emit. */
  apply(e) {
    const ts = Number(e.ts - this.base);
    switch (e.stage) {
      case Stage.Received:
        if (this.receivedAt === null) {
          this.receivedAt = ts;
          this.source = e.detail;
        }
        break;
      case Stage.ElSent:
        this.elSentAt = ts;
        break;
      case Stage.StfDone:
        this.stfDone ??= ts;
        break;
      case Stage.Attestable:
        this.attestable ??= ts;
        break;
      case Stage.ElVerdict:
        this.verdict = { status: e.detail, at: ts };
        break;
      case Stage.ColumnRecv:
        if (!this.columns.some((c) => c.index === e.columnIndex)) {
          this.columns.push({ index: e.columnIndex, origin: e.detail, receivedAt: ts, validatedAt: null });
        }
        break;
      case Stage.ColumnValidated: {
        const col = this.columns.find((c) => c.index === e.columnIndex);
        if (col) col.validatedAt ??= ts;
        break;
      }
      case Stage.DaAvailable:
        this.available = ts;
        break;
      case Stage.CustodyDone:
        this.custodyDone = ts;
        break;
    }
  }

  /** null while pending or not Valid: an optimistic head is not attested. */
  validAt() {
    return this.verdict?.status === Verdict.Valid ? this.verdict.at : null;
  }

  /** Stricter than the node's stage: attestable, a Valid verdict, and the
   *  gate open where it was seen. */
  attestableAt() {
    const valid = this.validAt();
    if (this.attestable === null || valid === null) return null;
    return Math.max(this.attestable, valid, this.available ?? this.attestable);
  }

  /** The block's own path; custody traffic excluded. */
  lastEvent() {
    return maxOf([this.attestable, this.verdict?.at ?? null, this.elSentAt, this.available].filter((t) => t !== null));
  }

  /** The DA gate when it held the block (it precedes dispatch), else arrival. */
  validateFrom() {
    if (this.receivedAt === null) return null;
    const gate = this.available;
    return gate !== null && this.elSentAt !== null && gate < this.elSentAt
      ? Math.max(this.receivedAt, gate)
      : this.receivedAt;
  }

  /** Imports without parking stamp post-state and import in one message. */
  parked() {
    return this.stfDone !== null && this.stfDone !== this.attestable;
  }

  ofOrigin(origin) {
    return this.columns.map((c, i) => [i, c]).filter(([, c]) => c.origin === origin);
  }

  hasOrigin(origin) {
    return this.columns.some((c) => c.origin === origin);
  }

  firstColumnAt() {
    return minOf(this.columns.map((c) => c.receivedAt));
  }

  /** null while the span has no events. */
  interval(span) {
    switch (span) {
      case 'strip': {
        const start = this.receivedAt ?? this.firstColumnAt();
        if (start === null) return null;
        const end = this.attestableAt() ?? this.lastEvent() ?? start;
        return iv(start, Math.max(end, start));
      }
      case 'da': {
        const start = this.firstColumnAt() ?? this.available;
        if (start === null) return null;
        return iv(start, this.available ?? maxOf(this.columns.map(colEnd)) ?? start);
      }
      case 'custody': {
        const start = this.firstColumnAt();
        return start === null || this.custodyDone === null ? null : iv(start, this.custodyDone);
      }
      case 'stf': {
        const start = this.validateFrom() ?? this.elSentAt;
        const end = this.attestable ?? this.elSentAt;
        return start === null || end === null ? null : iv(start, Math.max(end, start));
      }
      case 'validate': {
        const start = this.validateFrom();
        return start === null || this.elSentAt === null ? null : iv(start, this.elSentAt);
      }
      case 'apply': {
        const end = this.stfDone ?? this.attestable;
        return this.elSentAt === null || end === null ? null : iv(this.elSentAt, end);
      }
      case 'daWait':
        return this.stfDone === null || this.attestable === null ? null : iv(this.stfDone, this.attestable);
      case 'el':
        return this.verdict ? iv(this.elSentAt ?? this.verdict.at, this.verdict.at) : null;
      default: {
        const origin = colsOrigin(span);
        const cols = this.ofOrigin(origin).map(([, c]) => c);
        if (!cols.length) return null;
        return iv(minOf(cols.map((c) => c.receivedAt)), maxOf(cols.map(colEnd)));
      }
    }
  }

  /** One origin's columns in persist order (validation order), cut where
   *  consecutive validations are more than BATCH_GAP_NS apart. */
  batches(origin) {
    const batches = [];
    let prevEnd = null;
    let rank = 1;
    for (const [index, col] of this.ofOrigin(origin)) {
      const end = colEnd(col);
      const column = { index, rank: rank++ };
      if (prevEnd !== null && end - prevEnd <= BATCH_GAP_NS) batches[batches.length - 1].push(column);
      else batches.push([column]);
      prevEnd = end;
    }
    return batches;
  }

  batchOf(index) {
    const col = this.columns[index];
    return col ? (this.batches(col.origin).find((b) => b.some((c) => c.index === index)) ?? null) : null;
  }

  batchInterval(batch) {
    const cols = batch.map((c) => this.columns[c.index]);
    return iv(minOf(cols.map((c) => c.receivedAt)), maxOf(cols.map(colEnd)));
  }

  firstValidation(batch) {
    return minOf(batch.map((c) => colEnd(this.columns[c.index])));
  }

  /** The gate waited on this batch: its validation began before the gate. */
  countedForGate(batch) {
    return this.available === null || this.firstValidation(batch) <= this.available;
  }

  /** The last batch, across origins, whose validation began before the gate. */
  openedGate(batch) {
    if (this.available === null) return false;
    let opener = null;
    for (const origin of ORIGINS) {
      for (const b of this.batches(origin)) {
        const first = this.firstValidation(b);
        if (first <= this.available && (opener === null || first > this.firstValidation(opener))) opener = b;
      }
    }
    return opener !== null && opener[0].index === batch[0].index;
  }

  /** Trace time → into-slot offset; null outside the live window. */
  offsetInSlot(clock, t) {
    return clock.liveOffset(t + Number(this.base - clock.slotStart(this.slot)));
  }

  /** Trace time → wall-clock ms since the unix epoch. */
  wallMs(t) {
    return Number(this.base / 1_000_000n) + (Number(this.base % 1_000_000n) + t) / 1e6;
  }

  /** null before attestable. */
  deadlineMargin(clock) {
    const at = this.attestableAt();
    const offset = at === null ? null : this.offsetInSlot(clock, at);
    if (offset === null) return null;
    const deadline = clock.deadline();
    return offset <= deadline ? { delta: deadline - offset, madeIt: true } : { delta: offset - deadline, madeIt: false };
  }
}

export function colsSpan(origin) {
  return `cols:${origin}`;
}

export function colsOrigin(span) {
  return Number(span.slice('cols:'.length));
}
