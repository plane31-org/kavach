/**
 * 0.9.0: a record's local id for its whole life and the delivery query, enqueue without rotation
 * errors, authoritative join requests, and one drain at a time with a correlation id that reaches
 * the transport.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.js";
import { open, type ClientEvent } from "../src/client.js";
import { ready } from "../src/crypto.js";
import { KavachError } from "../src/errors.js";
import { MemorySecretStore, MemoryStore } from "../src/store.js";
import { MemoryPlatformProvider } from "../src/testing/providers.js";
import { hostTransport } from "../src/testing/sweep.js";
import { testPolicy } from "../src/testing/clock.js";
import type { Transport, TransportContext } from "../src/transport.js";
import { pair, resetTrust, world } from "./clientWorld.js";

beforeAll(() => ready());

const lifecycle = (events: ClientEvent[], localId: Uint8Array): string[] =>
  events.flatMap((e) => ((e.kind === "queued" || e.kind === "accepted" || e.kind === "cancelled" || e.kind === "resealed") && toHex(e.localId) === toHex(localId) ? [e.kind] : []));

describe("0.9.0: local ids and delivery", () => {
  it("a record enqueued offline keeps its local id from enqueue to acceptance; every event and the delivery query name it", async () => {
    const w = world();
    const { a } = await pair(w);
    // The epoch is retired and the host cannot publish the next one: the record waits unsealed.
    const relay = a.t.relay as { publishEpoch: unknown };
    const publish = relay.publishEpoch;
    relay.publishEpoch = () => Promise.reject(new KavachError("NETWORK", "transport", "unreachable"));
    await a.client.circles.setEnabled((await a.client.circles.list())[0]?.circleId ?? new Uint8Array(), false);
    const n = a.events.length;
    const r = await a.client.enqueue(1, Uint8Array.of(7), { idempotencyKey: "checkin-1" });
    expect(r.recordId).toBeUndefined();
    const queued = a.events.slice(n).find((e) => e.kind === "queued");
    expect(queued).toMatchObject({ kind: "queued", recordId: undefined, idempotencyKey: "checkin-1", recordKind: 1 });
    expect(await a.client.delivery(r.localId)).toEqual({ status: "queued", sealed: false, recordId: undefined });
    relay.publishEpoch = publish;
    await w.sync(a);
    const accepted = a.events.slice(n).find((e) => e.kind === "accepted");
    if (accepted?.kind !== "accepted") throw new Error("not accepted");
    expect([toHex(accepted.localId), accepted.idempotencyKey, accepted.recordId.length, r.localId.length]).toEqual([toHex(r.localId), "checkin-1", 32, 32]);
    expect(await a.client.delivery(r.localId)).toEqual({ status: "accepted", recordId: accepted.recordId });
    expect(lifecycle(a.events.slice(n), r.localId)).toEqual(["queued", "accepted"]);
    // A record sealed at once has its record id as its local id.
    const now = await a.client.enqueue(1, Uint8Array.of(8));
    expect(toHex(now.recordId ?? new Uint8Array())).toBe(toHex(now.localId));
  });

  it("delivery tells superseded from other cancellations, and answers nothing for an id it never held", async () => {
    const w = world();
    const { a } = await pair(w);
    const older = await a.client.enqueue(2, Uint8Array.of(1)); // kind 2 is latestWins
    const newer = await a.client.enqueue(2, Uint8Array.of(2));
    expect(await a.client.delivery(older.localId)).toEqual({ status: "cancelled", reason: "superseded", recordId: older.recordId });
    expect((await a.client.delivery(newer.localId))?.status).toBe("queued");
    const cancelled = a.events.find((e) => e.kind === "cancelled");
    expect(cancelled?.kind === "cancelled" && toHex(cancelled.localId)).toBe(toHex(older.localId));
    expect(await a.client.delivery(new Uint8Array(16))).toBeUndefined();
  });
});

describe("0.9.0: join requests", () => {
  it("the owner's list is stored and emitted on every change, down to none, and shown on the circle", async () => {
    const w = world();
    const a = await w.device("alice");
    const b = await w.device("bob");
    await a.client.initializeAccount();
    await b.client.initializeAccount();
    const { circleId } = await a.client.circles.create();
    await b.client.circles.requestJoin(circleId, (await a.client.inspect()).identityId ?? new Uint8Array());
    await w.sync(a);
    const lists = () => a.events.flatMap((e) => (e.kind === "joinRequests" ? [[...e.accountNames]] : []));
    expect(lists()).toEqual([["bob"]]);
    expect((await a.client.circles.list())[0]?.joinRequests).toEqual(["bob"]);
    await w.sync(a); // unchanged: no event
    expect(lists()).toEqual([["bob"]]);
    await a.client.circles.approve(circleId, "bob");
    await w.sync(a);
    expect(lists()).toEqual([["bob"], []]);
    expect((await a.client.getState()).circles[0]?.joinRequests).toEqual([]);
    expect((await b.client.circles.list())[0]?.joinRequests).toEqual([]); // not the owner
  });
});

describe("0.9.0: one drain at a time, with a correlation id", () => {
  it("concurrent drains share one run, a full one waits behind a quick one, and each run's id reaches every transport call", async () => {
    const w = world(testPolicy, { fullSyncEveryMs: 86_400_000 });
    const { a } = await pair(w);
    // A transport that records the client's attached context at each relay call.
    let ctx: TransportContext | undefined;
    const ops: (string | undefined)[] = [];
    const inner = a.t;
    const observed: Transport = {
      get directory() {
        return inner.directory;
      },
      relay: { ...inner.relay, listSubscriptions: () => (ops.push(ctx?.opId()), inner.relay.listSubscriptions()), syncState: () => (ops.push(ctx?.opId()), inner.relay.syncState?.() ?? Promise.resolve({ subscriptions: [] })) },
      attach: (c) => {
        ctx = c;
      }
    };
    const client = await open({ accountName: "alice", retentionPolicy: testPolicy, recoveryProvider: new MemoryPlatformProvider("alice@platform"), resetTrust, secretStore: a.secrets, store: a.store, transport: observed, now: w.clock.now, fullSyncEveryMs: 86_400_000 });
    expect(toHex(ctx?.device()?.certificateHash ?? new Uint8Array())).toBe(toHex((await client.getState()).certificateHash ?? new Uint8Array(1)));
    const [one, two] = await Promise.all([client.syncUntilDrained(), client.syncUntilDrained()]);
    expect(two).toBe(one);
    expect(one.opId).toMatch(/^[0-9a-f]{16}$/);
    expect(ops.every((o) => o === one.opId)).toBe(true);
    ops.length = 0;
    const quick = client.syncUntilDrained({ mode: "quick" });
    const full = client.syncUntilDrained();
    const [q, f] = await Promise.all([quick, full]);
    expect(f).not.toBe(q);
    expect([q.mode, f.mode]).toEqual(["quick", "full"]);
    expect(new Set(ops)).toEqual(new Set([q.opId, f.opId]));
    expect(ctx?.opId()).toBeUndefined(); // no sync running now
    await client.close();
    void hostTransport;
    void MemoryStore;
    void MemorySecretStore;
  });
});
