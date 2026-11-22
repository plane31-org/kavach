/** Revision 14: authenticated circle scope, isolated queues and reader slots. */
import { beforeAll, describe, expect, it } from "vitest";
import { ready, scopedStreamId } from "../src/crypto.js";
import { DocumentType, expectType, verifyDocument, type EpochManifest } from "../src/codec.js";
import { fixture, hex } from "./fixture.js";
import { toHex } from "../src/bytes.js";
import { testPolicy } from "../src/testing/clock.js";
import { world, type Dev } from "./clientWorld.js";

beforeAll(() => ready());
const policy = { ...testPolicy, kinds: [...testPolicy.kinds,
  { kind: 3, retentionMs: 86_400_000n, queue: "keepAll" as const, history: true, newest: false, headerClass: 1 as const, scope: "circle" as const },
  { kind: 4, retentionMs: 86_400_000n, queue: "latestWins" as const, history: false, newest: true, headerClass: 2 as const, scope: "circle" as const }
] };
async function setup() {
  const w = world(policy);
  const a = await w.device("alice"), b = await w.device("bob"), c = await w.device("carol");
  for (const d of [a,b,c]) await d.client.initializeAccount();
  const aid = (await a.client.inspect()).identityId ?? new Uint8Array();
  const family = (await a.client.circles.create()).circleId;
  const work = (await a.client.circles.create()).circleId;
  for (const [d,id,name] of [[b,family,"bob"],[c,work,"carol"]] as const) {
    await d.client.circles.requestJoin(id, aid); await w.sync(a); await a.client.circles.approve(id,name);
  }
  for (let n=0;n<2;n++) for (const d of [a,b,c]) await w.sync(d);
  return {w,a,b,c,aid,family,work};
}
const payloads = async (d:Dev, circleId?:Uint8Array) => (await d.client.history({kind:3,...(circleId?{circleId}:{})})).map(r=>r.plaintext[0]);

describe("circle-scoped records", () => {
  it("delivers to only the selected circle, while author records still reach both", async () => {
    const {w,a,b,c,aid,family,work}=await setup();
    const x=await a.client.enqueue(3,Uint8Array.of(11),{circleId:family});
    const y=await a.client.enqueue(3,Uint8Array.of(22),{circleId:work});
    await a.client.enqueue(1,Uint8Array.of(33));
    const r=await a.client.syncUntilDrained();
    expect(r.errors).toEqual([]);
    expect((await a.client.delivery(x.localId))?.status).toBe("accepted");
    expect((await a.client.delivery(y.localId))?.status).toBe("accepted");
    for(const d of [b,c]) await w.sync(d);
    expect(await payloads(b)).toEqual([11]); expect(await payloads(c)).toEqual([22]);
    expect(await payloads(a,family)).toEqual([11]); expect(await payloads(a,work)).toEqual([22]);
    expect((await b.client.history({kind:1,authorIdentityId:aid})).map(r=>r.plaintext[0])).toContain(33);
    expect((await c.client.history({kind:1,authorIdentityId:aid})).map(r=>r.plaintext[0])).toContain(33);
    expect(toHex((await b.client.history({kind:3}))[0]?.circleId ?? new Uint8Array())).toBe(toHex(family));
    expect(a.events.some(e=>e.kind==="accepted" && toHex(e.circleId??new Uint8Array())===toHex(family))).toBe(true);
  });

  it("latestWins and newest are isolated by circle, with global idempotency", async()=>{
    const {w,a,b,c,aid,family,work}=await setup();
    const old=await a.client.enqueue(4,Uint8Array.of(1),{circleId:family});
    const other=await a.client.enqueue(4,Uint8Array.of(2),{circleId:work});
    const fresh=await a.client.enqueue(4,Uint8Array.of(3),{circleId:family,idempotencyKey:"sample"});
    expect((await a.client.delivery(old.localId))?.status).toBe("cancelled");
    expect((await a.client.delivery(other.localId))?.status).toBe("queued");
    expect((await a.client.enqueue(4,Uint8Array.of(3),{circleId:family,idempotencyKey:"sample"})).localId).toEqual(fresh.localId);
    await a.client.syncUntilDrained(); for(const d of [b,c]) await w.sync(d);
    expect((await b.client.newest(aid,4,{circleId:family}))?.payload).toEqual(Uint8Array.of(3));
    expect((await c.client.newest(aid,4,{circleId:work}))?.payload).toEqual(Uint8Array.of(2));
    await expect(a.client.enqueue(3,Uint8Array.of(1))).rejects.toMatchObject({code:"MALFORMED"});
    await expect(a.client.enqueue(1,Uint8Array.of(1),{circleId:family})).rejects.toMatchObject({code:"MALFORMED"});
    expect(()=>a.client.newest(aid,4)).toThrow();
    expect(()=>scopedStreamId(new Uint8Array(32),new Uint8Array(16),new Uint8Array(1))).toThrow();
  });
});

it("matches the independent scoped stream and manifest fixture", () => {
  const v = (fixture as typeof fixture & { circle_scope: { circle_id: string; identity_id: string; device_id: string; stream_id: string; manifest_wire: string } }).circle_scope;
  expect(toHex(scopedStreamId(hex(v.identity_id), hex(v.device_id), hex(v.circle_id)))).toBe(v.stream_id);
  const author = fixture.identities.find(i => i.account === "alice");
  if (!author) throw new Error("fixture author missing");
  const m = expectType<EpochManifest>(verifyDocument(hex(v.manifest_wire), hex(author.device_sign_public)), DocumentType.EpochManifest);
  expect(toHex(m.streamId)).toBe(v.stream_id);
});

it("holds sealed backlog across a join, then excludes a removed member without rotating Work", async()=>{
  const {w,a,b,c,aid,family,work}=await setup();
  const queued=await a.client.enqueue(3,Uint8Array.of(40),{circleId:family});
  await a.client.enqueue(3,Uint8Array.of(50),{circleId:work});
  const scopes=await a.store.read(tx=>tx.list("scopedStreams").map(([,r])=>r));
  const workScope=scopes.find(r=>r.circleId===toHex(work));
  if(!workScope) throw new Error("no work stream");
  const workEpoch=await a.store.read(tx=>tx.get("stream",workScope.streamId)?.activeEpoch);
  await c.client.circles.requestJoin(family,aid); await a.client.circles.approve(family,"carol");
  // Approval holds the earlier sealed record; only a catch-up epoch may carry it.
  await a.client.syncUntilDrained(); await w.sync(b); await w.sync(c);
  expect((await a.client.delivery(queued.localId))?.status).toBe("accepted");
  expect(await payloads(c,family)).toEqual([]);
  expect(await a.store.read(tx=>tx.get("stream",workScope.streamId)?.activeEpoch)).toBe(workEpoch);
  const future=await a.client.enqueue(3,Uint8Array.of(41),{circleId:family});
  await a.client.circles.remove(family,(await b.client.inspect()).identityId??new Uint8Array());
  await a.client.syncUntilDrained(); await w.sync(c); await w.sync(b);
  expect((await a.client.delivery(future.localId))?.status).toBe("accepted");
  expect(await payloads(c,family)).toEqual([41]);
  expect(await payloads(b,family)).toEqual([40]);
});

it("disable and re-enable preserve the stream and counters; old history stays", async()=>{
  const {w,a,b,aid,family}=await setup();
  const first=await a.client.enqueue(3,Uint8Array.of(1),{circleId:family}); await w.sync(a); await w.sync(b);
  const pending=await a.client.enqueue(3,Uint8Array.of(2),{circleId:family});
  await a.client.circles.setEnabled(family,false); await w.sync(a);
  expect((await a.client.delivery(pending.localId))?.status).toBe("held");
  await expect(a.client.enqueue(3,Uint8Array.of(3),{circleId:family})).rejects.toMatchObject({code:"NOT_AUTHORIZED"});
  await a.client.circles.setEnabled(family,true); await a.client.syncUntilDrained(); await w.sync(b);
  expect(await payloads(b,family)).toEqual([1,2]);
  expect((await a.client.delivery(pending.localId))?.status).toBe("accepted");
  expect(pending.localId).not.toEqual(first.localId);
  expect((await b.client.history({authorIdentityId:aid,circleId:family})).length).toBe(2);
});

it("uses the first-seal audience for an offline first record and enforces the global queue cap", async()=>{
  const {w,a,b,c,aid,family,work}=await setup();
  const directory=a.t.directory;
  const register=directory.openScopedStream;
  if(!register) throw new Error("no scoped registration");
  const { KavachError } = await import("../src/errors.js");
  directory.openScopedStream=async()=>{throw new KavachError("NETWORK","scope");};
  const queued=await a.client.enqueue(3,Uint8Array.of(70),{circleId:family});
  expect(queued.recordId).toBeUndefined();
  await c.client.circles.requestJoin(family,aid); await a.client.circles.approve(family,"carol");
  directory.openScopedStream=register;
  await a.client.syncUntilDrained(); for(const d of [b,c]) await w.sync(d);
  expect(await payloads(c,family)).toEqual([70]);
  // Limits cover every stream, including the author stream, inside the same transaction.
  const { open } = await import("../src/client.js");
  const { resetTrust } = await import("./clientWorld.js");
  const limited=await open({accountName:"alice",retentionPolicy:{...policy,maxOutboxRecords:2},store:a.store,secretStore:a.secrets,transport:a.t,recoveryProvider:a.provider,resetTrust,now:w.clock.now});
  await limited.enqueue(3,Uint8Array.of(1),{circleId:family});
  await limited.enqueue(3,Uint8Array.of(2),{circleId:work});
  await expect(limited.enqueue(1,Uint8Array.of(3))).rejects.toMatchObject({code:"QUEUE_FULL"});
  await limited.close();
});

it("does not accept another circle's wire even when the relay offers it", async()=>{
  const {a,c,family}=await setup();
  const queued=await a.client.enqueue(3,Uint8Array.of(99),{circleId:family});
  const wire=await a.store.read(tx=>tx.get("outbox",toHex(queued.localId))?.wire);
  if(!wire) throw new Error("not sealed");
  expect(await c.client.receive(hex(wire))).toMatchObject({result:"invalid",reason:"NOT_AUTHORIZED"});
  expect(await payloads(c)).toEqual([]);
});

it("serializes concurrent scoped enqueues and resumes their counters after reopening", async()=>{
  const {w,a,family}=await setup();
  const other=await w.device("alice",a.provider,a.store.fork(),a.secrets);
  const [one,two]=await Promise.all([
    a.client.enqueue(3,Uint8Array.of(1),{circleId:family}),
    other.client.enqueue(3,Uint8Array.of(2),{circleId:family})
  ]);
  expect(one.recordId).toBeDefined(); expect(two.recordId).toBeDefined();
  expect(one.recordId).not.toEqual(two.recordId);
  await a.client.close(); await other.client.close();
  const reopened=await w.device("alice",a.provider,a.store.fork(),a.secrets);
  const third=await reopened.client.enqueue(3,Uint8Array.of(3),{circleId:family});
  const rows=await a.store.read(tx=>[one,two,third].map(r=>tx.get("outbox",toHex(r.localId))));
  expect(new Set(rows.map(r=>`${r?.scopeStream}:${r?.epoch}:${r?.counter}`)).size).toBe(3);
  expect(new Set(rows.map(r=>r?.scopeStream)).size).toBe(1);
  const report=await reopened.client.syncUntilDrained();
  expect(report.errors).toEqual([]); expect(report.outbox.accepted).toBe(3);
});

it.each([false, true])("resolves a pending scoped epoch after removal (host committed: %s)", async (committed) => {
  const { a, b, family } = await setup();
  const publish = a.t.relay.publishEpoch;
  a.t.relay.publishEpoch = async (request) => {
    if (committed) await publish(request);
    return { status: "RETRYABLE" };
  };
  const queued = await a.client.enqueue(3, Uint8Array.of(80), { circleId: family });
  a.t.relay.publishEpoch = publish;
  await a.client.circles.remove(family, (await b.client.inspect()).identityId ?? new Uint8Array());
  const report = await a.client.syncUntilDrained();
  expect(report.errors).toEqual([]);
  expect((await a.client.delivery(queued.localId))?.status).toBe("accepted");
  const binding = await a.store.read(tx => tx.list("scopedStreams").find(([, s]) => s.circleId === toHex(family))?.[1]);
  if (!binding) throw new Error("missing scope");
  expect(await a.store.read(tx => tx.get("stream", binding.streamId)?.highestCommittedEpoch)).toBe(2);
  expect(await a.store.read(tx => tx.get("epochs", `${binding.streamId}:1`)?.status)).toBe("obsolete");
});

it("forgets scoped reader keys on removal while retaining history and sending state", async () => {
  const { w, a, b, family } = await setup();
  await b.client.enqueue(3, Uint8Array.of(81), { circleId: family });
  await w.sync(b);
  await w.sync(a);
  const before = await a.store.read(tx => tx.list("readerEpochs"));
  expect(before.length).toBeGreaterThan(0);
  await a.client.circles.remove(family, (await b.client.inspect()).identityId ?? new Uint8Array());
  const remaining = await a.store.read(tx => new Set(tx.list("readerEpochs").map(([key]) => key)));
  for (const [key] of before) expect(remaining.has(key)).toBe(false);
  expect(await payloads(a, family)).toEqual([81]);
  expect(await b.store.read(tx => tx.list("stream").length)).toBe(2);
});

it("consumes stale publications without wraps and keeps them fenced after rejoin", async () => {
  const { w, a, b, aid, family } = await setup();
  const publish = a.t.relay.publishEpoch;
  let pending: Parameters<typeof publish>[0] | undefined;
  a.t.relay.publishEpoch = async request => { pending = request; return { status: "RETRYABLE" }; };
  await a.client.enqueue(3, Uint8Array.of(83), { circleId: family });
  a.t.relay.publishEpoch = publish;
  if (!pending) throw new Error("missing pending publication");
  const request = pending;
  await a.client.circles.remove(family, (await b.client.inspect()).identityId ?? new Uint8Array());
  expect((await publish(request)).status).toBe("COMMITTED");
  expect((await publish(request)).status).toBe("ALREADY_COMMITTED");
  const stream = w.host.streams.get(toHex(request.streamId));
  expect(stream?.epochs.get(1)?.wraps.size).toBe(0);
  expect(stream?.subscriptions.size).toBe(0);
  await w.sync(b);
  await b.client.circles.requestJoin(family, aid);
  await a.client.circles.approve(family, "bob");
  const epoch = await a.store.read(tx => tx.get("epochs", `${toHex(request.streamId)}:1`));
  const seed = await a.secrets.get("deviceSeed");
  if (!epoch || !seed) throw new Error("missing sending keys");
  const { deviceSigningKeypair } = await import("../src/crypto.js");
  const { sealRecord } = await import("../src/record.js");
  const record = sealRecord({ streamId: request.streamId, epoch: 1, nextCounter: 0, kind: 3, headerClass: 1, payload: Uint8Array.of(84), sentAt: w.clock.now(), epochKey: hex(epoch.epochKey), signingSecretKey: deviceSigningKeypair(seed).secretKey });
  expect((await a.t.relay.appendRecord(record.recordId, record.wire)).status).toBe("AUDIENCE_STALE");
  expect(stream?.tail).toBe(0n);
});

describe("circle-scoped records: review fixes", () => {
  it("a scoped record sent once, then its circle suspended, waits without keeping a drain running", async () => {
    const { w, a, family } = await setup();
    const stuck = await a.client.enqueue(3, Uint8Array.of(70), { circleId: family });
    w.host.failAppends = true; // handed off once and failed: queued, attempts above zero
    await a.client.syncUntilDrained();
    w.host.failAppends = false;
    expect((await a.client.delivery(stuck.localId))?.status).toBe("queued");
    await a.client.circles.setEnabled(family, false);
    const r = await a.client.syncUntilDrained();
    expect(r.stoppedBecause).toBe("drained");
    expect(r.rounds).toBeLessThan(10);
    expect((await a.client.delivery(stuck.localId))?.status).toBe("queued"); // it waits for sharing to resume
    await a.client.circles.setEnabled(family, true);
    await a.client.syncUntilDrained();
    expect((await a.client.delivery(stuck.localId))?.status).toBe("accepted");
  });

  it("the report keeps the author stream's epoch step and names each scoped stream's separately", async () => {
    const { w, a, c, family, work } = await setup();
    await a.client.enqueue(3, Uint8Array.of(80), { circleId: family }); // only Family has a scoped stream
    await a.client.syncUntilDrained();
    // A change to Work rotates the author stream; Family's scoped stream is unaffected.
    await a.client.circles.remove(work, (await c.client.inspect()).identityId ?? new Uint8Array());
    const r = await w.sync(a);
    expect(r.errors).toEqual([]);
    expect(r.epoch).toBe("prepared");
    expect(r.scopedEpochs?.map((x) => [toHex(x.circleId), x.epoch])).toEqual([[toHex(family), "unchanged"]]);
  });

  it("an idempotency key is answered inside the outbox before the circle check", async () => {
    const { a, family } = await setup();
    const first = await a.client.enqueue(3, Uint8Array.of(90), { circleId: family, idempotencyKey: "once" });
    await a.client.circles.setEnabled(family, false);
    // The outbox's own enqueue, as a call that raced the client's earlier key lookup would reach it.
    const { enqueue } = await import("../src/outbox.js");
    const deps = (a.client as unknown as { outboxDeps(c: Uint8Array): Parameters<typeof enqueue>[0] }).outboxDeps(family);
    const again = await enqueue(deps, 3, Uint8Array.of(90), { idempotencyKey: "once" });
    expect([toHex(again.localId), again.duplicate]).toEqual([toHex(first.localId), true]);
    await expect(a.client.enqueue(3, Uint8Array.of(91), { circleId: family })).rejects.toMatchObject({ code: "NOT_AUTHORIZED" });
  });

  it("a public enqueue that raced a committed key and a disabled circle returns the stored record", async () => {
    const { a, family } = await setup();
    // The first call reads the key as absent, then pauses before anything else.
    const read = a.store.read.bind(a.store);
    let resume: () => void = () => undefined;
    let paused: () => void = () => undefined;
    const reached = new Promise<void>((r) => (paused = r));
    let armed = true;
    a.store.read = (async (fn: Parameters<typeof read>[0]) => {
      const out = await read(fn);
      if (armed) {
        armed = false;
        paused();
        await new Promise<void>((r) => (resume = r));
      }
      return out;
    }) as typeof a.store.read;
    const first = a.client.enqueue(3, Uint8Array.of(92), { circleId: family, idempotencyKey: "race" });
    await reached;
    a.store.read = read;
    // Meanwhile another call commits the key, and sharing to the circle is disabled.
    const committed = await a.client.enqueue(3, Uint8Array.of(92), { circleId: family, idempotencyKey: "race" });
    await a.client.circles.setEnabled(family, false);
    resume();
    const r = await first;
    expect([toHex(r.localId), r.duplicate]).toEqual([toHex(committed.localId), true]);
    // Without a committed key the refusal stands.
    await expect(a.client.enqueue(3, Uint8Array.of(93), { circleId: family, idempotencyKey: "fresh" })).rejects.toMatchObject({ code: "NOT_AUTHORIZED" });
  });

  it("the fake host keeps a scoped stream's first registration on a repeat", async () => {
    const { w, a, family } = await setup();
    await a.client.enqueue(3, Uint8Array.of(95), { circleId: family });
    await a.client.syncUntilDrained();
    const row = await a.store.read((tx) => tx.list("scopedStreams").map(([, r]) => r).find((r) => r.own));
    if (!row) throw new Error("no scoped stream");
    const hosted = w.host.streams.get(row.streamId);
    if (!hosted) throw new Error("not registered");
    hosted.certificateHash = "first";
    const outcome = await a.t.directory.openScopedStream?.(family, Uint8Array.from(Buffer.from(row.streamId, "hex")), Uint8Array.from(Buffer.from(row.certificateHash, "hex")));
    expect(outcome?.status).toBe("ALREADY_COMMITTED");
    expect(w.host.streams.get(row.streamId)?.certificateHash).toBe("first");
  });
});
