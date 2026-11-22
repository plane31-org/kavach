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
