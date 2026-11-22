import { describe, expect, it } from "vitest";
import { toHex } from "@plane31/blind-relay";
import { testPolicy } from "@plane31/blind-relay/testing";
import { device, hostJson } from "./world.js";

const policy = { ...testPolicy, kinds: [...testPolicy.kinds, {kind:3,scope:"circle" as const,retentionMs:86_400_000n,queue:"keepAll" as const,history:true,newest:false,headerClass:1 as const}] };
describe("scoped HTTP streams",()=>{
  it("registers only the author's circle and delivers private records with scoped notifications",async()=>{
    const a=await device("alice",undefined,policy), b=await device("bob",undefined,policy), c=await device("carol",undefined,policy);
    for(const d of [a,b,c]) await d.client.initializeAccount();
    const aid=(await a.client.inspect()).identityId??new Uint8Array();
    const family=(await a.client.circles.create()).circleId, work=(await a.client.circles.create()).circleId;
    for(const [d,id,name] of [[b,family,"bob"],[c,work,"carol"]] as const){
      await d.client.circles.requestJoin(id,aid); await a.client.sync(); await a.client.circles.approve(id,name);
    }
    for(let i=0;i<2;i++) for(const d of [a,b,c]) await d.client.sync();
    const q=await a.client.enqueue(3,Uint8Array.of(42),{circleId:family});
    const report=await a.client.syncUntilDrained(); expect(report.errors).toEqual([]);
    expect((await a.client.delivery(q.localId))?.status).toBe("accepted");
    await b.client.sync(); await c.client.sync();
    expect((await b.client.history({circleId:family,kind:3})).map(r=>r.plaintext[0])).toEqual([42]);
    expect(await c.client.history({kind:3})).toEqual([]);
    const scopes=await a.store.read(tx=>tx.list("scopedStreams").map(([,r])=>r));
    const sid=scopes.find(s=>s.circleId===toHex(family))?.streamId;
    if(!sid) throw new Error("no scoped stream");
    const wrong=await hostJson<{status:string}>(`/v1/circles/${toHex(work)}/streams`,{method:"POST",headers:{authorization:a.bearer()},body:JSON.stringify({streamId:sid,certificateHash:toHex((await a.client.getState()).certificateHash??new Uint8Array())})});
    expect(wrong.status).toBe("UNAUTHORIZED");
    const notices=await hostJson<{kind:string;to_account:string}[]>("/v1/debug/notifications");
    expect(notices.filter(n=>n.kind==="visible").map(n=>n.to_account)).toEqual(["bob"]);
  });
});

it.each([false, true])("resolves interrupted scoped publication over HTTP (committed: %s)", async (committed) => {
  const a = await device("alice", undefined, policy), b = await device("bob", undefined, policy);
  for (const d of [a, b]) await d.client.initializeAccount();
  const aid = (await a.client.inspect()).identityId ?? new Uint8Array();
  const { circleId } = await a.client.circles.create();
  await b.client.circles.requestJoin(circleId, aid);
  await a.client.sync();
  await a.client.circles.approve(circleId, "bob");
  await a.client.sync(); await b.client.sync();
  const publish = a.transport.relay.publishEpoch;
  a.transport.relay.publishEpoch = async (request) => {
    if (committed) await publish(request);
    return { status: "RETRYABLE" };
  };
  const queued = await a.client.enqueue(3, Uint8Array.of(82), { circleId });
  a.transport.relay.publishEpoch = publish;
  await a.client.circles.remove(circleId, (await b.client.inspect()).identityId ?? new Uint8Array());
  const report = await a.client.syncUntilDrained();
  expect(report.errors).toEqual([]);
  expect((await a.client.delivery(queued.localId))?.status).toBe("accepted");
  const row = await a.store.read(tx => tx.get("outbox", toHex(queued.localId)));
  expect(row?.epoch).toBe(2);
  const notices = await hostJson<{kind: string; to_account: string}[]>("/v1/debug/notifications");
  expect(notices.filter(n => n.kind === "visible")).toEqual([]);
});
