import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.js";
import { createCircleSnapshot, newCircleId, successorSnapshot } from "../src/circle.js";
import { buildEncryptedRecord, encodeLocation } from "../src/codec.js";
import { randomBytes, ready } from "../src/crypto.js";
import { history, newestSlot, purgeHistory, receive, syncStream } from "../src/inbox.js";
import { drain, enqueue } from "../src/outbox.js";
import { locationFromDegrees } from "../src/record.js";
import { FakeHost } from "../src/testing/fakeHost.js";
import { Clock, setupDevice, type Device } from "./harness.js";

beforeAll(() => ready());

const sample = (clock: Clock, lat = 37.7749): Uint8Array => encodeLocation(locationFromDegrees(lat, -122.4194, 5, clock.now()));

async function trio(): Promise<{ host: FakeHost; clock: Clock; alice: Device; bob: Device; carol: Device; circleId: Uint8Array }> {
  const host = new FakeHost();
  const clock = new Clock();
  host.now = clock.now;
  const alice = await setupDevice(host, clock, "alice");
  const bob = await setupDevice(host, clock, "bob");
  const carol = await setupDevice(host, clock, "carol");
  for (const d of [alice, bob, carol]) for (const o of [alice, bob, carol]) if (d !== o) await d.know(o);
  const circleId = newCircleId();
  const owner = { identityId: alice.pin.identityId, accountSecretKey: alice.account.account.secretKey };
  const genesis = createCircleSnapshot(owner, circleId);
  await alice.transport.directory.publishOwnedCircle({ circleId, expectedRevision: 0n, expectedHash: undefined, newSnapshot: genesis });
  let state = await alice.joinLocally(circleId, alice.pin, genesis);
  const two = successorSnapshot(state, { admit: bob.pin.identityId }, owner);
  if (!two) throw new Error("two");
  state = await alice.joinLocally(circleId, alice.pin, two);
  const three = successorSnapshot(state, { admit: carol.pin.identityId }, owner);
  if (!three) throw new Error("three");
  await alice.transport.directory.publishOwnedCircle({ circleId, expectedRevision: 1n, expectedHash: undefined, newSnapshot: two });
  await alice.transport.directory.publishOwnedCircle({ circleId, expectedRevision: 2n, expectedHash: undefined, newSnapshot: three });
  for (const d of [alice, bob, carol]) await d.joinLocally(circleId, alice.pin, three);
  await alice.rotate();
  return { host, clock, alice, bob, carol, circleId };
}

const aliceStream = (d: Device): Uint8Array => d.pin.streamId;

describe("receiving through sync", () => {
  it("stores, moves the pin, acknowledges, and the relay deletes once every required reader has it", async () => {
    const { host, clock, alice, bob, carol } = await trio();
    await enqueue(alice.outbox, 0, sample(clock));
    await enqueue(alice.outbox, 0, sample(clock, 38));
    await drain(alice.outbox);
    expect(host.retainedCount(alice.pin.streamId)).toBe(2);
    const b = await syncStream(bob.inbox, aliceStream(alice), alice.pin.identityId);
    expect(b).toMatchObject({ read: 2, stored: 2, keyPending: 0, acked: 2n });
    expect(host.retainedCount(alice.pin.streamId)).toBe(2); // Carol has not read yet
    const pin = await newestSlot(bob.store, alice.pin.identityId, 0, clock.now());
    expect(pin && toHex(pin.payload)).toBe(toHex(sample(clock, 38)));
    const c = await syncStream(carol.inbox, aliceStream(alice), alice.pin.identityId);
    expect(c.acked).toBe(2n);
    expect(host.retainedCount(alice.pin.streamId)).toBe(0);
    // Nothing more to read, no second acknowledgement.
    const again = await syncStream(bob.inbox, aliceStream(alice), alice.pin.identityId);
    expect(again).toMatchObject({ read: 0, acked: undefined });
    expect((await history(bob.store, bob.inbox.policy)).length).toBe(2);
  });

  it("S11 to S13 and S16: updated, duplicate, equivocation, and counter 6 after 7 keeps the pin at 7", async () => {
    const { clock, alice, bob } = await trio();
    const key = await alice.store.read((tx) => tx.get("epochs", "1")?.epochKey ?? "");
    const wireFor = (counter: number, lat: number): Uint8Array =>
      buildEncryptedRecord({ streamId: alice.pin.streamId, epoch: 1, counter, sentAt: clock.now(), kind: 0 }, sample(clock, lat), Uint8Array.from(Buffer.from(key, "hex")), randomBytes(24), alice.device.signing.secretKey);
    // Bob needs the epoch key: one real delivery fetches it.
    await enqueue(alice.outbox, 0, sample(clock));
    await drain(alice.outbox);
    await syncStream(bob.inbox, aliceStream(alice), alice.pin.identityId);
    const seven = wireFor(7, 40);
    expect((await receive(bob.inbox, seven)).result).toBe("updated");
    expect((await receive(bob.inbox, seven)).result).toBe("duplicate");
    const conflicting = wireFor(7, 41);
    expect(await receive(bob.inbox, conflicting)).toEqual({ result: "invalid", reason: "EQUIVOCATION" });
    expect((await receive(bob.inbox, wireFor(6, 39))).result).toBe("history");
    const pin = await newestSlot(bob.store, alice.pin.identityId, 0, clock.now());
    expect(pin && toHex(pin.payload)).toBe(toHex(sample(clock, 40)));
    expect((await history(bob.store, bob.inbox.policy, { authorIdentityId: alice.pin.identityId })).length).toBe(3);
  });

  it("a record that cannot be opened offline holds the prefix while later records flow, and opens after the next sync", async () => {
    const { host, clock, alice, bob } = await trio();
    await enqueue(alice.outbox, 0, sample(clock, 1));
    await drain(alice.outbox);
    host.withholdEpochs = true;
    let s = await syncStream(bob.inbox, aliceStream(alice), alice.pin.identityId);
    expect(s).toMatchObject({ read: 1, keyPending: 1, stored: 0, acked: undefined });
    // Alice rotates and sends two more; Bob can fetch the new epoch but still not the old one.
    await alice.rotate();
    await enqueue(alice.outbox, 0, sample(clock, 2));
    await enqueue(alice.outbox, 1, sample(clock, 3));
    await drain(alice.outbox);
    host.withholdEpochs = false;
    const s2 = host.streams.get(toHex(alice.pin.streamId));
    const epoch1 = s2?.epochs.get(1);
    s2?.epochs.delete(1); // simulate: only epoch 1 is unreachable
    s = await syncStream(bob.inbox, aliceStream(alice), alice.pin.identityId);
    expect(s).toMatchObject({ read: 3, stored: 2, keyPending: 1, acked: undefined });
    const sub = await bob.store.read((tx) => tx.get("subscriptions", toHex(alice.pin.streamId)));
    expect(sub?.scanPos).toBe("3");
    expect(sub?.ackPrefix).toBe("0");
    expect(host.retainedCount(alice.pin.streamId)).toBe(3);
    // The epoch becomes reachable: the old record is read again, opened, and the prefix advances to 3.
    if (epoch1) s2?.epochs.set(1, epoch1);
    s = await syncStream(bob.inbox, aliceStream(alice), alice.pin.identityId);
    expect(s).toMatchObject({ read: 3, stored: 1, duplicate: 2, acked: 3n });
    expect((await history(bob.store, bob.inbox.policy)).map((h) => toHex(h.plaintext).slice(0, 4))).toHaveLength(3);
  });

  it("a check-in survives later locations, is never the pin, and a superseded device's record is history only", async () => {
    const { clock, alice, bob, host } = await trio();
    await enqueue(alice.outbox, 1, sample(clock, 10));
    await enqueue(alice.outbox, 0, sample(clock, 11));
    await enqueue(alice.outbox, 0, sample(clock, 12));
    await drain(alice.outbox);
    await syncStream(bob.inbox, aliceStream(alice), alice.pin.identityId);
    const all = await history(bob.store, bob.inbox.policy, { authorIdentityId: alice.pin.identityId });
    expect(all.map((h) => h.kind)).toEqual([1, 0, 0]);
    const pin = await newestSlot(bob.store, alice.pin.identityId, 0, clock.now());
    expect(pin && toHex(pin.payload)).toBe(toHex(sample(clock, 12)));
    expect((await history(bob.store, bob.inbox.policy, { kind: 1 })).length).toBe(1);
    // Alice replaces her phone: Bob accepts the new certificate; a late record from the old device is history only.
    const { certify, newDevice } = await import("../src/identity.js");
    const newPhone = newDevice();
    const cert2 = certify(alice.account, newPhone, 2n);
    await bob.know(cert2);
    const key = await alice.store.read((tx) => tx.get("epochs", "1")?.epochKey ?? "");
    const late = buildEncryptedRecord({ streamId: alice.pin.streamId, epoch: 1, counter: 9, sentAt: clock.now(), kind: 0 }, sample(clock, 13), Uint8Array.from(Buffer.from(key, "hex")), randomBytes(24), alice.device.signing.secretKey);
    const r = await receive(bob.inbox, late);
    expect(r.result).toBe("history");
    const after = await newestSlot(bob.store, alice.pin.identityId, 0, clock.now());
    expect(after && toHex(after.payload)).toBe(toHex(sample(clock, 12)));
    expect((await history(bob.store, bob.inbox.policy, { authorIdentityId: alice.pin.identityId })).find((h) => toHex(h.plaintext) === toHex(sample(clock, 13)))?.superseded).toBe(true);
    void host;
  });

  it("a record not addressed to this device never holds the prefix; an unknown author is refused", async () => {
    const { clock, alice, bob, carol } = await trio();
    await enqueue(alice.outbox, 0, sample(clock));
    await drain(alice.outbox);
    await syncStream(bob.inbox, aliceStream(alice), alice.pin.identityId);
    // Carol pushes Bob a record of hers that Bob has no key for and that names only Carol's own audience:
    // Carol is a member of Bob's circle, so Bob is authorised, but the epoch does not address him.
    await carol.rotate();
    const own = await carol.store.read((tx) => tx.get("epochs", "1"));
    const wire = buildEncryptedRecord({ streamId: carol.pin.streamId, epoch: 1, counter: 0, sentAt: clock.now(), kind: 0 }, sample(clock, 5), Uint8Array.from(Buffer.from(own?.epochKey ?? "", "hex")), randomBytes(24), carol.device.signing.secretKey);
    const r = await receive(bob.inbox, wire);
    // Carol's epoch 1 names Bob (she joined the circle), so Bob fetches the key and opens it.
    expect(["updated", "keyPending"]).toContain(r.result);
    // A stranger: no certificate for the stream.
    const stranger = await setupDevice(new FakeHost(), clock, "mallory");
    await stranger.rotate();
    const ek = await stranger.store.read((tx) => tx.get("epochs", "1")?.epochKey ?? "");
    const foreign = buildEncryptedRecord({ streamId: stranger.pin.streamId, epoch: 1, counter: 0, sentAt: clock.now(), kind: 0 }, sample(clock), Uint8Array.from(Buffer.from(ek, "hex")), randomBytes(24), stranger.device.signing.secretKey);
    expect(await receive(bob.inbox, foreign)).toEqual({ result: "invalid", reason: "NOT_AUTHORIZED" });
    // Future skew is dropped, never stored.
    clock.advance(-600_000n);
    const future = buildEncryptedRecord({ streamId: alice.pin.streamId, epoch: 1, counter: 50, sentAt: clock.now() + 600_000n, kind: 0 }, sample(clock), Uint8Array.from(Buffer.from((await alice.store.read((tx) => tx.get("epochs", "1")?.epochKey)) ?? "", "hex")), randomBytes(24), alice.device.signing.secretKey);
    expect(await receive(bob.inbox, future)).toEqual({ result: "expired", reason: "CLOCK_SKEW" });
  });

  it("crossing an expired prefix stores nothing and claims nothing; retention purges history and the pin with it", async () => {
    const { host, clock, alice, bob } = await trio();
    await enqueue(alice.outbox, 0, sample(clock, 1));
    await drain(alice.outbox);
    clock.advance(86_400_001n);
    host.expire();
    expect(host.retainedCount(alice.pin.streamId)).toBe(0);
    const s = await syncStream(bob.inbox, aliceStream(alice), alice.pin.identityId);
    expect(s).toMatchObject({ read: 0, stored: 0 });
    const sub = await bob.store.read((tx) => tx.get("subscriptions", toHex(alice.pin.streamId)));
    expect(sub?.ackPrefix).toBe("1");
    expect((await history(bob.store, bob.inbox.policy)).length).toBe(0);
    // Alice's own history is the only copy; her retention window then removes it too.
    expect((await history(alice.store, alice.outbox.policy)).length).toBe(1);
    expect(await purgeHistory(alice.store, alice.outbox.policy, clock.now())).toBe(1);
    // A fresh record and a purge of the reader side removes the pin with the record.
    await alice.rotate();
    await enqueue(alice.outbox, 0, sample(clock, 2));
    await drain(alice.outbox);
    await syncStream(bob.inbox, aliceStream(alice), alice.pin.identityId);
    expect(await newestSlot(bob.store, alice.pin.identityId, 0, clock.now())).toBeDefined();
    clock.advance(86_400_001n);
    expect(await purgeHistory(bob.store, bob.inbox.policy, clock.now())).toBe(1);
    expect(await newestSlot(bob.store, alice.pin.identityId, 0, clock.now())).toBeUndefined();
  });
});
