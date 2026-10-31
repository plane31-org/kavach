/** A minimal device for module tests: account, device, store and an epoch published to the fake host. */
import { toHex } from "../src/bytes.js";
import { resolveAudience, type ResolvedAudience } from "../src/audience.js";
import { acceptSnapshot, pinCircle, type CircleState } from "../src/circle.js";
import { DocumentType, expectType, verifyDocument, type AccountDevice } from "../src/codec.js";
import { identityId, randomBytes } from "../src/crypto.js";
import { prepareEpoch, resolvePublish } from "../src/epoch.js";
import { acceptCertificate, certify, deviceFromSeed, newDevice, openAccount, pinFromCertificate, type AccountPin, type DeviceKeys, type OwnAccount } from "../src/identity.js";
import type { InboxDeps } from "../src/inbox.js";
import type { OutboxDeps } from "../src/outbox.js";
import { circleToRow, pinToRow } from "../src/rows.js";
import { MemorySecretStore, MemoryStore } from "../src/store.js";
import { t1Activate, t1Header, t1Secrets, t3ApplyChange, t4PersistPrepared, t5Committed } from "../src/transactions.js";
import type { Transport } from "../src/transport.js";
import { buildVault } from "../src/vault.js";
import type { FakeHost } from "../src/testing/fakeHost.js";

export { testPolicy as policy, TestClock as Clock } from "../src/testing/clock.js";
import { testPolicy as policy, TestClock as Clock } from "../src/testing/clock.js";

export interface Device {
  name: string;
  account: OwnAccount;
  device: DeviceKeys;
  pin: AccountPin;
  store: MemoryStore;
  secrets: MemorySecretStore;
  transport: Transport;
  outbox: OutboxDeps;
  inbox: InboxDeps;
  /** Pin another account's certificate locally. */
  know(other: Device | Uint8Array): Promise<AccountPin>;
  /** Accept a circle snapshot locally. */
  joinLocally(circleId: Uint8Array, owner: AccountPin, snapshot: Uint8Array, enabled?: boolean): Promise<CircleState>;
  /** Prepare, publish and promote the next epoch for the current audience. */
  rotate(): Promise<number>;
  audience(): Promise<ResolvedAudience>;
}

export async function setupDevice(host: FakeHost, clock: Clock, name: string, seeds?: { accountSeed: Uint8Array; deviceSeed: Uint8Array; deviceId: Uint8Array }): Promise<Device> {
  const accountSeed = seeds?.accountSeed ?? randomBytes(32);
  const account = openAccount(name, accountSeed);
  const device = seeds ? deviceFromSeed(seeds.deviceSeed, seeds.deviceId) : newDevice();
  const certificate = certify(account, device, 1n);
  const pin = pinFromCertificate(expectType<AccountDevice>(verifyDocument(certificate), DocumentType.AccountDevice));
  const store = new MemoryStore();
  const secrets = new MemorySecretStore();
  const recoveryKey = randomBytes(32);
  const instanceId = randomBytes(16);
  await t1Secrets(secrets, { accountSeed, deviceSeed: device.deviceSeed, recoveryKey, instanceId });
  await store.transaction((tx) => t1Header(tx, { account, device, certificate, instanceId, generation: 1n }));
  const vault = buildVault({ accountName: name, accountKey: account.account.publicKey, vaultRevision: 1n }, { accountSeed, lastDeviceGeneration: 1n, lastCertificateHash: pin.certificateHash, entries: [] }, recoveryKey);
  const transport = host.asDevice(name, pin.certificateHash);
  const reg = await transport.directory.registerAccount({ certificate, vault: vault.wire });
  if (reg.status !== "COMMITTED") throw new Error("register " + reg.status);
  await store.transaction((tx) => t1Activate(tx));
  const self = { identityId: pin.identityId, certificateHash: pin.certificateHash, box: device.box };
  const outbox: OutboxDeps = { store, relay: transport.relay, policy, now: clock.now, author: () => ({ streamId: pin.streamId, signingSecretKey: device.signing.secretKey, generation: 1n, identityId: pin.identityId }) };
  const inbox: InboxDeps = { store, relay: transport.relay, policy, now: clock.now, self: () => self };
  const d: Device = {
    name,
    account,
    device,
    pin,
    store,
    secrets,
    transport,
    outbox,
    inbox,
    async know(other) {
      const wire = other instanceof Uint8Array ? other : other.pin.certificate;
      const doc = expectType<AccountDevice>(verifyDocument(wire), DocumentType.AccountDevice);
      const iid = toHex(identityId(doc.accountName, doc.accountKey));
      const existing = await store.read((tx) => tx.get("pins", iid));
      const outcome = acceptCertificate(existing ? rowToPin(existing) : undefined, wire);
      const p = outcome.pin;
      await store.transaction((tx) => {
        tx.put("pins", toHex(p.identityId), pinToRow(p));
        if (outcome.outcome === "ACCEPTED" && outcome.previous) {
          const prev = outcome.previous;
          const old = tx.get("certificates", toHex(prev.certificateHash));
          if (old) tx.put("certificates", toHex(prev.certificateHash), { ...old, current: false });
          t3ApplyChange(tx, { kind: "deviceChanged", identityId: p.identityId, certificateHash: p.certificateHash });
        }
        tx.put("certificates", toHex(p.certificateHash), { identityId: toHex(p.identityId), certificateHash: toHex(p.certificateHash), signingKey: toHex(p.signingKey), boxKey: toHex(p.boxKey), streamId: toHex(p.streamId), generation: p.generation.toString(), wire: toHex(p.certificate), current: true });
      });
      return p;
    },
    async joinLocally(circleId, owner, snapshot, enabled = true) {
      const r = acceptSnapshot(pinCircle(circleId, owner.identityId, enabled, "requested"), snapshot, owner.accountKey, pin.identityId, clock.now());
      if (r.outcome !== "ACCEPTED") throw new Error("snapshot");
      await store.transaction((tx) => {
        tx.put("circles", toHex(circleId), circleToRow(r.state));
        t3ApplyChange(tx, { kind: "snapshot", circleId, revision: r.state.revision });
      });
      return r.state;
    },
    async audience() {
      return store.read((tx) => {
        const pins = new Map(tx.list("pins").map(([k, p]) => [k, rowToPinSync(p)]));
        const circles = tx.list("circles").map(([, c]) => rowToCircleSync(c));
        return resolveAudience(pin, circles, pins);
      });
    },
    async rotate() {
      const aud = await d.audience();
      const stream = await store.read((tx) => tx.get("stream", "stream"));
      const revision = await store.read((tx) => BigInt(tx.get("revision", "revision")?.desiredRevision ?? "1"));
      const epoch = (stream?.highestCommittedEpoch ?? 0) + 1;
      const prepared = prepareEpoch({ author: { identityId: pin.identityId, certificateHash: pin.certificateHash, streamId: pin.streamId, signingSecretKey: device.signing.secretKey }, epoch, createdAt: clock.now(), audience: aud, desiredRevision: revision });
      await store.transaction((tx) => t4PersistPrepared(tx, prepared));
      const outcome = await transport.relay.publishEpoch({ streamId: pin.streamId, expectedEpoch: epoch - 1, expectedHash: undefined, manifest: prepared.manifest, wraps: prepared.wraps });
      const res = resolvePublish(prepared, outcome.status === "CONFLICT" ? { status: "CONFLICT", currentEpoch: outcome.currentEpoch ?? 0, currentManifest: outcome.currentManifest } : { status: outcome.status as "COMMITTED" });
      if (res !== "COMMITTED") throw new Error("publish " + res);
      await store.transaction((tx) => t5Committed(tx, epoch, aud.key));
      return epoch;
    }
  };
  return d;
}

import { rowToCircle, rowToPin } from "../src/rows.js";
const rowToPinSync = rowToPin;
const rowToCircleSync = rowToCircle;
