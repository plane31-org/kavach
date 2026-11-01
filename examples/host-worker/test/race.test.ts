/** Review finding 3: two replacements racing at the Worker commit exactly one, and the loser leaves no trace. */
import { describe, expect, it } from "vitest";
import { toHex } from "@plane31/blind-relay";
import { circleOfTwo, device, hostJson, Platform } from "./world.js";

async function proposal(name: string) {
  const d = await device(name, new Platform());
  const p = await d.client.prepareReplacement();
  const { token } = await hostJson<{ token: string }>(`/v1/accounts/${name}/replacement-authorizations`, {
    method: "POST",
    body: JSON.stringify({ successionId: toHex(p.successionId), expectedCertificateHash: toHex(p.expectedCertificateHash), certificate: toHex(p.certificate) })
  });
  return { d, p, token: Uint8Array.from(Buffer.from(token, "hex")) };
}

describe("two replacements racing at the Worker", () => {
  it("exactly one commits; the loser's succession is never stored and can never answer as committed", async () => {
    const { bobId } = await circleOfTwo();
    const x = await proposal("bob");
    const y = await proposal("bob");
    const outcomes = await Promise.all(
      [x, y].map((c) =>
        c.d.client
          .completeReplacement({ successionId: c.p.successionId, authorization: c.token })
          .then(() => "OK")
          .catch((e: { code?: string }) => e.code ?? "ERROR")
      )
    );
    expect(outcomes.sort()).toEqual(["OK", "REPLACEMENT_CONFLICT"]);
    const page = await hostJson<{ successions: unknown[] }>(`/v1/successions/${toHex(bobId)}?after=0&limit=10`);
    expect(page.successions.length).toBe(1);
    const loser = outcomes[0] === "OK" ? y : x;
    // The loser's id is unknown to the host: the same call again is a definitive conflict, not ALREADY_COMMITTED.
    expect(await loser.d.client.completeReplacement({ successionId: loser.p.successionId, authorization: loser.token }).catch((e: { code?: string }) => e.code)).toBe("REPLACEMENT_CONFLICT");
    const [resolved] = await hostJson<{ certificate: string; successions?: unknown[] }[]>(`/v1/accounts?names=bob`);
    expect(resolved?.successions?.length).toBe(1);
  });
});
