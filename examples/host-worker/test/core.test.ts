import { describe, expect, it } from "vitest";
import { ready, toHex } from "@kavach/core/adapters";
import { accountKeypair, identityId } from "@kavach/core/testing";

describe("core inside workerd", () => {
  it("loads the portable cipher suite and derives the fixture identity", async () => {
    await ready();
    const seed = Uint8Array.from({ length: 32 }, (_, i) => i);
    const ak = accountKeypair(seed).publicKey;
    expect(toHex(ak)).toBe("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8");
    expect(toHex(identityId("alice", ak))).toBe("64d69431f7f407ec2c6f81f1966aa10758694d0e0a0eba75726af808428c2edb");
  });
});
