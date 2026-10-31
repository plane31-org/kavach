import type { OutboxDeps } from "../src/outbox.js";
import type { AppendOutcome } from "../src/transport.js";
import { recordOutcome } from "../src/outbox.js";

export function recordOutcomeForTest(deps: OutboxDeps, key: string, outcome: AppendOutcome | undefined): Promise<string> {
  return recordOutcome(deps, key, outcome);
}
