import { DurableObject } from "cloudflare:workers";
import type { Env } from "./env.js";
export class StreamDO extends DurableObject<Env> {
  async fetch(): Promise<Response> {
    return Response.json({ ok: true });
  }
}
