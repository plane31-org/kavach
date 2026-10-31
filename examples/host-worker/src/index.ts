import type { Env } from "./env.js";
export { StreamDO } from "./streamDo.js";
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { handle } = await import("./router.js");
    return handle(request, env);
  }
};
