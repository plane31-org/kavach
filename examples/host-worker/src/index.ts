import type { Env } from "./env.js";
import { handle } from "./router.js";
export { StreamDO } from "./streamDo.js";
export default {
  fetch(request: Request, env: Env): Promise<Response> {
    return handle(request, env);
  }
};
