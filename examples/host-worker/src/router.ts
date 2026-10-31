import type { Env } from "./env.js";
export async function handle(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname === "/health") return Response.json({ ok: true, host: "kavach reference host", clock: env.ALLOW_TEST_CLOCK === "true" ? "test" : "real" });
  return new Response("not found", { status: 404 });
}
