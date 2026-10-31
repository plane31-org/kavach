import type { Env } from "./env.js";
export async function handle(request: Request, _env: Env): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname === "/health") return Response.json({ ok: true, host: "kavach reference host" });
  return new Response("not found", { status: 404 });
}
