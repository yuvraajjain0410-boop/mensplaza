const json = (data, status = 200, headers = {}) =>
  Response.json(data, { status, headers: { "Cache-Control": "no-store", ...headers } });

const encoder = new TextEncoder();
const toBase64Url = value => {
  const bytes = typeof value === "string" ? encoder.encode(value) : new Uint8Array(value);
  let output = "";
  bytes.forEach(byte => output += String.fromCharCode(byte));
  return btoa(output).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};
async function sign(value, secret) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return toBase64Url(await crypto.subtle.sign("HMAC", key, encoder.encode(value)));
}

const SESSION_HOURS = 12;

export async function onRequestPost(context) {
  const { request, env } = context;

  if (!env.ADMIN_PASSWORD || !env.SESSION_SECRET) {
    return json({ error: "Server not configured" }, 500);
  }

  let body;
  try { body = await request.json(); } catch { return json({ error: "Bad request" }, 400); }

  if (typeof body?.password !== "string" || body.password !== env.ADMIN_PASSWORD) {
    return json({ error: "Incorrect password" }, 401);
  }

  const exp = Date.now() + SESSION_HOURS * 60 * 60 * 1000;
  const payload = toBase64Url(JSON.stringify({ exp }));
  const signature = await sign(payload, env.SESSION_SECRET);
  const token = `${payload}.${signature}`;

  const cookie = [
    `mp_admin=${token}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
    `Max-Age=${SESSION_HOURS * 60 * 60}`
  ].join("; ");

  return json({ ok: true }, 200, { "Set-Cookie": cookie });
}

// Optional: lets the admin panel explicitly log out if you wire a button to it later.
export async function onRequestDelete() {
  const cookie = ["mp_admin=", "Path=/", "HttpOnly", "Secure", "SameSite=Strict", "Max-Age=0"].join("; ");
  return json({ ok: true }, 200, { "Set-Cookie": cookie });
}
