const encoder = new TextEncoder();

function toBase64Url(value) {
  const bytes = typeof value === "string" ? encoder.encode(value) : new Uint8Array(value);
  let output = "";
  bytes.forEach(byte => output += String.fromCharCode(byte));
  return btoa(output).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function sign(value, secret) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return toBase64Url(await crypto.subtle.sign("HMAC", key, encoder.encode(value)));
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const { password } = await request.json().catch(() => ({}));
  if (!env.ADMIN_PASSWORD || !env.SESSION_SECRET || password !== env.ADMIN_PASSWORD) {
    return Response.json({ error: "Incorrect password" }, { status: 401 });
  }

  const payload = toBase64Url(JSON.stringify({ exp: Date.now() + 8 * 60 * 60 * 1000 }));
  const token = `${payload}.${await sign(payload, env.SESSION_SECRET)}`;
  return Response.json({ ok: true }, {
    headers: {
      "Set-Cookie": `mp_admin=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`,
      "Cache-Control": "no-store"
    }
  });
}
