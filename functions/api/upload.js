const json = (data, status = 200) => Response.json(data, { status, headers: { "Cache-Control": "no-store" } });

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
async function isAdmin(request, env) {
  const token = request.headers.get("Cookie")?.match(/(?:^|;\s*)mp_admin=([^;]+)/)?.[1];
  if (!token || !env.SESSION_SECRET) return false;
  const [payload, signature] = token.split(".");
  if (!payload || !signature || signature !== await sign(payload, env.SESSION_SECRET)) return false;
  try { return JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/"))).exp > Date.now(); } catch { return false; }
}

// Turns a "data:image/jpeg;base64,...." string into raw bytes + content type.
function decodeDataUrl(dataUrl) {
  const match = /^data:(image\/[a-zA-Z+]+);base64,(.+)$/.exec(dataUrl || "");
  if (!match) return null;
  const contentType = match[1];
  const binary = atob(match[2]);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return { contentType, bytes };
}

export async function onRequestPost(context) {
  const { request, env } = context;

  if (!env.BUCKET) return json({ error: "Storage not configured" }, 500);
  if (!(await isAdmin(request, env))) return json({ error: "Unauthorized" }, 401);

  const body = await request.json().catch(() => null);
  if (!body?.image) return json({ error: "Missing image" }, 400);

  const decoded = decodeDataUrl(body.image);
  if (!decoded) return json({ error: "Invalid image data" }, 400);

  // 5MB safety cap per photo — plenty for a compressed 900px JPEG.
  if (decoded.bytes.length > 5 * 1024 * 1024) return json({ error: "Image too large" }, 400);

  const ext = decoded.contentType.split("/")[1] || "jpg";
  const key = `products/${crypto.randomUUID()}.${ext}`;

  await env.BUCKET.put(key, decoded.bytes, { httpMetadata: { contentType: decoded.contentType } });

  const publicUrl = env.R2_PUBLIC_URL ? `${env.R2_PUBLIC_URL}/${key}` : `/images/${key}`;
  return json({ ok: true, url: publicUrl });
}

// Lets the admin panel delete an orphaned photo from R2 when a product photo is removed/replaced.
export async function onRequestDelete(context) {
  const { request, env } = context;
  if (!env.BUCKET) return json({ error: "Storage not configured" }, 500);
  if (!(await isAdmin(request, env))) return json({ error: "Unauthorized" }, 401);

  const body = await request.json().catch(() => null);
  if (!body?.key) return json({ error: "Missing key" }, 400);
  await env.BUCKET.delete(String(body.key));
  return json({ ok: true });
}
