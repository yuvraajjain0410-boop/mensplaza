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

function decodeDataUrl(dataUrl) {
  const match = /^data:(image\/[a-zA-Z+]+);base64,(.+)$/.exec(dataUrl || "");
  if (!match) return null;
  const contentType = match[1];
  const binary = atob(match[2]);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return { contentType, bytes };
}

async function uploadOne(env, dataUrl, tag) {
  const decoded = decodeDataUrl(dataUrl);
  if (!decoded) return dataUrl; // not base64 (already a URL, or empty) — leave untouched
  const ext = decoded.contentType.split("/")[1] || "jpg";
  const key = `products/migrated-${tag}-${crypto.randomUUID()}.${ext}`;
  await env.BUCKET.put(key, decoded.bytes, { httpMetadata: { contentType: decoded.contentType } });
  return env.R2_PUBLIC_URL ? `${env.R2_PUBLIC_URL}/${key}` : `/images/${key}`;
}

const BATCH_SIZE = 12; // conservative, to stay well inside the Worker's per-request time limit

export async function onRequestPost(context) {
  const { request, env } = context;

  if (!env.BUCKET) return json({ error: "Storage not configured (R2 binding missing)" }, 500);
  if (!(await isAdmin(request, env))) return json({ error: "Unauthorized" }, 401);

  const { results } = await env.DB.prepare(
    "SELECT id, image, images FROM products WHERE image LIKE 'data:%' OR images LIKE '%data:%' LIMIT ?"
  ).bind(BATCH_SIZE).all();

  if (!results.length) {
    return json({ ok: true, processed: 0, done: true, message: "No base64 photos left — migration complete." });
  }

  const statements = [];
  for (const row of results) {
    const newImage = await uploadOne(env, row.image, `${row.id}-main`);
    let oldImages = [];
    try { oldImages = JSON.parse(row.images || "[]"); } catch {}
    const newImages = [];
    for (let i = 0; i < oldImages.length; i++) {
      newImages.push(await uploadOne(env, oldImages[i], `${row.id}-${i}`));
    }
    statements.push(
      env.DB.prepare("UPDATE products SET image = ?, images = ? WHERE id = ?")
        .bind(newImage, JSON.stringify(newImages), row.id)
    );
  }
  await env.DB.batch(statements);

  const { results: remainingRows } = await env.DB.prepare(
    "SELECT COUNT(*) as c FROM products WHERE image LIKE 'data:%' OR images LIKE '%data:%'"
  ).all();
  const remaining = remainingRows[0]?.c || 0;

  return json({ ok: true, processed: results.length, remaining, done: remaining === 0 });
}
