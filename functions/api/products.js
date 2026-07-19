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

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "GET") {
    const { results } = await env.DB.prepare(
      "SELECT id, name, brand, price, old_price, category, gender, sizes, image, images, notes, stock FROM products ORDER BY created_at DESC"
    ).all();
    return json(results.map(row => ({
      id: row.id, name: row.name, brand: row.brand || "Men's Plaza", price: row.price,
      oldPrice: row.old_price || 0, cat: row.category, gender: row.gender || "Unisex",
      size: row.sizes || "", img: row.image || "", images: JSON.parse(row.images || "[]"),
      notes: row.notes || "", stock: row.stock || 0
    })));
  }

  if (request.method !== "PUT") return json({ error: "Method not allowed" }, 405);
  if (!(await isAdmin(request, env))) return json({ error: "Unauthorized" }, 401);

  const body = await request.json();
  // index.html sends { products, deletedIds } — NOT a bare array. Support both
  // shapes so an older cached frontend can't silently break saving either.
  const products = Array.isArray(body) ? body : body?.products;
  const deletedIds = Array.isArray(body?.deletedIds) ? body.deletedIds : [];
  if (!Array.isArray(products)) return json({ error: "Products must be an array" }, 400);
  if (products.length > 500) return json({ error: "Too many products" }, 400);
  if (deletedIds.length > 500) return json({ error: "Too many deletions" }, 400);

  // Upsert only what was sent. Never wipe the whole table — if a second device
  // (or a stale browser cache) saves with a shorter local list, products that
  // device doesn't know about must survive.
  const statements = [];
  for (const product of products) {
    if (!product.id || !product.name || !Number.isFinite(Number(product.price))) continue;
    statements.push(env.DB.prepare(
      "INSERT INTO products (id, name, brand, price, old_price, category, gender, sizes, image, images, notes, stock, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(id) DO UPDATE SET name=excluded.name, brand=excluded.brand, price=excluded.price, old_price=excluded.old_price, category=excluded.category, gender=excluded.gender, sizes=excluded.sizes, image=excluded.image, images=excluded.images, notes=excluded.notes, stock=excluded.stock, updated_at=CURRENT_TIMESTAMP"
    ).bind(
      String(product.id), String(product.name), String(product.brand || "Men's Plaza"), Number(product.price), Number(product.oldPrice || 0),
      String(product.cat || "Other"), String(product.gender || "Unisex"), String(product.size || ""), String(product.img || ""),
      JSON.stringify(Array.isArray(product.images) ? product.images : []), String(product.notes || ""), Number(product.stock || 0)
    ));
  }
  for (const id of deletedIds) {
    if (id) statements.push(env.DB.prepare("DELETE FROM products WHERE id = ?").bind(String(id)));
  }
  if (!statements.length) return json({ ok: true, count: 0 });
  await env.DB.batch(statements);
  return json({ ok: true, count: products.length });
}
