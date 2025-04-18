// api/decrypt.js — GitHub Pages Function (Deno / Cloudflare Workers edge)
export async function onRequestGet({ request }) {
  const { searchParams } = new URL(request.url);
  const encURL   = searchParams.get("url");
  const password = searchParams.get("key");

  if (!encURL || !password) {
    return new Response(
      "usage: /api/decrypt?url=<ENC_URL>&key=<PASSWORD>",
      { status: 400, headers: { "content-type": "text/plain" } },
    );
  }

  // 1. fetch base64 ciphertext
  const res = await fetch(encURL);
  if (!res.ok) {
    return new Response(
      `fetch error: HTTP ${res.status}`,
      { status: 502, headers: { "content-type": "text/plain" } },
    );
  }
  const b64 = await res.text();
  const enc = Uint8Array.from(atob(b64.replace(/\\s+/g, "")), c => c.charCodeAt(0));

  // 2. sanity‑check + split header / salt / cipher
  if (enc.length < 16 || new TextDecoder().decode(enc.slice(0, 8)) !== "Salted__") {
    return new Response("invalid OpenSSL ciphertext", {
      status: 422,
      headers: { "content-type": "text/plain" },
    });
  }
  const salt   = enc.slice(8, 16);
  const cipher = enc.slice(16);

  // 3. derive key & IV (PBKDF2‑SHA256, 10 000 iters)
  const passKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits  = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 10000, hash: "SHA-256" },
    passKey,
    384,
  );
  const bytes = new Uint8Array(bits);          // 32 key | 16 IV
  const aesKey = await crypto.subtle.importKey(
    "raw",
    bytes.slice(0, 32),
    { name: "AES-CBC" },
    false,
    ["decrypt"],
  );
  const plainBuf = await crypto.subtle.decrypt(
    { name: "AES-CBC", iv: bytes.slice(32, 48) },
    aesKey,
    cipher,
  );

  return new Response(plainBuf, {
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}
