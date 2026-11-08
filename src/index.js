
const COOKIE = "opm_session";
const SESSION_DAYS = 7;

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...extraHeaders
    }
  });
}

function cookieOptions(maxAge) {
  return `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

function randomHex(length = 32) {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

async function sha256(value) {
  const data = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash), b =>
    b.toString(16).padStart(2, "0")
  ).join("");
}

async function passwordHash(password, salt) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    salt: new TextEncoder().encode(salt),
    iterations: 310000,
    hash: "SHA-256"
  }, key, 256);

  return Array.from(new Uint8Array(bits), b =>
    b.toString(16).padStart(2, "0")
  ).join("");
}

function getCookie(request) {
  const cookies = request.headers.get("Cookie") || "";
  const match = cookies.match(/(?:^|;\s*)opm_session=([^;]+)/);
  return match ? match[1] : null;
}

async function createSession(env, userId) {
  const token = randomHex(32);
  const tokenHash = await sha256(token);
  const expires = new Date(
    Date.now() + SESSION_DAYS * 86400000
  ).toISOString();

  await env.DB.prepare(
    "INSERT INTO user_sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)"
  ).bind(userId, tokenHash, expires).run();

  return token;
}

async function getUser(request, env) {
  const token = getCookie(request);
  if (!token) return null;

  const tokenHash = await sha256(token);

  const session = await env.DB.prepare(`
    SELECT users.id, users.username, users.diamond,
           users.gold, users.summon_ticket
    FROM user_sessions
    JOIN users ON users.id = user_sessions.user_id
    WHERE user_sessions.token_hash = ?
      AND user_sessions.expires_at > ?
  `).bind(tokenHash, new Date().toISOString()).first();

  return session || null;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Allow": "GET, POST, OPTIONS"
        }
      });
    }

    try {
      if (path === "/api/status" && request.method === "GET") {
        await env.DB.prepare("SELECT 1").first();

        return json({
          success: true,
          message: "OPM Reborn backend aktif",
          database: "connected"
        });
      }

      if (path === "/api/register" && request.method === "POST") {
        const body = await request.json();
        const username = String(body.username || "").trim();
        const password = String(body.password || "");

        if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
          return json({
            success: false,
            message: "Username harus 3-20 karakter, hanya huruf, angka, dan underscore."
          }, 400);
        }

        if (password.length < 8 || password.length > 128) {
          return json({
            success: false,
            message: "Password harus 8-128 karakter."
          }, 400);
        }

        const salt = randomHex(16);
        const hash = await passwordHash(password, salt);

        await env.DB.prepare(`
          INSERT INTO users
          (username, password_hash, password_salt)
          VALUES (?, ?, ?)
        `).bind(username, hash, salt).run();

        const user = await env.DB.prepare(
          "SELECT id, username, diamond, gold, summon_ticket FROM users WHERE username = ?"
        ).bind(username).first();

        const token = await createSession(env, user.id);

        return json({
          success: true,
          message: "Registrasi berhasil",
          user
        }, 201, {
          "Set-Cookie": `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`
        });
      }

      if (path === "/api/login" && request.method === "POST") {
        const body = await request.json();
        const username = String(body.username || "").trim();
        const password = String(body.password || "");

        const user = await env.DB.prepare(
          "SELECT * FROM users WHERE username = ?"
        ).bind(username).first();

        if (!user) {
          return json({
            success: false,
            message: "Username atau password salah."
          }, 401);
        }

        const hash = await passwordHash(password, user.password_salt);

        if (hash !== user.password_hash) {
          return json({
            success: false,
            message: "Username atau password salah."
          }, 401);
        }

        const token = await createSession(env, user.id);

        return json({
          success: true,
          message: "Login berhasil"
        }, 200, {
          "Set-Cookie": `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`
        });
      }

      if (path === "/api/me" && request.method === "GET") {
        const user = await getUser(request, env);

        if (!user) {
          return json({
            success: false,
            message: "Belum login."
          }, 401);
        }

        return json({
          success: true,
          user
        });
      }

      if (path === "/api/logout" && request.method === "POST") {
        const token = getCookie(request);

        if (token) {
          const tokenHash = await sha256(token);

          await env.DB.prepare(
            "DELETE FROM user_sessions WHERE token_hash = ?"
          ).bind(tokenHash).run();
        }

        return json({
          success: true,
          message: "Logout berhasil"
        }, 200, {
          "Set-Cookie": cookieOptions(0)
        });
      }

      if (path === "/api/players" && request.method === "GET") {
        const user = await getUser(request, env);

        if (!user) {
          return json({
            success: false,
            message: "Silakan login terlebih dahulu."
          }, 401);
        }

        return json([user]);
      }

      return json({
        success: false,
        message: "Endpoint tidak ditemukan."
      }, 404);

    } catch (error) {
      if (error.message && error.message.includes("UNIQUE constraint failed")) {
        return json({
          success: false,
          message: "Username sudah digunakan."
        }, 409);
      }

      return json({
        success: false,
        message: "Terjadi kesalahan pada server."
      }, 500);
    }
  }
};
