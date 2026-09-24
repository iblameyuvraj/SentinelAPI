/**
 * Intentionally Secured Backend - Hardened Authentication (OWASP API2:2023)
 * 
 * Port: 8005 (or process.env.PORT)
 * Defense Standards Enforced:
 *   1. Mandatory Authentication: Protected routes require valid Bearer token.
 *   2. Cryptographic Verification: Tokens verified with HMAC-SHA256 and SECRET_KEY.
 *   3. Algorithm Whitelisting: Rejects 'alg: none' and non-HS256 algorithms.
 *   4. Expiration Validation: Strictly validates 'exp' claim against current epoch time.
 *   5. Safe Error Handling: Returns uniform 401 Unauthorized without stack traces.
 *   6. Role-Based Access Control (RBAC): Admin routes require role: 'admin'.
 */

const http = require("http");
const url = require("url");
const crypto = require("crypto");

const PORT = process.env.PORT || 8005;
const SECRET_KEY = "sentinel-super-secret-key-2026";

// Helper: base64url encode/decode
function base64UrlEncode(str) {
  return Buffer.from(str)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function base64UrlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) {
    str += "=";
  }
  return Buffer.from(str, "base64").toString("utf8");
}

// Generate valid sample JWT
function createSampleToken(payload, expired = false) {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const fullPayload = {
    ...payload,
    iat: now - 3600,
    exp: expired ? now - 1800 : now + 3600,
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(fullPayload));
  const signature = crypto
    .createHmac("sha256", SECRET_KEY)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

// Secure JWT Verification Middleware
function verifyToken(authHeader) {
  if (!authHeader || typeof authHeader !== "string") {
    return { valid: false, error: "Missing authorization credentials" };
  }

  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    return { valid: false, error: "Invalid authorization format. Bearer token expected" };
  }

  const token = match[1].trim();
  const parts = token.split(".");
  if (parts.length !== 3) {
    return { valid: false, error: "Malformed JWT structure" };
  }

  try {
    const headerStr = base64UrlDecode(parts[0]);
    const payloadStr = base64UrlDecode(parts[1]);
    const signature = parts[2];

    const header = JSON.parse(headerStr);
    const payload = JSON.parse(payloadStr);

    // 1. Enforce Algorithm Whitelist (Prevent alg:none and confusion attacks)
    if (!header.alg || header.alg.toUpperCase() !== "HS256") {
      return { valid: false, error: "Unsupported or unverified algorithm" };
    }

    // 2. Cryptographic HMAC-SHA256 Signature Verification
    const expectedSig = crypto
      .createHmac("sha256", SECRET_KEY)
      .update(`${parts[0]}.${parts[1]}`)
      .digest("base64")
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");

    // Timing-safe comparison to prevent timing attacks
    if (signature.length !== expectedSig.length || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig))) {
      return { valid: false, error: "Invalid cryptographic signature" };
    }

    // 3. Expiration Check ('exp' claim)
    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp !== "number" || payload.exp < now) {
      return { valid: false, error: "Token has expired" };
    }

    return { valid: true, payload };
  } catch (err) {
    // Return generic error; never leak parsing exceptions or stack traces
    return { valid: false, error: "Token validation failed" };
  }
}

// Mock Database
const USERS_DB = {
  101: { id: 101, username: "yuvraj_dev", email: "yuvraj@example.com", role: "developer" },
  102: { id: 102, username: "alex_admin", email: "alex@sentinel.internal", role: "admin" },
};

const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  const method = req.method;

  // CORS Headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, Cookie, X-API-Key");
  res.setHeader("Content-Type", "application/json");

  if (method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  // 1. Safe Public Endpoint (Public access permitted)
  if (pathname === "/api/public/status" && method === "GET") {
    res.writeHead(200);
    res.end(JSON.stringify({
      status: "online",
      service: "Secured Sentinel Authentication Sandbox",
      timestamp: new Date().toISOString(),
      public_access: true,
    }));
    return;
  }

  // 2. SECURED: Admin Route requires Valid Auth + Admin Role Check
  if (pathname === "/api/admin/users" && method === "GET") {
    const auth = verifyToken(req.headers["authorization"]);
    if (!auth.valid) {
      res.writeHead(401);
      res.end(JSON.stringify({ error: auth.error }));
      return;
    }

    if (auth.payload.role !== "admin") {
      res.writeHead(403);
      res.end(JSON.stringify({ error: "Forbidden: Administrative privileges required" }));
      return;
    }

    res.writeHead(200);
    res.end(JSON.stringify({
      total_users: Object.keys(USERS_DB).length,
      users: Object.values(USERS_DB),
    }));
    return;
  }

  // 3. SECURED: User Profile requires valid token + signature + active exp
  if (pathname === "/api/user/profile" && method === "GET") {
    const auth = verifyToken(req.headers["authorization"]);
    if (!auth.valid) {
      res.writeHead(401);
      res.end(JSON.stringify({ error: auth.error }));
      return;
    }

    res.writeHead(200);
    res.end(JSON.stringify({
      message: "Profile retrieved successfully",
      authenticated_user: {
        id: auth.payload.id,
        username: auth.payload.username,
        role: auth.payload.role,
      },
    }));
    return;
  }

  // 4. SECURED: User Settings verifies token and checks expiration
  if (pathname === "/api/user/settings" && method === "GET") {
    const auth = verifyToken(req.headers["authorization"]);
    if (!auth.valid) {
      res.writeHead(401);
      res.end(JSON.stringify({ error: auth.error }));
      return;
    }

    res.writeHead(200);
    res.end(JSON.stringify({
      settings: { theme: "dark", notifications: true, auto_scan: false },
      user_id: auth.payload.id,
    }));
    return;
  }

  // 5. SECURED: User Data with safe exception handling (no 500 error leaks)
  if (pathname === "/api/user/data" && method === "GET") {
    const auth = verifyToken(req.headers["authorization"]);
    if (!auth.valid) {
      res.writeHead(401);
      res.end(JSON.stringify({ error: auth.error }));
      return;
    }

    res.writeHead(200);
    res.end(JSON.stringify({ data: "Confidential user vault data" }));
    return;
  }

  // Fallback 404
  res.writeHead(404);
  res.end(JSON.stringify({ error: "Route not found", path: pathname }));
});

server.listen(PORT, () => {
  const validDevToken = createSampleToken({ id: 101, username: "yuvraj_dev", role: "developer" }, false);
  const validAdminToken = createSampleToken({ id: 102, username: "alex_admin", role: "admin" }, false);

  console.log(`\n===============================================================`);
  console.log(`[SECURED] Hardened Auth Server on http://localhost:${PORT}`);
  console.log(`===============================================================`);
  console.log(`- GET /api/public/status       (Safe public endpoint)`);
  console.log(`- GET /api/admin/users         (Enforces RBAC: Admin Role + Valid Token)`);
  console.log(`- GET /api/user/profile        (Enforces HMAC-SHA256 & Rejects alg: none)`);
  console.log(`- GET /api/user/settings       (Enforces Token Expiration)`);
  console.log(`- GET /api/user/data           (Safe Exception Handling, No Stack Traces)`);
  console.log(`\nValid Test Tokens:`);
  console.log(`Dev Token:   Bearer ${validDevToken}`);
  console.log(`Admin Token: Bearer ${validAdminToken}\n`);
});
