/**
 * Intentionally Vulnerable Backend - Authentication Misconfiguration (OWASP API2:2023)
 * 
 * Port: 8004 (or process.env.PORT)
 * Vulnerabilities Demonstrated:
 *   1. Missing Authentication: Sensitive admin route (/api/admin/users) lacks auth check entirely.
 *   2. JWT alg:none Bypass: /api/user/profile accepts unsigned tokens with header {"alg": "none"}.
 *   3. Signature Verification Disabled: /api/user/profile splits token and decodes payload without verifying HMAC signature.
 *   4. Expired Token Acceptance: /api/user/settings does not validate the "exp" timestamp claim.
 *   5. Stack Trace / 500 Error Leak: /api/user/data crashes and leaks raw stack traces when passed malformed tokens.
 *   6. Safe Public Endpoint: /api/public/status properly functions without auth.
 */

const http = require("http");
const url = require("url");
const crypto = require("crypto");

const PORT = process.env.PORT || 8004;
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
    exp: expired ? now - 1800 : now + 3600, // Expired 30 min ago if expired=true
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

// Generate sample alg:none token
function createNoneAlgToken(payload) {
  const header = { alg: "none", typ: "JWT" };
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  return `${encodedHeader}.${encodedPayload}.`;
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

  // 1. Safe Public Endpoint (No auth expected)
  if (pathname === "/api/public/status" && method === "GET") {
    res.writeHead(200);
    res.end(JSON.stringify({
      status: "online",
      service: "Vulnerable Sentinel Authentication Sandbox",
      timestamp: new Date().toISOString(),
      public_access: true,
    }));
    return;
  }

  // 2. VULNERABLE: Missing Authentication on Sensitive Admin Route
  // Intended to be admin-only, but developer completely forgot auth check!
  if (pathname === "/api/admin/users" && method === "GET") {
    res.writeHead(200);
    res.end(JSON.stringify({
      warning: "VULNERABILITY DETECTED: This endpoint returned sensitive admin data without requiring authentication!",
      total_users: Object.keys(USERS_DB).length,
      users: Object.values(USERS_DB),
    }));
    return;
  }

  // 3. VULNERABLE: JWT alg:none and Signature Verification Flaws
  if (pathname === "/api/user/profile" && method === "GET") {
    const authHeader = req.headers["authorization"];

    if (!authHeader) {
      res.writeHead(401);
      res.end(JSON.stringify({ error: "Unauthorized: Missing Authorization header" }));
      return;
    }

    const token = authHeader.replace(/^Bearer\s+/i, "").trim();
    if (!token) {
      res.writeHead(401);
      res.end(JSON.stringify({ error: "Unauthorized: Empty Bearer token" }));
      return;
    }

    const parts = token.split(".");
    if (parts.length < 2) {
      res.writeHead(401);
      res.end(JSON.stringify({ error: "Invalid token format" }));
      return;
    }

    try {
      const header = JSON.parse(base64UrlDecode(parts[0]));
      const payload = JSON.parse(base64UrlDecode(parts[1]));

      // VULNERABILITY 2.1: alg:none acceptance
      if (header.alg && header.alg.toLowerCase() === "none") {
        res.writeHead(200);
        res.end(JSON.stringify({
          message: "VULNERABILITY DETECTED: Accepted JWT with alg: 'none' (unsigned token accepted!)",
          authenticated_user: payload,
          vulnerability: "JWT Signature Bypass via alg: none",
        }));
        return;
      }

      // VULNERABILITY 2.2: Blindly trusting payload without verifying signature!
      // The server fails to compute HMAC-SHA256 signature check
      res.writeHead(200);
      res.end(JSON.stringify({
        message: "Profile retrieved successfully",
        authenticated_user: payload,
        warning: "VULNERABILITY DETECTED: Server did not verify cryptographic signature against SECRET_KEY!",
      }));
      return;
    } catch (err) {
      res.writeHead(401);
      res.end(JSON.stringify({ error: "Malformed token payload" }));
      return;
    }
  }

  // 4. VULNERABLE: Expired Token Accepted
  if (pathname === "/api/user/settings" && method === "GET") {
    const authHeader = req.headers["authorization"];

    if (!authHeader) {
      res.writeHead(401);
      res.end(JSON.stringify({ error: "Unauthorized: Missing Authorization header" }));
      return;
    }

    const token = authHeader.replace(/^Bearer\s+/i, "").trim();
    const parts = token.split(".");

    if (parts.length >= 2) {
      try {
        const payload = JSON.parse(base64UrlDecode(parts[1]));
        // VULNERABILITY: Does NOT check if payload.exp < Date.now() / 1000!
        res.writeHead(200);
        res.end(JSON.stringify({
          settings: { theme: "dark", notifications: true, auto_scan: false },
          user_id: payload.id || 101,
          token_exp_received: payload.exp,
          current_server_time: Math.floor(Date.now() / 1000),
          warning: "VULNERABILITY DETECTED: Server accepted expired token without verifying 'exp' claim!",
        }));
        return;
      } catch (e) {
        res.writeHead(401);
        res.end(JSON.stringify({ error: "Invalid token" }));
        return;
      }
    }

    res.writeHead(401);
    res.end(JSON.stringify({ error: "Invalid token" }));
    return;
  }

  // 5. VULNERABLE: Stack Trace / 500 Error Leak on Malformed Token
  if (pathname === "/api/user/data" && method === "GET") {
    const authHeader = req.headers["authorization"];

    if (!authHeader) {
      res.writeHead(401);
      res.end(JSON.stringify({ error: "Unauthorized: Missing Authorization header" }));
      return;
    }

    const token = authHeader.replace(/^Bearer\s+/i, "").trim();

    // VULNERABILITY: Direct unhandled JSON.parse and Buffer decode crashes server on malformed input!
    const parts = token.split(".");
    // Deliberate lack of try/catch to simulate framework unhandled exception
    if (token.includes("invalid") || token.includes("malformed") || token.includes("not.a.valid")) {
      res.writeHead(500);
      res.end(JSON.stringify({
        error: "Internal Server Error",
        exception: "SyntaxError: Unexpected token  in JSON at position 0",
        stack_trace: [
          "at JSON.parse (<anonymous>)",
          "at decodeJwtPayload (/app/services/auth.js:42:18)",
          "at authMiddleware (/app/middleware/auth.js:89:12)",
          "at processTicksAndRejections (node:internal/process/task_queues:95:5)"
        ],
        framework: "Express/4.18.2 Node.js/" + process.version,
      }));
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
  const validToken = createSampleToken({ id: 101, username: "yuvraj_dev", role: "developer" }, false);
  const expiredToken = createSampleToken({ id: 101, username: "yuvraj_dev", role: "developer" }, true);
  const noneToken = createNoneAlgToken({ id: 101, username: "admin", role: "admin" });

  console.log(`\n===============================================================`);
  console.log(`[VULNERABLE] Auth Misconfiguration Server on http://localhost:${PORT}`);
  console.log(`===============================================================`);
  console.log(`- GET /api/public/status       (Safe public baseline)`);
  console.log(`- GET /api/admin/users         (CRITICAL: Missing Auth Check Entirely)`);
  console.log(`- GET /api/user/profile        (CRITICAL: Accepts 'alg: none' & Unverified Signatures)`);
  console.log(`- GET /api/user/settings       (HIGH: Accepts Expired Tokens)`);
  console.log(`- GET /api/user/data           (MEDIUM: Leaks 500 Stack Trace on Malformed Token)`);
  console.log(`\nPre-Generated Test Tokens:`);
  console.log(`Valid JWT:   Bearer ${validToken}`);
  console.log(`Expired JWT: Bearer ${expiredToken}`);
  console.log(`alg:none JWT: Bearer ${noneToken}\n`);
});
