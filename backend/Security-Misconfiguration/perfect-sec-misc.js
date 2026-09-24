/**
 * Intentionally Secured Backend - Security Misconfiguration Hardened (OWASP API8:2023)
 * 
 * Port: 8011 (or process.env.PORT)
 * Defense Standards Enforced:
 *   1. Complete HTTP Security Headers: Strict-Transport-Security, CSP, nosniff, X-Frame-Options, Referrer-Policy, Permissions-Policy.
 *   2. Server Technology Cloaking: Suppresses X-Powered-By and Server banner leaks.
 *   3. Hardened Cookie Security Flags: Enforces HttpOnly, Secure, SameSite=Strict on all Set-Cookie directives.
 *   4. Strict CORS Policy: Whitelists specific authorized origins; prohibits wildcard (*) with credentials.
 *   5. Safe Sanitized Error Handling: Strips internal stack traces and internal paths from API responses.
 */

const http = require("http");
const url = require("url");

const PORT = process.env.PORT || 8011;

const ALLOWED_ORIGIN = "https://app.sentinelapi.io";

function applySecurityHeaders(res) {
  // 1. Enforce HTTPS & HSTS
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");

  // 2. Strict Content Security Policy
  res.setHeader("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self';");

  // 3. Prevent MIME Sniffing
  res.setHeader("X-Content-Type-Options", "nosniff");

  // 4. Prevent Clickjacking
  res.setHeader("X-Frame-Options", "DENY");

  // 5. Secure Referrer Policy
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

  // 6. Restrict Browser Capabilities
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");

  // 7. Strip Fingerprinting Headers (Explicitly do not send X-Powered-By or Server)
  res.removeHeader("X-Powered-By");
  res.setHeader("Server", "Protected-API-Gateway");
}

const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  const method = req.method;

  // Apply baseline security headers to all responses
  applySecurityHeaders(res);

  // Strict CORS checking
  const origin = req.headers["origin"];
  if (origin === ALLOWED_ORIGIN) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  } else {
    // Prohibit cross-origin resource sharing for untrusted origins
    res.setHeader("Access-Control-Allow-Origin", "null");
  }

  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  // Handle preflight
  if (method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  // 1. Hardened Public Health Check
  if (pathname === "/api/public/status" && method === "GET") {
    res.setHeader("Content-Type", "application/json");
    res.writeHead(200);
    res.end(JSON.stringify({
      status: "online",
      service: "Hardened Security Misconfiguration Sandbox",
      headers_enforced: true,
    }));
    return;
  }

  // 2. Hardened Authentication Endpoint (Strict Cookies)
  if (pathname === "/api/auth/login" && (method === "POST" || method === "GET")) {
    res.setHeader("Content-Type", "application/json");
    // HARDENED: HttpOnly; Secure; SameSite=Strict
    res.setHeader("Set-Cookie", [
      "session_id=sess_hardened_1122334455; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600",
      "auth_token=jwt_hardened_token_789; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600"
    ]);

    res.writeHead(200);
    res.end(JSON.stringify({
      message: "Authentication successful",
      user: "guest_user",
      cookie_policy: "Enforced: HttpOnly, Secure, SameSite=Strict",
    }));
    return;
  }

  // 3. User Profile Endpoint (Hardened CORS & Headers)
  if (pathname === "/api/user/profile" && method === "GET") {
    res.setHeader("Content-Type", "application/json");
    res.writeHead(200);
    res.end(JSON.stringify({
      id: 101,
      username: "alice_crypto",
      email: "alice@example.com",
      balance: "$4,520.00",
      security: "Protected by Strict-Transport-Security, CSP, nosniff, and controlled CORS",
    }));
    return;
  }

  // 4. Diagnostic/Error Endpoint (Sanitized Error Response)
  if (pathname === "/api/debug/error" && method === "GET") {
    res.setHeader("Content-Type", "application/json");
    res.writeHead(500);
    // HARDENED: No stack trace, no environment variables, no internal IPs leaked
    res.end(JSON.stringify({
      error: "InternalServerError",
      message: "An internal service error occurred. Please contact support with Incident ID: INC-88219.",
      incident_id: "INC-88219",
    }));
    return;
  }

  // 5. Config Endpoint
  if (pathname === "/api/config" && method === "GET") {
    res.setHeader("Content-Type", "application/json");
    res.writeHead(200);
    res.end(JSON.stringify({
      api_name: "SecMisc Demo API",
      allowed_features: ["read", "write"],
    }));
    return;
  }

  // Default 404
  res.setHeader("Content-Type", "application/json");
  res.writeHead(404);
  res.end(JSON.stringify({ error: "Endpoint not found" }));
});

server.listen(PORT, () => {
  console.log(`\n===============================================================`);
  console.log(`[SECURED] Hardened Security Misconfiguration Sandbox active on http://localhost:${PORT}`);
  console.log(`===============================================================`);
  console.log(`- GET  /api/public/status  (Protected: HSTS, CSP, nosniff, X-Frame-Options)`);
  console.log(`- POST /api/auth/login     (Secured Cookies: HttpOnly; Secure; SameSite=Strict)`);
  console.log(`- GET  /api/user/profile   (Strict CORS & Cloaked Server Banners)`);
  console.log(`- GET  /api/debug/error    (Sanitized error: No stack trace or paths leaked)`);
  console.log(`- GET  /api/config         (X-Powered-By suppressed)\n`);
});
