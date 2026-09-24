/**
 * Intentionally Vulnerable Backend - Security Misconfiguration (OWASP API8:2023)
 * 
 * Port: 8010 (or process.env.PORT)
 * Vulnerabilities Demonstrated:
 *   1. Missing HTTP Security Headers: No HSTS, CSP, nosniff, X-Frame-Options, or Referrer-Policy.
 *   2. Server Technology Fingerprinting: Leaks "X-Powered-By: Express/4.18.2" and "Server: Apache/2.4.52 (Ubuntu)".
 *   3. Insecure Cookie Attributes: Sets session cookie without HttpOnly, Secure, or SameSite flags.
 *   4. CORS Misconfiguration: Overly permissive CORS with wildcard or arbitrary origin reflection with credentials.
 *   5. Verbose Diagnostic Error: Returns internal stack trace and system paths on error.
 */

const http = require("http");
const url = require("url");

const PORT = process.env.PORT || 8010;

const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  const method = req.method;

  // VULNERABLE: Leaking technology banners and server fingerprints
  res.setHeader("X-Powered-By", "Express/4.18.2");
  res.setHeader("Server", "Apache/2.4.52 (Ubuntu) PHP/8.1.2");

  // VULNERABLE: Overly permissive CORS wildcard on all routes
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  // Handle preflight
  if (method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  // 1. Public Health Check (Missing all security headers)
  if (pathname === "/api/public/status" && method === "GET") {
    res.setHeader("Content-Type", "application/json");
    res.writeHead(200);
    res.end(JSON.stringify({
      status: "online",
      service: "Vulnerable Security Misconfiguration Sandbox",
      version: "1.0.0-beta",
    }));
    return;
  }

  // 2. Authentication & Session Endpoint (Insecure Set-Cookie)
  if (pathname === "/api/auth/login" && (method === "POST" || method === "GET")) {
    res.setHeader("Content-Type", "application/json");
    // VULNERABLE: Missing HttpOnly (allows XSS theft), missing Secure (transmitted over plaintext HTTP), missing SameSite (CSRF risk)
    res.setHeader("Set-Cookie", [
      "session_id=sess_vuln_998877665544; Path=/;",
      "auth_token=jwt_vuln_insecure_token_123; Path=/;"
    ]);

    res.writeHead(200);
    res.end(JSON.stringify({
      message: "Authentication successful",
      user: "guest_user",
      notice: "VULNERABILITY: Cookies returned without HttpOnly, Secure, or SameSite flags!",
    }));
    return;
  }

  // 3. User Profile Endpoint (Permissive CORS + Missing Headers)
  if (pathname === "/api/user/profile" && method === "GET") {
    const origin = req.headers["origin"] || "*";
    // VULNERABILITY: Arbitrary origin reflection with credentials allowed
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Content-Type", "application/json");

    res.writeHead(200);
    res.end(JSON.stringify({
      id: 101,
      username: "alice_crypto",
      email: "alice@example.com",
      balance: "$4,520.00",
      warning: "VULNERABILITY: Origin reflection with Access-Control-Allow-Credentials: true allows any site to read this data!",
    }));
    return;
  }

  // 4. Diagnostic/Error Endpoint (Verbose Stack Trace Leak)
  if (pathname === "/api/debug/error" && method === "GET") {
    res.setHeader("Content-Type", "application/json");
    res.writeHead(500);
    res.end(JSON.stringify({
      error: "InternalServerError",
      message: "Database connection failed: getaddrinfo ENOTFOUND db-internal.cluster.local",
      stack: "Error: connect ECONNREFUSED 10.0.4.15:5432\n    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1494:16)\n    at Pool.connect (/var/www/api/node_modules/pg-pool/index.js:59:11)",
      environment: {
        NODE_ENV: "development",
        DEBUG: "true",
        SERVER_ROOT: "/var/www/api",
      }
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
  res.end(JSON.stringify({ error: "Endpoint not found", path: pathname }));
});

server.listen(PORT, () => {
  console.log(`\n===============================================================`);
  console.log(`[VULNERABLE] Security Misconfiguration Sandbox active on http://localhost:${PORT}`);
  console.log(`===============================================================`);
  console.log(`- GET  /api/public/status  (Missing HSTS, CSP, nosniff, X-Frame-Options)`);
  console.log(`- POST /api/auth/login     (Insecure Cookies: Missing HttpOnly, Secure, SameSite)`);
  console.log(`- GET  /api/user/profile   (Permissive CORS: Arbitrary Origin reflection + Credentials)`);
  console.log(`- GET  /api/debug/error    (Verbose stack trace and environment leak)`);
  console.log(`- GET  /api/config         (Server banner leaks X-Powered-By & Server headers)\n`);
});
