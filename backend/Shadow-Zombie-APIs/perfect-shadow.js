/**
 * Intentionally Secured Backend - Asset & Inventory Hardened (OWASP API9:2023)
 * 
 * Port: 8013 (or process.env.PORT)
 * Defense Standards Enforced:
 *   1. Clean API Inventory: All active routes strictly match the official OpenAPI specification.
 *   2. Explicit Deprecation & Retirement: Deprecated v1 endpoints return HTTP 410 Gone with Sunset headers.
 *   3. Disabled Diagnostics & Debug: No debug or actuator routes exposed in production (HTTP 404).
 *   4. Zero Shadow Routes: Beta, internal, or backup endpoints are stripped before deployment.
 */

const http = require("http");
const url = require("url");

const PORT = process.env.PORT || 8013;

const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  const method = req.method;

  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Content-Type", "application/json");

  if (method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  // ==========================================
  // 1. OFFICIAL DOCUMENTED ENDPOINTS (In OpenAPI spec)
  // ==========================================
  if (pathname === "/api/public/ping" && method === "GET") {
    res.writeHead(200);
    res.end(JSON.stringify({ status: "ok", service: "Hardened Inventory API (v2.0)" }));
    return;
  }

  if (pathname === "/api/v2/users" && method === "GET") {
    res.writeHead(200);
    res.end(JSON.stringify({
      version: "2.0",
      users: [
        { id: 101, username: "alice_crypto" },
        { id: 102, username: "bob_traveler" }
      ]
    }));
    return;
  }

  if (pathname === "/api/v2/products" && method === "GET") {
    res.writeHead(200);
    res.end(JSON.stringify({
      version: "2.0",
      products: [
        { id: 1, name: "Premium Dog Leash", price: 29.99 },
        { id: 2, name: "Organic Dog Food", price: 45.00 }
      ]
    }));
    return;
  }

  // ==========================================
  // 2. HARDENED ZOMBIE DECOMMISSIONING (HTTP 410 Gone)
  // ==========================================
  if (pathname.startsWith("/api/v1/")) {
    res.setHeader("Sunset", "Wed, 01 Jan 2025 00:00:00 GMT");
    res.setHeader("Link", '</api/v2>; rel="successor-version"');
    res.writeHead(410);
    res.end(JSON.stringify({
      error: "Gone",
      message: "API version 1.0 has been permanently decommissioned as of Jan 1, 2025. Please migrate your client to /api/v2/.",
      documentation: "https://docs.sentinelapi.io/api/v2"
    }));
    return;
  }

  // ==========================================
  // 3. HARDENED DEBUG & SHADOW ROUTE SUPPRESSION (HTTP 404)
  // All internal, beta, and diagnostic routes are completely disabled in production.
  // ==========================================
  res.writeHead(404);
  res.end(JSON.stringify({ error: "Route not found", path: pathname }));
});

server.listen(PORT, () => {
  console.log(`\n===============================================================`);
  console.log(`[SECURED] Hardened Shadow & Zombie API Sandbox active on http://localhost:${PORT}`);
  console.log(`===============================================================`);
  console.log(`- GET  /api/public/ping    (Documented active)`);
  console.log(`- GET  /api/v2/users        (Documented active)`);
  console.log(`- GET  /api/v2/products     (Documented active)`);
  console.log(`- ALL  /api/v1/*            (HARDENED: Returns HTTP 410 Gone with Sunset header)`);
  console.log(`- ALL  /debug/*, /actuator  (HARDENED: Completely disabled in production 404)\n`);
});
