/**
 * Intentionally Vulnerable Backend - Shadow & Zombie APIs (OWASP API9:2023)
 * 
 * Port: 8012 (or process.env.PORT)
 * Vulnerabilities Demonstrated:
 *   1. Zombie API: Old deprecated v1 routes (/api/v1/users, /api/v1/auth/legacy-login) left active without auth.
 *   2. Shadow API: Hidden undocumented routes (/api/v2/beta/export-users) not documented in OpenAPI spec.
 *   3. Exposed Debug/Diagnostics: Diagnostic endpoint (/debug/server-vars) exposing system secrets.
 *   4. Sensitive Backup Exposure: Legacy backup files (/api/config.old) accessible via direct URL.
 *   5. Spring Boot / Actuator Leak: Exposed /actuator/health and /metrics.
 */

const http = require("http");
const url = require("url");

const PORT = process.env.PORT || 8012;

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
    res.end(JSON.stringify({ status: "ok", service: "Inventory Sandbox API (v2.0)" }));
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
  // 2. ZOMBIE APIS (Deprecated v1 routes left running)
  // ==========================================
  // VULNERABILITY: /api/v1/users was retired in 2024, but server still responds!
  // It lacks current authentication and leaks sensitive PII!
  if (pathname === "/api/v1/users" && method === "GET") {
    res.writeHead(200);
    res.end(JSON.stringify({
      warning: "ZOMBIE API: Deprecated v1 endpoint still active without modern authentication!",
      version: "1.0-deprecated",
      users: [
        { id: 101, username: "alice_crypto", email: "alice@example.com", ssn: "XXX-XX-4819", salary: "$125,000" },
        { id: 102, username: "bob_traveler", email: "bob@example.com", ssn: "XXX-XX-1122", salary: "$95,000" }
      ]
    }));
    return;
  }

  if (pathname === "/api/v1/auth/legacy-login" && (method === "POST" || method === "GET")) {
    res.writeHead(200);
    res.end(JSON.stringify({
      warning: "ZOMBIE API: Legacy v1 login endpoint bypasses modern 2FA enforcement!",
      status: "authenticated",
      bypass_2fa: true,
      token: "legacy_insecure_token_1928"
    }));
    return;
  }

  // ==========================================
  // 3. SHADOW APIS (Undocumented live routes)
  // ==========================================
  // VULNERABILITY: Developer added a beta bulk export route and forgot to document or remove it
  if (pathname === "/api/v2/beta/export-users" && method === "GET") {
    res.writeHead(200);
    res.end(JSON.stringify({
      warning: "SHADOW API DETECTED: Undocumented beta endpoint live in production!",
      exported_records: 2,
      data: [
        { id: 101, username: "alice_crypto", password_hash: "$2b$12$e829312...hashed" },
        { id: 102, username: "bob_traveler", password_hash: "$2b$12$k102941...hashed" }
      ]
    }));
    return;
  }

  // ==========================================
  // 4. EXPOSED DIAGNOSTICS & SYSTEM METRICS
  // ==========================================
  if (pathname === "/debug/server-vars" && method === "GET") {
    res.writeHead(200);
    res.end(JSON.stringify({
      warning: "SHADOW DIAGNOSTIC DETECTED: Server environment variables exposed!",
      environment: "production",
      internal_db_host: "postgres-cluster.internal.sentinel.io",
      jwt_secret_key: "super_secret_jwt_key_2026",
      cloud_bucket: "s3://sentinel-production-assets"
    }));
    return;
  }

  if (pathname === "/actuator/health" && method === "GET") {
    res.writeHead(200);
    res.end(JSON.stringify({
      status: "UP",
      components: { db: { status: "UP" }, diskSpace: { status: "UP" } }
    }));
    return;
  }

  // ==========================================
  // 5. SENSITIVE BACKUP / CONFIG EXPOSURE
  // ==========================================
  if (pathname === "/api/config.old" && method === "GET") {
    res.writeHead(200);
    res.end(JSON.stringify({
      warning: "SHADOW BACKUP DETECTED: Deprecated configuration file left accessible!",
      database_url: "postgres://admin:Password123@localhost:5432/main_db"
    }));
    return;
  }

  // Default 404
  res.writeHead(404);
  res.end(JSON.stringify({ error: "Route not found", path: pathname }));
});

server.listen(PORT, () => {
  console.log(`\n===============================================================`);
  console.log(`[VULNERABLE] Shadow & Zombie API Sandbox active on http://localhost:${PORT}`);
  console.log(`===============================================================`);
  console.log(`Documented Routes (In OpenAPI Spec):`);
  console.log(`  - GET  /api/public/ping`);
  console.log(`  - GET  /api/v2/users`);
  console.log(`  - GET  /api/v2/products\n`);
  console.log(`Undocumented Shadow & Zombie Routes (ACTIVE ON SERVER):`);
  console.log(`  - GET  /api/v1/users               (ZOMBIE: Old v1 leaks PII without auth)`);
  console.log(`  - POST /api/v1/auth/legacy-login   (ZOMBIE: Old login bypasses 2FA)`);
  console.log(`  - GET  /api/v2/beta/export-users   (SHADOW: Undocumented beta export)`);
  console.log(`  - GET  /debug/server-vars          (SHADOW: Leaks environment secrets)`);
  console.log(`  - GET  /actuator/health            (SHADOW: Spring Actuator exposed)`);
  console.log(`  - GET  /api/config.old             (SHADOW: Backup config leaked)\n`);
});
