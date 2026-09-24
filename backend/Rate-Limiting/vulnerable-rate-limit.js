/**
 * Intentionally Vulnerable Backend - Unrestricted Resource Consumption & Missing Rate Limiting (OWASP API4:2023)
 * 
 * Port: 8006 (or process.env.PORT)
 * Vulnerability:
 *   Endpoints completely lack rate limiting, concurrency throttles, or IP-based limits.
 *   Allows infinite burst requests, brute-force credential attacks, and compute exhaustion.
 */

const http = require("http");
const url = require("url");

const PORT = process.env.PORT || 8006;

// Counter to track total requests received per IP for demonstration
const requestCounts = {};

const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  const method = req.method;
  const clientIp = req.socket.remoteAddress || "127.0.0.1";

  // Track request count
  requestCounts[clientIp] = (requestCounts[clientIp] || 0) + 1;

  // CORS Headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, Cookie");
  res.setHeader("Content-Type", "application/json");

  if (method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  // 1. Safe Public Health Check
  if (pathname === "/api/public/status" && method === "GET") {
    res.writeHead(200);
    res.end(JSON.stringify({
      status: "online",
      service: "Vulnerable Rate Limit Sandbox",
      total_requests_received: requestCounts[clientIp],
    }));
    return;
  }

  // 2. VULNERABLE: Authentication Login Endpoint (No rate limiting / Brute-force prone)
  if (pathname === "/api/auth/login" && method === "POST") {
    // VULNERABILITY: No lockout, no 429 status, no IP throttling!
    res.writeHead(200);
    res.end(JSON.stringify({
      status: "processed",
      message: "Login attempt processed without throttling",
      attempt_number: requestCounts[clientIp],
      warning: "VULNERABILITY DETECTED: Endpoint processed burst request without returning HTTP 429 or rate limit headers!",
    }));
    return;
  }

  // 3. VULNERABLE: Password Reset / SMS OTP trigger (Allows OTP flooding / Email bombing)
  if (pathname === "/api/auth/forgot-password" && method === "POST") {
    res.writeHead(200);
    res.end(JSON.stringify({
      status: "queued",
      message: "Password reset link dispatched",
      request_count: requestCounts[clientIp],
      warning: "VULNERABILITY DETECTED: Missing rate limiting allows attackers to flood inbox/SMS services (Financial exhaustion risk)!",
    }));
    return;
  }

  // 4. VULNERABLE: Resource-Intensive Search Endpoint (Allows compute exhaustion / DoS)
  if (pathname === "/api/search" && method === "GET") {
    // Simulate heavy query workload
    const query = parsedUrl.query.q || "all";
    res.writeHead(200);
    res.end(JSON.stringify({
      query: query,
      results_count: 150,
      compute_time_ms: 12.4,
      total_burst_count: requestCounts[clientIp],
      warning: "VULNERABILITY DETECTED: Unrestricted heavy search queries can exhaust database connection pools!",
    }));
    return;
  }

  // 5. VULNERABLE: User Profile Export
  if (pathname === "/api/user/export" && method === "GET") {
    res.writeHead(200);
    res.end(JSON.stringify({
      export_status: "ready",
      archive_size_bytes: 5242880, // 5MB simulated
      warning: "VULNERABILITY DETECTED: Uncapped large payload downloads allow network bandwidth exhaustion.",
    }));
    return;
  }

  // Fallback 404
  res.writeHead(404);
  res.end(JSON.stringify({ error: "Route not found", path: pathname }));
});

server.listen(PORT, () => {
  console.log(`\n===============================================================`);
  console.log(`[VULNERABLE] Rate Limit Sandbox active on http://localhost:${PORT}`);
  console.log(`===============================================================`);
  console.log(`- GET  /api/public/status          (Safe status baseline)`);
  console.log(`- POST /api/auth/login             (HIGH: Unrestricted credential brute-force)`);
  console.log(`- POST /api/auth/forgot-password   (HIGH: Unrestricted OTP / Email flood)`);
  console.log(`- GET  /api/search                 (MEDIUM: Heavy un-cached query exhaustion)`);
  console.log(`- GET  /api/user/export            (MEDIUM: Large export bandwidth exhaustion)\n`);
});
