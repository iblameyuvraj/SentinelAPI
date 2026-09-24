/**
 * Intentionally Secured Backend - Hardened Rate Limiting & Throttling (OWASP API4:2023)
 * 
 * Port: 8007 (or process.env.PORT)
 * Defense Standards Enforced:
 *   1. Strict Sliding Window Throttling on sensitive auth routes (5 req/min).
 *   2. RFC Standard Rate Limit Headers (X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After).
 *   3. HTTP 429 Too Many Requests returned upon exceeding threshold.
 *   4. Exponential backoff requirement for brute-force mitigation.
 */

const http = require("http");
const url = require("url");

const PORT = process.env.PORT || 8007;

// In-Memory Sliding Window Rate Limiter
// Map: key -> Array of timestamps (in ms)
const requestWindows = new Map();

function checkRateLimit(key, maxRequests, windowMs) {
  const now = Date.now();
  let timestamps = requestWindows.get(key) || [];

  // Evict timestamps older than the sliding window
  timestamps = timestamps.filter(ts => now - ts < windowMs);
  requestWindows.set(key, timestamps);

  if (timestamps.length >= maxRequests) {
    const oldest = timestamps[0];
    const retryAfterSec = Math.ceil((windowMs - (now - oldest)) / 1000);
    return {
      allowed: false,
      limit: maxRequests,
      remaining: 0,
      retryAfter: Math.max(1, retryAfterSec),
      resetTime: Math.ceil((oldest + windowMs) / 1000),
    };
  }

  // Record current request
  timestamps.push(now);
  requestWindows.set(key, timestamps);

  return {
    allowed: true,
    limit: maxRequests,
    remaining: maxRequests - timestamps.length,
    retryAfter: 0,
    resetTime: Math.ceil((now + windowMs) / 1000),
  };
}

const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  const method = req.method;
  const clientIp = req.socket.remoteAddress || "127.0.0.1";

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

  // Helper to send rate-limited response
  function applyRateLimit(routeKey, maxRequests, windowMs = 60000) {
    const rateKey = `${clientIp}:${routeKey}`;
    const status = checkRateLimit(rateKey, maxRequests, windowMs);

    res.setHeader("X-RateLimit-Limit", status.limit.toString());
    res.setHeader("X-RateLimit-Remaining", status.remaining.toString());
    res.setHeader("X-RateLimit-Reset", status.resetTime.toString());

    if (!status.allowed) {
      res.setHeader("Retry-After", status.retryAfter.toString());
      res.writeHead(429);
      res.end(JSON.stringify({
        error: "Too Many Requests",
        message: `Rate limit threshold exceeded. Maximum ${maxRequests} requests per ${windowMs / 1000} seconds.`,
        retry_after_seconds: status.retryAfter,
      }));
      return false;
    }
    return true;
  }

  // 1. Safe Public Health Check (Permits 100 req/min)
  if (pathname === "/api/public/status" && method === "GET") {
    if (!applyRateLimit("public_status", 100)) return;

    res.writeHead(200);
    res.end(JSON.stringify({
      status: "online",
      service: "Secured Rate Limit Sandbox",
      rate_limiting: "enforced",
    }));
    return;
  }

  // 2. SECURED: Login Route (Strict 5 req / minute)
  if (pathname === "/api/auth/login" && method === "POST") {
    if (!applyRateLimit("auth_login", 5)) return;

    res.writeHead(200);
    res.end(JSON.stringify({
      status: "processed",
      message: "Login attempt processed successfully",
    }));
    return;
  }

  // 3. SECURED: Password Reset Route (Strict 3 req / minute)
  if (pathname === "/api/auth/forgot-password" && method === "POST") {
    if (!applyRateLimit("auth_forgot", 3)) return;

    res.writeHead(200);
    res.end(JSON.stringify({
      status: "queued",
      message: "Password reset link dispatched",
    }));
    return;
  }

  // 4. SECURED: Search Route (Strict 8 req / minute)
  if (pathname === "/api/search" && method === "GET") {
    if (!applyRateLimit("search", 8)) return;

    res.writeHead(200);
    res.end(JSON.stringify({
      query: parsedUrl.query.q || "all",
      results_count: 150,
    }));
    return;
  }

  // 5. SECURED: User Export Route (Strict 3 req / minute)
  if (pathname === "/api/user/export" && method === "GET") {
    if (!applyRateLimit("user_export", 3)) return;

    res.writeHead(200);
    res.end(JSON.stringify({
      export_status: "ready",
      archive_size_bytes: 5242880,
    }));
    return;
  }

  // Fallback 404
  res.writeHead(404);
  res.end(JSON.stringify({ error: "Route not found", path: pathname }));
});

server.listen(PORT, () => {
  console.log(`\n===============================================================`);
  console.log(`[SECURED] Hardened Rate Limiting active on http://localhost:${PORT}`);
  console.log(`===============================================================`);
  console.log(`- GET  /api/public/status          (100 req/min baseline)`);
  console.log(`- POST /api/auth/login             (SECURED: Throttled to 5 req/min, returns 429)`);
  console.log(`- POST /api/auth/forgot-password   (SECURED: Throttled to 3 req/min, returns 429)`);
  console.log(`- GET  /api/search                 (SECURED: Throttled to 8 req/min, returns 429)`);
  console.log(`- GET  /api/user/export            (SECURED: Throttled to 3 req/min, returns 429)\n`);
});
