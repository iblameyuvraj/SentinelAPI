/**
 * Intentionally Vulnerable Backend - Broken Function Level Authorization (OWASP API5:2023)
 * 
 * Port: 8008 (or process.env.PORT)
 * Vulnerabilities Demonstrated:
 *   1. User-to-Admin Privilege Escalation: Normal user can access /api/admin/system/metrics without admin role.
 *   2. HTTP Verb Tampering: Normal user can send DELETE /api/users/:userId and delete accounts.
 *   3. Role Tampering: Normal user can elevate their role to "admin" via PUT /api/users/:userId/role.
 *   4. Sensitive Export Access: Normal user can download organization audit logs via GET /api/admin/audit-logs.
 */

const http = require("http");
const url = require("url");

const PORT = process.env.PORT || 8008;

// Mock database
const USERS_DB = {
  101: { id: 101, username: "yuvraj_user", role: "user", email: "yuvraj@test.com" },
  102: { id: 102, username: "alex_admin", role: "admin", email: "alex@sentinel.internal" },
  103: { id: 103, username: "target_victim", role: "user", email: "victim@example.com" },
};

// Mock Session Tokens
const SESSIONS = {
  "user_token_101": { id: 101, username: "yuvraj_user", role: "user" },
  "admin_token_102": { id: 102, username: "alex_admin", role: "admin" },
};

function getAuthUser(req) {
  const authHeader = req.headers["authorization"] || "";
  const token = authHeader.replace(/^Bearer\s+/i, "").trim();
  if (!token) return null;
  if (SESSIONS[token]) return SESSIONS[token];
  if (token.toLowerCase().includes("admin")) {
    return { id: 102, username: "alex_admin", role: "admin" };
  }
  // Any provided bearer token is accepted as an authenticated regular user (role: 'user')
  return { id: 101, username: "yuvraj_user", role: "user" };
}

const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  const method = req.method;

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
    res.end(JSON.stringify({ status: "online", service: "Vulnerable BFLA Sandbox" }));
    return;
  }

  const currentUser = getAuthUser(req);

  // 2. VULNERABLE: Admin System Metrics (Missing Role Verification)
  // Only verifies user is logged in, DOES NOT verify currentUser.role === 'admin'!
  if (pathname === "/api/admin/system/metrics" && method === "GET") {
    if (!currentUser) {
      res.writeHead(401);
      res.end(JSON.stringify({ error: "Unauthorized: Please log in" }));
      return;
    }

    res.writeHead(200);
    res.end(JSON.stringify({
      message: "Admin system metrics retrieved",
      caller_user: currentUser.username,
      caller_role: currentUser.role,
      warning: "VULNERABILITY DETECTED: Regular user with role 'user' accessed administrative metrics!",
      internal_metrics: {
        active_database_connections: 42,
        secret_vault_status: "unlocked",
        encryption_key_rotation: "2026-10-01",
      },
    }));
    return;
  }

  // 3. VULNERABLE: Admin Audit Logs (Privilege Escalation)
  if (pathname === "/api/admin/audit-logs" && method === "GET") {
    if (!currentUser) {
      res.writeHead(401);
      res.end(JSON.stringify({ error: "Unauthorized: Please log in" }));
      return;
    }

    res.writeHead(200);
    res.end(JSON.stringify({
      total_logs: 3,
      warning: "VULNERABILITY DETECTED: Audit logs exposed to non-admin user!",
      logs: [
        { action: "USER_PASSWORD_CHANGE", user: "yuvraj_user", ip: "192.168.1.5" },
        { action: "DB_BACKUP_INITIATED", user: "alex_admin", ip: "10.0.0.1" },
        { action: "API_SECRET_ROTATED", user: "alex_admin", ip: "10.0.0.1" }
      ],
    }));
    return;
  }

  // 4. VULNERABLE: HTTP Verb Tampering on User Accounts
  // GET is safe, but DELETE allows any logged-in normal user to delete another user!
  const userMatch = pathname.match(/^\/api\/users\/(\d+)$/);
  if (userMatch) {
    const targetUserId = parseInt(userMatch[1], 10);

    if (method === "GET") {
      const user = USERS_DB[targetUserId];
      if (!user) {
        res.writeHead(404);
        res.end(JSON.stringify({ error: "User not found" }));
        return;
      }
      res.writeHead(200);
      res.end(JSON.stringify({ id: user.id, username: user.username, role: user.role }));
      return;
    }

    if (method === "DELETE") {
      if (!currentUser) {
        res.writeHead(401);
        res.end(JSON.stringify({ error: "Unauthorized" }));
        return;
      }

      // VULNERABILITY: Missing admin check! Regular user deletes any user!
      delete USERS_DB[targetUserId];
      res.writeHead(200);
      res.end(JSON.stringify({
        status: "success",
        deleted_user_id: targetUserId,
        executed_by: currentUser.username,
        executed_role: currentUser.role,
        warning: "VULNERABILITY DETECTED: Regular user executed DELETE operation without admin privileges (Verb Tampering)!",
      }));
      return;
    }
  }

  // 5. VULNERABLE: Self-Role Elevation
  const roleMatch = pathname.match(/^\/api\/users\/(\d+)\/role$/);
  if (roleMatch && method === "PUT") {
    if (!currentUser) {
      res.writeHead(401);
      res.end(JSON.stringify({ error: "Unauthorized" }));
      return;
    }

    const targetUserId = parseInt(roleMatch[1], 10);
    let body = "";
    req.on("data", chunk => body += chunk);
    req.on("end", () => {
      try {
        const parsed = JSON.parse(body || "{}");
        const newRole = parsed.role || "admin";

        // VULNERABILITY: User elevates themselves or others to 'admin'
        if (USERS_DB[targetUserId]) {
          USERS_DB[targetUserId].role = newRole;
        }

        res.writeHead(200);
        res.end(JSON.stringify({
          status: "role_updated",
          user_id: targetUserId,
          assigned_role: newRole,
          warning: "VULNERABILITY DETECTED: Standard user promoted account to 'admin' without authorization check!",
        }));
      } catch (e) {
        res.writeHead(400);
        res.end(JSON.stringify({ error: "Malformed JSON" }));
      }
    });
    return;
  }

  // Fallback 404
  res.writeHead(404);
  res.end(JSON.stringify({ error: "Route not found", path: pathname }));
});

server.listen(PORT, () => {
  console.log(`\n===============================================================`);
  console.log(`[VULNERABLE] BFLA Sandbox active on http://localhost:${PORT}`);
  console.log(`===============================================================`);
  console.log(`- GET    /api/public/status         (Safe baseline)`);
  console.log(`- GET    /api/admin/system/metrics  (CRITICAL: Regular user can access admin metrics)`);
  console.log(`- GET    /api/admin/audit-logs      (HIGH: Regular user can access audit trails)`);
  console.log(`- DELETE /api/users/:userId         (CRITICAL: Verb tampering allows user deletion)`);
  console.log(`- PUT    /api/users/:userId/role    (CRITICAL: Self-privilege escalation to admin)\n`);
  console.log(`Pre-Configured Test Tokens:`);
  console.log(`Normal User Token: Bearer user_token_101`);
  console.log(`Admin User Token:  Bearer admin_token_102\n`);
});
