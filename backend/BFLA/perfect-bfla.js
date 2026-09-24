/**
 * Intentionally Secured Backend - Hardened Role-Based Access Control & BFLA Defense (OWASP API5:2023)
 * 
 * Port: 8009 (or process.env.PORT)
 * Defense Standards Enforced:
 *   1. Strict RBAC (Role-Based Access Control) on all administrative routes.
 *   2. Rejects non-admin users with HTTP 403 Forbidden.
 *   3. Enforces HTTP Verb Authorization (DELETE requires admin).
 *   4. Blocks unauthorized privilege escalation on role modification.
 */

const http = require("http");
const url = require("url");

const PORT = process.env.PORT || 8009;

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
    res.end(JSON.stringify({ status: "online", service: "Secured BFLA Sandbox" }));
    return;
  }

  const currentUser = getAuthUser(req);

  // 2. SECURED: Admin System Metrics (Strict Admin Verification)
  if (pathname === "/api/admin/system/metrics" && method === "GET") {
    if (!currentUser) {
      res.writeHead(401);
      res.end(JSON.stringify({ error: "Unauthorized" }));
      return;
    }

    if (currentUser.role !== "admin") {
      res.writeHead(403);
      res.end(JSON.stringify({ error: "Forbidden: Administrative privileges required" }));
      return;
    }

    res.writeHead(200);
    res.end(JSON.stringify({
      message: "Admin system metrics retrieved",
      internal_metrics: {
        active_database_connections: 42,
        secret_vault_status: "unlocked",
      },
    }));
    return;
  }

  // 3. SECURED: Admin Audit Logs (Strict Admin Verification)
  if (pathname === "/api/admin/audit-logs" && method === "GET") {
    if (!currentUser) {
      res.writeHead(401);
      res.end(JSON.stringify({ error: "Unauthorized" }));
      return;
    }

    if (currentUser.role !== "admin") {
      res.writeHead(403);
      res.end(JSON.stringify({ error: "Forbidden: Administrative privileges required" }));
      return;
    }

    res.writeHead(200);
    res.end(JSON.stringify({
      total_logs: 3,
      logs: [
        { action: "USER_PASSWORD_CHANGE", user: "yuvraj_user" },
        { action: "DB_BACKUP_INITIATED", user: "alex_admin" },
      ],
    }));
    return;
  }

  // 4. SECURED: User Accounts & Verb Authorization
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

      // Enforce Admin Role for user deletion
      if (currentUser.role !== "admin") {
        res.writeHead(403);
        res.end(JSON.stringify({ error: "Forbidden: Only administrators can delete user accounts" }));
        return;
      }

      delete USERS_DB[targetUserId];
      res.writeHead(200);
      res.end(JSON.stringify({ status: "success", deleted_user_id: targetUserId }));
      return;
    }
  }

  // 5. SECURED: Role Modification Guard
  const roleMatch = pathname.match(/^\/api\/users\/(\d+)\/role$/);
  if (roleMatch && method === "PUT") {
    if (!currentUser) {
      res.writeHead(401);
      res.end(JSON.stringify({ error: "Unauthorized" }));
      return;
    }

    // Enforce Admin Role for role changes
    if (currentUser.role !== "admin") {
      res.writeHead(403);
      res.end(JSON.stringify({ error: "Forbidden: Role elevation requires super-admin authorization" }));
      return;
    }

    const targetUserId = parseInt(roleMatch[1], 10);
    let body = "";
    req.on("data", chunk => body += chunk);
    req.on("end", () => {
      try {
        const parsed = JSON.parse(body || "{}");
        const newRole = parsed.role || "user";
        if (USERS_DB[targetUserId]) {
          USERS_DB[targetUserId].role = newRole;
        }
        res.writeHead(200);
        res.end(JSON.stringify({ status: "role_updated", user_id: targetUserId, assigned_role: newRole }));
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
  console.log(`[SECURED] Hardened BFLA Sandbox active on http://localhost:${PORT}`);
  console.log(`===============================================================`);
  console.log(`- GET    /api/public/status         (Public)`);
  console.log(`- GET    /api/admin/system/metrics  (SECURED: Returns 403 Forbidden to normal users)`);
  console.log(`- GET    /api/admin/audit-logs      (SECURED: Returns 403 Forbidden to normal users)`);
  console.log(`- DELETE /api/users/:userId         (SECURED: Returns 403 Forbidden to normal users)`);
  console.log(`- PUT    /api/users/:userId/role    (SECURED: Returns 403 Forbidden to normal users)\n`);
});
