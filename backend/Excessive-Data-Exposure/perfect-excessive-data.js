/**
 * Properly Secured Backend - Excessive Data Exposure Mitigated (OWASP API3:2023 Compliant)
 * 
 * Port: 8003 (or process.env.PORT)
 * Security Controls:
 *   1. Explicit Response DTO Projections: Whitelist only fields authorized for client consumption.
 *   2. Strict Object Sanitization: Never serialize full database ORM entities to JSON.
 *   3. Sensitive Data Masking: Hide PII, hashes, secrets, and internal architecture identifiers.
 */
const http = require("http");
const url = require("url");

const PORT = process.env.PORT || 8003;

// Mock database containing sensitive internal fields
const USERS_DB = {
  101: {
    id: 101,
    name: "Yuvraj",
    username: "yuvraj_dev",
    email: "yuvraj@example.com",
    phone: "+91-9876543210",
    password_hash: "$2b$12$e8Y5M6v8r4oP9xLz.K8e9uQeWJ1eC6sV1l.d6r7t8y9u0",
    password_salt: "d41d8cd98f00b204e9800998ecf8427e",
    reset_token: "9f83a45c-20c1-4b72-b5e1-8974a682cd12",
    internal_role: "super_admin",
    is_admin: true,
    permissions: ["user.read", "user.write", "admin.override", "billing.bypass"],
    ssn: "987-65-4321",
    salary: 185000,
    credit_card_last4: "4242",
    stripe_customer_id: "cus_Nb89sL29xK0pQq",
    failed_login_attempts: 0,
    mfa_secret: "JBSWY3DPEHPK3PXP",
    deleted_at: null,
  },
  102: {
    id: 102,
    name: "Aman Gupta",
    username: "aman_g",
    email: "aman@example.com",
    phone: "+91-9123456780",
    password_hash: "$2b$12$K1m9x8v7r6oP5xLz.U4e3uQeWJ1eC6sV9l.a1b2c3d4e5",
    password_salt: "a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3",
    reset_token: null,
    internal_role: "finance_auditor",
    is_admin: false,
    permissions: ["finance.read"],
    ssn: "123-45-6789",
    salary: 95000,
    credit_card_last4: "1881",
    stripe_customer_id: "cus_J89x0pQ7sK3pLm",
    failed_login_attempts: 2,
    mfa_secret: "HXDMVJECJJWSRB3H",
    deleted_at: null,
  },
};

const PRODUCTS_DB = {
  501: {
    id: 501,
    title: "Cloud Microservices Security Scanner",
    description: "Enterprise zero-trust API scanning suite.",
    retail_price: 299,
    supplier_cost: 45,
    wholesale_vendor_token: "wh_live_sec_8930491823749817293847",
    markup_margin_percentage: 564.4,
    internal_inventory_warehouse_id: "WH-EAST-09",
    debug_trace_code: "TRACE-882-SYS-INT",
  },
};

// ==========================================
// SECURE DATA PROJECTION DTOs (WHITELISTING)
// ==========================================
function toPublicUserDTO(user) {
  return {
    id: user.id,
    name: user.name,
    username: user.username,
  };
}

function toPublicProfileDTO(user) {
  return {
    id: user.id,
    name: user.name,
    username: user.username,
    email: user.email,
  };
}

function toPublicProductDTO(product) {
  return {
    id: product.id,
    title: product.title,
    description: product.description,
    retail_price: product.retail_price,
  };
}

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
  });
  res.end(JSON.stringify(data, null, 2));
}

const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const path = parsedUrl.pathname;
  const authHeader = req.headers["authorization"] || "";

  // Helper check
  const isAuthenticated = authHeader.startsWith("Bearer ");

  // 1. Health / Baseline check
  if (path === "/" || path === "/health" || path === "/api/system/health") {
    return sendJson(res, 200, {
      status: "online",
      target: "Secured Excessive Data Exposure Backend",
      auth_required: true,
      timestamp: new Date().toISOString(),
    });
  }

  // 2. Public Product Endpoint: GET /api/products/:productId (Strict DTO applied)
  const productMatch = path.match(/^\/api\/products\/(\d+)$/);
  if (req.method === "GET" && productMatch) {
    const productId = parseInt(productMatch[1], 10);
    const product = PRODUCTS_DB[productId];
    if (!product) {
      return sendJson(res, 404, { error: "Product Not Found", code: "NOT_FOUND" });
    }
    // SECURED: Only whitelist safe public product fields
    return sendJson(res, 200, toPublicProductDTO(product));
  }

  // Protected Routes Guard
  if (!isAuthenticated) {
    return sendJson(res, 401, {
      error: "Unauthorized",
      message: "Protected resource requires a valid Bearer token in the Authorization header.",
    });
  }

  // 3. User Full Profile: GET /api/users/:userId (Strict DTO applied)
  const userMatch = path.match(/^\/api\/users\/(\d+)$/);
  if (req.method === "GET" && userMatch) {
    const userId = parseInt(userMatch[1], 10);
    const user = USERS_DB[userId];
    if (!user) {
      return sendJson(res, 404, { error: "User Not Found", code: "NOT_FOUND" });
    }
    // SECURED: Whitelisted DTO prevents leaking password_hash, ssn, role, salary
    return sendJson(res, 200, toPublicUserDTO(user));
  }

  // 4. User Profile Summary: GET /api/users/:userId/profile (Strict DTO applied)
  const profileMatch = path.match(/^\/api\/users\/(\d+)\/profile$/);
  if (req.method === "GET" && profileMatch) {
    const userId = parseInt(profileMatch[1], 10);
    const user = USERS_DB[userId];
    if (!user) {
      return sendJson(res, 404, { error: "User Not Found", code: "NOT_FOUND" });
    }
    // SECURED: Whitelisted DTO prevents leaking mfa_secret, internal_role
    return sendJson(res, 200, toPublicProfileDTO(user));
  }

  // Fallback 404
  return sendJson(res, 404, {
    error: "Not Found",
    message: `Cannot ${req.method} ${path}`,
  });
});

server.listen(PORT, () => {
  console.log(`[SECURED] Protected Excessive Data Server active on http://localhost:${PORT}`);
  console.log(`- GET /api/users/:userId          (Protected: returns only { id, name, username })`);
  console.log(`- GET /api/users/:userId/profile  (Protected: returns only { id, name, username, email })`);
  console.log(`- GET /api/products/:productId    (Public: returns only safe product DTO)`);
  console.log(`- GET /api/system/health          (Public baseline: safe)`);
});
