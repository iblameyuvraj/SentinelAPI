/**
 * Properly Secured Backend - BOLA / IDOR Protected
 * 
 * Port: 8001 (or process.env.PORT)
 * Security Controls (OWASP API1:2023 compliant):
 *   1. Identity Extraction: Resolves caller identity from token.
 *   2. Object-Level Access Control: Validates that caller identity matches requested resource owner.
 *   3. Enforces 403 Forbidden on cross-account object inspection.
 */
const http = require("http");
const url = require("url");

const PORT = process.env.PORT || 8001;

// Mock database
const USERS = {
  101: { id: 101, name: "Yuvraj", email: "yuvraj@example.com" },
  102: { id: 102, name: "Rahul", email: "rahul@example.com" },
};

const ORDERS = [
  { id: 501, userId: 101, item: "MacBook Pro", amount: 2400 },
  { id: 502, userId: 101, item: "Mechanical Keyboard", amount: 150 },
  { id: 503, userId: 102, item: "4K Monitor", amount: 650 },
];

// Helper: Extract authenticated user from token
// Supports tokens like "Bearer token-101", "Bearer user-101", or "Bearer 101"
function getAuthenticatedUser(authHeader) {
  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;
  const token = authHeader.replace("Bearer ", "").trim();
  
  // Extract user id from token
  const match = token.match(/(\d+)/);
  if (!match) return null;
  const uid = parseInt(match[1], 10);
  return USERS[uid] || null;
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

  // 1. Health / Discovery
  if (path === "/" || path === "/health") {
    return sendJson(res, 200, {
      status: "online",
      target: "Secured BOLA-Protected Backend",
      auth_scheme: "Bearer JWT / Token",
      protection: "Strict Object-Level Authorization enforced",
    });
  }

  // 2. Authentication Check
  const currentUser = getAuthenticatedUser(authHeader);
  if (!currentUser) {
    return sendJson(res, 401, {
      error: "Unauthorized",
      message: "Valid Bearer token with identified user required (e.g., Bearer token-101)",
    });
  }

  // 3. Secured Profile endpoint: GET /users/:userId
  const userMatch = path.match(/^\/users\/(\d+)$/);
  if (userMatch && req.method === "GET") {
    const requestedUserId = parseInt(userMatch[1], 10);

    // BOLA Check: Only allowed to view own profile (or admin)
    if (currentUser.id !== requestedUserId) {
      return sendJson(res, 403, {
        error: "Forbidden",
        code: "BOLA_PREVENTED",
        message: `Access denied: Authenticated user (${currentUser.id}) cannot access profile of user (${requestedUserId}).`,
      });
    }

    return sendJson(res, 200, currentUser);
  }

  // 4. Secured Orders endpoint: GET /users/:userId/orders
  const ordersMatch = path.match(/^\/users\/(\d+)\/orders$/);
  if (ordersMatch && req.method === "GET") {
    const requestedUserId = parseInt(ordersMatch[1], 10);

    // BOLA Check: Strictly check resource ownership
    if (currentUser.id !== requestedUserId) {
      return sendJson(res, 403, {
        error: "Forbidden",
        code: "BOLA_PREVENTED",
        message: `Access denied: Object-level authorization failed. You do not own userId (${requestedUserId}).`,
      });
    }

    const userOrders = ORDERS.filter((o) => o.userId === requestedUserId);
    return sendJson(res, 200, {
      userId: requestedUserId,
      count: userOrders.length,
      orders: userOrders,
    });
  }

  // 5. Secured Single Order endpoint: GET /orders/:orderId
  const singleOrderMatch = path.match(/^\/orders\/(\d+)$/);
  if (singleOrderMatch && req.method === "GET") {
    const orderId = parseInt(singleOrderMatch[1], 10);
    const order = ORDERS.find((o) => o.id === orderId);

    if (!order) {
      return sendJson(res, 404, { error: "Order not found" });
    }

    // BOLA Check: Verify order belongs to caller
    if (order.userId !== currentUser.id) {
      return sendJson(res, 403, {
        error: "Forbidden",
        code: "BOLA_PREVENTED",
        message: `Access denied: Order ${orderId} does not belong to authenticated user ${currentUser.id}.`,
      });
    }

    return sendJson(res, 200, order);
  }

  sendJson(res, 404, { error: "Route not found" });
});

server.listen(PORT, () => {
  console.log(`[Secured Backend] Server running at http://localhost:${PORT}`);
});
