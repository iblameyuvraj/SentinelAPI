/**
 * Intentionally Vulnerable Backend - BOLA / IDOR Flaw
 * 
 * Port: 8000
 * Vulnerability:
 *   GET /users/:userId/orders validates authentication (Bearer token exists),
 *   but FAILS to verify if token identity matches requested userId.
 *   User A (101) can view User B (102)'s private orders.
 */
const http = require("http");
const url = require("url");

const PORT = process.env.PORT || 8000;

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

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
  });
  res.end(JSON.stringify(data, null, 2));
}

const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const path = parsedUrl.pathname;
  const authHeader = req.headers["authorization"] || "";

  // Helper authentication check
  const isAuthenticated = authHeader.startsWith("Bearer ");

  // 1. Root info
  if (path === "/" || path === "/health") {
    return sendJson(res, 200, {
      status: "online",
      target: "Vulnerable BOLA Backend",
      auth_required: true,
    });
  }

  // Auth Guard
  if (!isAuthenticated) {
    return sendJson(res, 401, {
      error: "Unauthorized",
      message: "Missing or invalid Bearer authorization header",
    });
  }

  // 2. Profile endpoint: GET /users/:userId
  const userMatch = path.match(/^\/users\/(\d+)$/);
  if (userMatch && req.method === "GET") {
    const userId = parseInt(userMatch[1], 10);
    const user = USERS[userId];
    if (!user) return sendJson(res, 404, { error: "User not found" });
    return sendJson(res, 200, user);
  }

  // 3. Vulnerable Orders endpoint: GET /users/:userId/orders (BOLA / IDOR)
  // BUG: Server does NOT check if the caller owns userId!
  const ordersMatch = path.match(/^\/users\/(\d+)\/orders$/);
  if (ordersMatch && req.method === "GET") {
    const userId = parseInt(ordersMatch[1], 10);
    const userOrders = ORDERS.filter((o) => o.userId === userId);
    return sendJson(res, 200, {
      userId: userId,
      count: userOrders.length,
      orders: userOrders,
    });
  }

  // 4. Order endpoint: GET /orders/:orderId
  const singleOrderMatch = path.match(/^\/orders\/(\d+)$/);
  if (singleOrderMatch && req.method === "GET") {
    const orderId = parseInt(singleOrderMatch[1], 10);
    const order = ORDERS.find((o) => o.id === orderId);
    if (!order) return sendJson(res, 404, { error: "Order not found" });
    return sendJson(res, 200, order);
  }

  sendJson(res, 404, { error: "Route not found" });
});

server.listen(PORT, () => {
  console.log(`[Vulnerable Backend] Server running at http://localhost:${PORT}`);
});
