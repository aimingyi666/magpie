/**
 * Employee Portal - HTTP helpers
 */

export class PortalError extends Error {
  constructor(message = "portal error", options = {}) {
    super(message);
    this.name = "PortalError";
    this.statusCode = options.statusCode || 400;
    this.code = options.code || "portal_error";
  }
}

export async function readBody(req) {
  let data = "";
  for await (const chunk of req) {
    data += chunk;
  }
  if (!data) return {};
  try {
    return JSON.parse(data);
  } catch {
    throw new PortalError("Invalid JSON in request body", { statusCode: 400, code: "invalid_json" });
  }
}

export function ensureAuth(req) {
  const userId = (req.headers["x-user-id"] || "").trim();
  if (!userId) {
    throw new PortalError("x-user-id header required", { statusCode: 401, code: "unauthorized" });
  }
  return userId;
}

export function respond(res, body, status = 200) {
  res.writeHead(status, {
    "content-type": "application/json",
    "cache-control": "no-store",
  });
  res.end(JSON.stringify(body));
}
