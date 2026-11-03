/**
 * Employee Portal - HTTP Service Layer
 * Handles all API endpoints for the portal.
 */

import { JsonStore } from "./store.js";
import { PortalError, ensureAuth, readBody, respond } from "./http.js";
import { applyAgentConfig, getAgentConfig } from "./agent-config.js";
import { getPersonalUsage } from "./usage.js";
import { createTicket, listTickets, getTicket } from "./tickets.js";

export async function createService(config) {
  const store = new JsonStore(config.storePath);

  async function handleRequest(req, res) {
    const pathname = req.url.split("?")[0];
    const method = req.method;

    const userId = ensureAuth(req);
    const orgUnit = (req.headers["x-org-unit"] || config.defaultOrgUnit || "").trim();

    try {
      let result;
      let status = 200;

      if (method === "GET" && pathname === "/api/v1/portal/config") {
        result = { ok: true, data: await getConfig(store) };
      } else if (method === "POST" && pathname === "/api/v1/portal/config/apply") {
        result = { ok: true, data: await applyConfig(req, store, userId, orgUnit) };
      } else if (method === "GET" && pathname === "/api/v1/portal/agent") {
        result = { ok: true, data: await getAgentConfig(store, userId, orgUnit) };
      } else if (method === "GET" && pathname === "/api/v1/portal/usage/personal") {
        result = { ok: true, data: await getPersonalUsage(store, userId, orgUnit) };
      } else if (method === "POST" && pathname === "/api/v1/portal/tickets") {
        result = { ok: true, data: await handleCreateTicket(req, store, userId, orgUnit) };
      } else if (method === "GET" && pathname === "/api/v1/portal/tickets") {
        result = { ok: true, data: await listTickets(store, userId) };
      } else {
        const m = pathname.match(/^\/api\/v1\/portal\/tickets\/(.+)$/);
        if (method === "GET" && m) {
          const ticket = await getTicket(store, m[1], userId);
          if (!ticket) {
            status = 404;
            result = { ok: false, error: { code: "ticket_not_found" } };
          } else {
            result = { ok: true, data: ticket };
          }
        } else {
          status = 404;
          result = { ok: false, error: { code: "route_not_found" } };
        }
      }

      return respond(res, result, status);
    } catch (err) {
      if (err instanceof PortalError) {
        return respond(res, { ok: false, error: { code: err.code, message: err.message } }, err.statusCode);
      }
      return respond(res, { ok: false, error: { code: "internal_error" } }, 500);
    }
  }

  return { handleRequest, store };
}

async function getConfig(store) {
  const data = await store.read();
  return { models: data.models || [], mcpServers: data.mcpServers || [] };
}

async function applyConfig(req, store, userId, orgUnit) {
  const body = await readBody(req);
  return applyAgentConfig(body, store, userId, orgUnit);
}

async function handleCreateTicket(req, store, userId, orgUnit) {
  const body = await readBody(req);
  return createTicket(body, store, userId, orgUnit);
}
