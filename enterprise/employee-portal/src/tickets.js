/**
 * Employee Portal - Tickets Module
 * Ticket creation, listing, and retrieval for employees.
 */

import { generateId } from "./store.js";

export class TicketError extends Error {
  constructor(message = "ticket error", options = {}) {
    super(message);
    this.name = "TicketError";
    this.statusCode = options.statusCode || 400;
    this.code = options.code || "ticket_error";
  }
}

export const TICKET_STATUSES = Object.freeze(["open", "in_progress", "resolved", "closed"]);
export const TICKET_TYPES = Object.freeze(["bug", "feature", "question", "other"]);

function isValidTicketType(type) {
  return TICKET_TYPES.includes(type);
}

function validateTicketCreateRequest(body) {
  if (!body || typeof body !== "object") {
    throw new TicketError("request body is required", { statusCode: 400, code: "invalid_body" });
  }
  const { title, description, type, priority } = body;
  if (!title || typeof title !== "string" || title.trim().length === 0) {
    throw new TicketError("title is required and must be a non-empty string", { statusCode: 400, code: "invalid_title" });
  }
  if (typeof description !== "string") {
    throw new TicketError("description is required and must be a string", { statusCode: 400, code: "invalid_description" });
  }
  const ticketType = type || "other";
  if (!isValidTicketType(ticketType)) {
    throw new TicketError(`invalid ticket type: ${type}`, { statusCode: 400, code: "invalid_type" });
  }
  const ticketPriority = priority || "medium";
  if (!["low", "medium", "high", "critical"].includes(ticketPriority)) {
    throw new TicketError("priority must be low, medium, high, or critical", { statusCode: 400, code: "invalid_priority" });
  }
  return { title: title.trim(), description: description.trim(), type: ticketType, priority: ticketPriority };
}

export async function createTicket(body, store, userId, orgUnit) {
  const validated = validateTicketCreateRequest(body);
  const now = new Date().toISOString();
  const ticket = {
    id: generateId("ticket"),
    ...validated,
    status: "open",
    userId,
    orgUnit,
    priority: validated.priority,
    createdAt: now,
    updatedAt: now,
    createdBy: userId,
    updatedBy: userId,
  };

  await store.mutate((data) => {
    (data.tickets || []).push(ticket);
  });

  return ticket;
}

export async function listTickets(store, userId, options = {}) {
  const data = await store.read();
  let tickets = (data.tickets || []).filter((t) => t.userId === userId);
  const { status, type, limit = 50 } = options;
  if (status) {
    tickets = tickets.filter((t) => t.status === status);
  }
  if (type) {
    tickets = tickets.filter((t) => t.type === type);
  }
  tickets.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  return tickets.slice(0, Number(limit));
}

export async function getTicket(store, ticketId, userId) {
  const data = await store.read();
  const tickets = data.tickets || [];
  const ticket = tickets.find((t) => t.id === ticketId && t.userId === userId);
  return ticket || null;
}
