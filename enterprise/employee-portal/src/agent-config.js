/**
 * Employee Portal - Agent Config Module
 * One-click agent configuration via browser portal.
 */

import { generateId } from "./store.js";

export class AgentConfigError extends Error {
  constructor(message = "agent config error", options = {}) {
    super(message);
    this.name = "AgentConfigError";
    this.statusCode = options.statusCode || 400;
    this.code = options.code || "agent_config_error";
    this.retryable = options.retryable || false;
  }
}

export async function applyAgentConfig(config, store, userId, orgUnit) {
  if (!config || typeof config !== "object") {
    throw new AgentConfigError("config is required", { statusCode: 400 });
  }

  const { modelId, mcpServers, providers, envOverrides } = config;

  if (!modelId || typeof modelId !== "string" || modelId.length === 0) {
    throw new AgentConfigError("modelId is required", { statusCode: 400 });
  }

  const now = new Date().toISOString();
  const mcpList = Array.isArray(mcpServers)
    ? mcpServers.map((s) => ({ name: s.name, endpoint: s.endpoint }))
    : [];
  const providerList = Array.isArray(providers)
    ? providers.map((p) => ({ id: p.id, enabled: Boolean(p.enabled) }))
    : [];

  let agentEntry;
  await store.mutate((data) => {
    const existing = (data.agents || []).find(
      (a) => a.userId === userId && a.orgUnit === orgUnit
    );
    agentEntry = {
      id: existing ? existing.id : generateId("agent"),
      userId,
      orgUnit,
      modelId,
      mcpServers: mcpList,
      providers: providerList,
      envOverrides: envOverrides || {},
      createdAt: existing ? existing.createdAt : now,
      updatedAt: now,
      appliedBy: userId,
    };
    if (existing) {
      const idx = (data.agents || []).findIndex((a) => a.id === existing.id);
      if (idx >= 0) data.agents[idx] = agentEntry;
    } else {
      (data.agents || []).push(agentEntry);
    }
  });

  return agentEntry;
}

export async function getAgentConfig(store, userId, orgUnit) {
  const data = await store.read();
  const agents = data.agents || [];
  return agents.find((a) => a.userId === userId && a.orgUnit === orgUnit) || null;
}

export async function listAgentConfigs(store, orgUnit) {
  const data = await store.read();
  let agents = data.agents || [];
  if (orgUnit) {
    agents = agents.filter((a) => a.orgUnit === orgUnit);
  }
  return agents;
}
