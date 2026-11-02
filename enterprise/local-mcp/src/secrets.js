import { LocalMcpError } from "./errors.js";

export const DEFAULT_SECRET_TIMEOUT_MS = 5_000;
export const DEFAULT_MAX_SECRET_BYTES = 64 * 1024;
const MAX_SECRET_RESPONSE_BYTES = 128 * 1024;

function loopbackHost(hostname) {
  return hostname === "127.0.0.1" || hostname === "::1" || hostname === "localhost";
}

export function createEnterpriseSecretBroker({
  endpoint,
  tokenProvider,
  fetchImpl = globalThis.fetch,
  timeoutMs = DEFAULT_SECRET_TIMEOUT_MS,
  maxSecretBytes = DEFAULT_MAX_SECRET_BYTES,
  allowLoopbackHttp = false,
} = {}) {
  let url;
  try {
    url = new URL(endpoint);
  } catch {
    throw new LocalMcpError("invalid_config", "secret broker endpoint is invalid");
  }
  if (url.username
      || url.password
      || url.hash
      || (url.protocol !== "https:" && !(allowLoopbackHttp && url.protocol === "http:" && loopbackHost(url.hostname)))) {
    throw new LocalMcpError("invalid_config", "secret broker endpoint must use HTTPS");
  }
  if (typeof tokenProvider !== "function" || typeof fetchImpl !== "function") {
    throw new LocalMcpError("invalid_config", "secret broker transport is misconfigured");
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30_000) {
    throw new LocalMcpError("invalid_config", "secret broker timeout is invalid");
  }
  if (!Number.isSafeInteger(maxSecretBytes) || maxSecretBytes < 1 || maxSecretBytes > DEFAULT_MAX_SECRET_BYTES) {
    throw new LocalMcpError("invalid_config", "secret broker size limit is invalid");
  }

  return {
    async resolve(context, signal) {
      let token;
      try {
        token = await tokenProvider();
      } catch {
        throw new LocalMcpError("secret_unavailable", "secret broker token is unavailable");
      }
      if (typeof token !== "string" || !token) {
        throw new LocalMcpError("secret_unavailable", "secret broker token is unavailable");
      }
      const timeoutSignal = AbortSignal.timeout(timeoutMs);
      const combinedSignal = signal
        ? AbortSignal.any([signal, timeoutSignal])
        : timeoutSignal;
      let response;
      try {
        response = await fetchImpl(url, {
          method: "POST",
          redirect: "error",
          signal: combinedSignal,
          headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json",
            accept: "application/json",
          },
          body: JSON.stringify({
            reference: context.reference,
            packageId: context.packageId,
            releaseId: context.releaseId,
            toolName: context.toolName,
          }),
        });
      } catch {
        throw new LocalMcpError("secret_unavailable", "secret broker request failed");
      }
      if (!response.ok
          || !String(response.headers.get("content-type") || "").toLowerCase().startsWith("application/json")) {
        throw new LocalMcpError("secret_unavailable", "secret broker rejected the request");
      }
      const declaredLength = Number(response.headers.get("content-length"));
      if (Number.isFinite(declaredLength) && declaredLength > MAX_SECRET_RESPONSE_BYTES) {
        throw new LocalMcpError("secret_unavailable", "secret broker response is too large");
      }
      let bytes;
      try {
        bytes = Buffer.from(await response.arrayBuffer());
      } catch {
        throw new LocalMcpError("secret_unavailable", "secret broker response could not be read");
      }
      if (bytes.length > MAX_SECRET_RESPONSE_BYTES) {
        throw new LocalMcpError("secret_unavailable", "secret broker response is too large");
      }
      let body;
      try {
        body = JSON.parse(bytes.toString("utf8"));
      } catch {
        throw new LocalMcpError("secret_unavailable", "secret broker response is invalid");
      }
      if (!body || typeof body !== "object" || Array.isArray(body)
          || typeof body.value !== "string"
          || !body.value
          || Buffer.byteLength(body.value, "utf8") > maxSecretBytes
          || typeof body.leaseId !== "string"
          || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(body.leaseId)
          || typeof body.expiresAt !== "string"
          || Number.isNaN(Date.parse(body.expiresAt))) {
        throw new LocalMcpError("secret_unavailable", "secret broker response is invalid");
      }
      return {
        value: body.value,
        leaseId: body.leaseId,
        expiresAt: new Date(body.expiresAt).toISOString(),
      };
    },
  };
}
