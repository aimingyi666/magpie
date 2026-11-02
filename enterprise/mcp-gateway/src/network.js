import dns from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import net from "node:net";

export class NetworkPolicyError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "NetworkPolicyError";
    this.code = code;
  }
}

function hostAllowed(hostname, allowlist) {
  const host = hostname.toLowerCase();
  return allowlist.some((entry) => {
    const allowed = entry.toLowerCase();
    if (allowed.startsWith("*.")) {
      const suffix = allowed.slice(1);
      return host.endsWith(suffix) && host.length > suffix.length;
    }
    return host === allowed;
  });
}

function ipv4Parts(address) {
  if (net.isIP(address) !== 4) return null;
  return address.split(".").map(Number);
}

function inIpv4Range(parts, network, prefix) {
  const address = (((parts[0] << 24) >>> 0)
    + (parts[1] << 16)
    + (parts[2] << 8)
    + parts[3]) >>> 0;
  const baseParts = [...network, 0, 0, 0].slice(0, 4);
  const base = (((baseParts[0] << 24) >>> 0)
    + (baseParts[1] << 16)
    + (baseParts[2] << 8)
    + baseParts[3]) >>> 0;
  const size = 2 ** (32 - prefix);
  return address >= base && address < base + size;
}

function expandIpv6(address) {
  let value = address.toLowerCase().split("%")[0];
  if (value.startsWith("::ffff:")) {
    const mapped = value.slice("::ffff:".length);
    if (net.isIP(mapped) === 4) return { mapped };
  }
  const halves = value.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if (missing < 0) return null;
  const words = [...left, ...Array(missing).fill("0"), ...right];
  if (words.length !== 8 || words.some((word) => !/^[0-9a-f]{1,4}$/.test(word))) {
    return null;
  }
  return { words: words.map((word) => Number.parseInt(word, 16)) };
}

function ipv4FromWords(high, low) {
  return `${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}`;
}

function ipv4FromPair(words, offset) {
  return ipv4FromWords(words[offset], words[offset + 1]);
}

export function isUnsafeAddress(address) {
  const family = net.isIP(address);
  if (family === 4) {
    const parts = ipv4Parts(address);
    return inIpv4Range(parts, [0], 8)
      || inIpv4Range(parts, [10], 8)
      || inIpv4Range(parts, [100, 64], 10)
      || inIpv4Range(parts, [127], 8)
      || inIpv4Range(parts, [169, 254], 16)
      || inIpv4Range(parts, [172, 16], 12)
      || inIpv4Range(parts, [192, 0, 0], 24)
      || inIpv4Range(parts, [192, 0, 2], 24)
      || inIpv4Range(parts, [192, 168], 16)
      || inIpv4Range(parts, [198, 18], 15)
      || inIpv4Range(parts, [198, 51, 100], 24)
      || inIpv4Range(parts, [203, 0, 113], 24)
      || inIpv4Range(parts, [224], 4)
      || inIpv4Range(parts, [240], 4);
  }
  if (family === 6) {
    const parsed = expandIpv6(address);
    if (!parsed) return true;
    if (parsed.mapped) return isUnsafeAddress(parsed.mapped);
    const words = parsed.words;
    const [first, second] = words;
    const allZero = words.every((word) => word === 0);
    if (allZero || (words.slice(0, 7).every((word) => word === 0)
        && words[7] === 1)) {
      return true;
    }
    // IPv4-mapped and IPv4-compatible addresses can otherwise carry a private
    // IPv4 destination through an IPv6 parser and bypass the private-range test.
    if (words.slice(0, 5).every((word) => word === 0) && words[5] === 0xffff) {
      return isUnsafeAddress(ipv4FromPair(words, 6));
    }
    if (words.slice(0, 6).every((word) => word === 0)) {
      return isUnsafeAddress(ipv4FromPair(words, 6));
    }
    if (words.slice(0, 4).every((word) => word === 0)
        && words[4] === 0xffff
        && words[5] === 0) {
      return isUnsafeAddress(ipv4FromPair(words, 6));
    }
    // Well-known NAT64 and local-use NAT64 can translate an embedded private
    // IPv4 destination. 6to4 and ISATAP similarly carry an IPv4 address.
    if (first === 0x0064 && second === 0xff9b && words.slice(2, 6).every((word) => word === 0)) {
      return isUnsafeAddress(ipv4FromPair(words, 6));
    }
    if (first === 0x0064 && second === 0xff9b && words[2] === 0x0001) {
      return true;
    }
    if (first === 0x2002) {
      return isUnsafeAddress(ipv4FromPair(words, 1));
    }
    if (words[4] === 0 && words[5] === 0x5efe) {
      return isUnsafeAddress(ipv4FromPair(words, 6));
    }
    if ((first & 0xfe00) === 0xfc00) return true;
    if ((first & 0xffc0) === 0xfe80) return true;
    if ((first & 0xff00) === 0xff00) return true;
    if (first === 0x0100 && words.slice(1, 4).every((word) => word === 0)) return true;
    if (first === 0x2001 && second === 0x0000) return true;
    if (first === 0x2001 && second === 0x0002) return true;
    if (first === 0x2001 && second === 0x0db8) return true;
    if (first === 0x2001 && [0x0010, 0x0020].includes(second & 0xfff0)) return true;
    if (first === 0x3fff && (second & 0xf000) === 0) return true;
    if (first === 0x5f00) return true;
  }
  return true;
}

export function validateUpstreamUrl(value, config) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new NetworkPolicyError("invalid_upstream_url", "The upstream URL is invalid");
  }
  if (!["http:", "https:"].includes(parsed.protocol)
      || (parsed.protocol === "http:" && !config.allowHttpUpstreams)) {
    throw new NetworkPolicyError(
      "insecure_upstream_url",
      "The upstream URL must use HTTPS unless HTTP is explicitly enabled",
    );
  }
  if (parsed.username
      || parsed.password
      || parsed.hash
      || parsed.hostname.length === 0
      || parsed.hostname.length > 253) {
    throw new NetworkPolicyError("invalid_upstream_url", "The upstream URL is unsafe");
  }
  if (!config.upstreamAllowedHosts.length) {
    throw new NetworkPolicyError(
      "upstream_host_not_allowed",
      "No upstream host allowlist is configured",
    );
  }
  if (!hostAllowed(parsed.hostname, config.upstreamAllowedHosts)) {
    throw new NetworkPolicyError(
      "upstream_host_not_allowed",
      "The upstream host is not allowed",
    );
  }
  return parsed;
}

async function resolveAddresses(hostname, resolver) {
  if (net.isIP(hostname)) {
    return [{ address: hostname, family: net.isIP(hostname) }];
  }
  try {
    const result = resolver ? await resolver(hostname) : await dns.lookup(hostname, {
      all: true,
      verbatim: true,
    });
    const records = Array.isArray(result) ? result : [result];
    const addresses = records.map((entry) => {
      const address = typeof entry === "string" ? entry : entry?.address;
      const family = typeof entry === "string" ? net.isIP(entry) : entry?.family;
      return { address, family: family || net.isIP(address) };
    });
    if (!addresses.length || addresses.some((entry) => !net.isIP(entry.address))) {
      throw new Error("empty result");
    }
    return addresses;
  } catch {
    throw new NetworkPolicyError("upstream_dns_failed", "The upstream host did not resolve");
  }
}

function errorWithCode(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

export async function safeRequest(urlValue, options) {
  const {
    config,
    resolver,
    method = "POST",
    headers = {},
    body = "",
    timeoutMs = config.upstreamTimeoutMs,
    maxResponseBytes = config.upstreamMaxResponseBytes,
  } = options;
  const parsed = validateUpstreamUrl(urlValue, config);
  const addresses = await resolveAddresses(parsed.hostname, resolver);
  if (!config.allowPrivateUpstreams
      && addresses.some((entry) => isUnsafeAddress(entry.address))) {
    throw new NetworkPolicyError(
      "unsafe_upstream_address",
      "The upstream host resolves to a non-public address",
    );
  }
  const pinned = addresses[0];
  const transport = parsed.protocol === "https:" ? https : http;
  const payload = Buffer.isBuffer(body) ? body : Buffer.from(String(body), "utf8");
  const requestHeaders = {
    accept: "application/json, text/event-stream",
    "user-agent": "magpie-enterprise-mcp-gateway/0.1",
    ...headers,
    "content-length": String(payload.length),
  };

  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      if (error) reject(error);
      else resolve(value);
    };
    const request = transport.request({
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
      path: `${parsed.pathname}${parsed.search}`,
      method,
      headers: requestHeaders,
      rejectUnauthorized: true,
      agent: false,
      ...(config.upstreamCa ? { ca: config.upstreamCa } : {}),
      lookup: (_hostname, _options, callback) => {
        callback(null, pinned.address, pinned.family);
      },
    }, (response) => {
      if (response.statusCode >= 300 && response.statusCode < 400) {
        response.resume();
        finish(new NetworkPolicyError(
          "upstream_redirect_refused",
          "Upstream redirects are not followed",
        ));
        return;
      }
      const chunks = [];
      let total = 0;
      response.on("data", (chunk) => {
        total += chunk.length;
        if (total > maxResponseBytes) {
          response.destroy();
          finish(new NetworkPolicyError(
            "upstream_response_too_large",
            "The upstream response exceeded the configured limit",
          ));
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => {
        if (settled) return;
        finish(null, {
          statusCode: response.statusCode,
          headers: response.headers,
          body: Buffer.concat(chunks),
        });
      });
      response.on("error", (error) => {
        finish(errorWithCode(
          "The upstream response failed",
          error.code || "upstream_response_failed",
        ));
      });
    });
    request.setTimeout(timeoutMs, () => {
      request.destroy(errorWithCode("The upstream request timed out", "upstream_timeout"));
    });
    request.on("error", (error) => {
      finish(error.code === "upstream_timeout"
        ? error
        : errorWithCode("The upstream request failed", error.code || "upstream_request_failed"));
    });
    request.end(payload);
  });
}
