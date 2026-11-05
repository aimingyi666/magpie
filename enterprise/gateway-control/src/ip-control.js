/**
 * M7 - IP Control Module for Gateway Content Control
 * 
 * Provides IP whitelist/blacklist enforcement for gateway keys.
 */

const WHITELIST_ACTION = "whitelist";
const BLACKLIST_ACTION = "blacklist";
const ACTION_SET = new Set([WHITELIST_ACTION, BLACKLIST_ACTION]);
const IP_PATTERN = /^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)(\/(\d|[12]\d|3[0-2]))?$/;

export class IpControlError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

function normalizeIp(ip, name = "ip") {
  let value = String(ip || "").trim();
  if (!value) throw new IpControlError("invalid_ip", `${name} is required`);
  // Normalize IPv4-mapped IPv6 (::ffff:1.2.3.4 -> 1.2.3.4)
  const ipv4MappedMatch = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(value);
  if (ipv4MappedMatch) value = ipv4MappedMatch[1];
  const match = IP_PATTERN.exec(value);
  if (!match) throw new IpControlError("invalid_ip", `${name} is invalid: ${value}`);
  return value.toLowerCase();
}

export function parseIpRule(raw, name = "ip_rule") {
  const [ip, prefix] = String(raw || "").split("/");
  const normalizedIp = normalizeIp(ip, `${name}.ip`);
  const prefixBits = prefix == null ? 32 : Number(prefix);
  if (!Number.isInteger(prefixBits) || prefixBits < 0 || prefixBits > 32) {
    throw new IpControlError("invalid_prefix", `${name} has invalid prefix: ${prefix}`);
  }
  return { ip: normalizedIp, prefix: prefixBits };
}

export function checkIpAccess(ip, whitelist, blacklist) {
  if (!ip) return { allowed: true, reason: "" };
  
  // Normalize IPv4-mapped IPv6 before checking
  let normalizedIp = String(ip || "").trim();
  const ipv4MappedMatch = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(normalizedIp);
  if (ipv4MappedMatch) normalizedIp = ipv4MappedMatch[1];
  
  // Check blacklist first
  if (Array.isArray(blacklist)) {
    for (const rule of blacklist) {
      if (ipInRange(normalizedIp, rule.ip, rule.prefix)) {
        return { allowed: false, reason: "blacklisted" };
      }
    }
  }
  
  // If whitelist is configured, only allow whitelisted IPs
  if (Array.isArray(whitelist) && whitelist.length > 0) {
    for (const rule of whitelist) {
      if (ipInRange(normalizedIp, rule.ip, rule.prefix)) {
        return { allowed: true, reason: "" };
      }
    }
    return { allowed: false, reason: "not_whitelisted" };
  }
  
  return { allowed: true, reason: "" };
}

function ipInRange(ip, rangeIp, prefix) {
  if (prefix === 32) return ip === rangeIp;
  
  const ipBytes = ip.split(".").map(Number);
  const rangeBytes = rangeIp.split(".").map(Number);
  let remaining = prefix;
  
  for (let index = 0; index < 4; index += 1) {
    const bits = Math.min(8, remaining);
    if (bits > 0) {
      const mask = (0xff << (8 - bits)) & 0xff;
      if ((ipBytes[index] & mask) !== (rangeBytes[index] & mask)) return false;
    }
    remaining -= bits;
  }
  return true;
}

export { WHITELIST_ACTION, BLACKLIST_ACTION, ACTION_SET };
