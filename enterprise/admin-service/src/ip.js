import net from "node:net";

function ipv4Bytes(value) {
  const parts = String(value).split(".");
  if (parts.length !== 4) return null;
  const bytes = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const number = Number(part);
    if (number < 0 || number > 255) return null;
    bytes.push(number);
  }
  return bytes;
}

export function normalizeIp(value) {
  let ip = String(value || "").trim();
  if (ip.startsWith("[") && ip.endsWith("]")) ip = ip.slice(1, -1);
  if (/^::ffff:\d+\.\d+\.\d+\.\d+$/i.test(ip)) ip = ip.slice(7);
  return ip.toLowerCase();
}

export function parseAllowedIp(raw, name = "ADMIN_ALLOWED_IPS") {
  const value = normalizeIp(raw);
  if (!value) throw new Error(`${name} contains an empty entry`);
  const [address, prefixText, extra] = value.split("/");
  if (extra != null) throw new Error(`${name} contains an invalid CIDR entry`);

  if (net.isIP(address) === 4) {
    const prefix = prefixText == null ? 32 : Number(prefixText);
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
      throw new Error(`${name} contains an invalid IPv4 prefix`);
    }
    return { version: 4, address, bytes: ipv4Bytes(address), prefix };
  }

  if (net.isIP(address) === 6) {
    const prefix = prefixText == null ? 128 : Number(prefixText);
    if (prefix !== 128) {
      throw new Error(`${name} currently supports only exact IPv6 addresses (/128)`);
    }
    return { version: 6, address, prefix: 128 };
  }

  throw new Error(`${name} contains an invalid IP address`);
}

export function ipMatches(rule, value) {
  const ip = normalizeIp(value);
  if (rule.version === 6) return ip === rule.address;

  const bytes = ipv4Bytes(ip);
  if (!bytes) return false;
  let remaining = rule.prefix;
  for (let index = 0; index < 4; index += 1) {
    const bits = Math.min(8, remaining);
    if (bits > 0) {
      const mask = (0xff << (8 - bits)) & 0xff;
      if ((bytes[index] & mask) !== (rule.bytes[index] & mask)) return false;
    }
    remaining -= bits;
  }
  return true;
}

export function clientIp(req) {
  return normalizeIp(req.socket.remoteAddress || "");
}
