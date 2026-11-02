import { ClientSyncError } from "./errors.js";

function parseVersion(value, code = "manifest_invalid") {
  if (typeof value !== "string") {
    throw new ClientSyncError(code, "version must be a string");
  }
  const match = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(value);
  if (!match) throw new ClientSyncError(code, "version must be semantic version x.y.z");
  return {
    core: [Number(match[1]), Number(match[2]), Number(match[3])],
    prerelease: match[4] ? match[4].split(".") : [],
  };
}

function comparePrerelease(left, right) {
  if (left.length === 0 && right.length === 0) return 0;
  if (left.length === 0) return 1;
  if (right.length === 0) return -1;
  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    if (left[index] === undefined) return -1;
    if (right[index] === undefined) return 1;
    const leftNumber = /^\d+$/.test(left[index]);
    const rightNumber = /^\d+$/.test(right[index]);
    if (leftNumber && rightNumber) {
      const difference = Number(left[index]) - Number(right[index]);
      if (difference !== 0) return Math.sign(difference);
      continue;
    }
    if (leftNumber !== rightNumber) return leftNumber ? -1 : 1;
    const difference = left[index].localeCompare(right[index], "en");
    if (difference !== 0) return Math.sign(difference);
  }
  return 0;
}

function compareParsedVersions(left, right) {
  for (let index = 0; index < 3; index += 1) {
    const difference = left.core[index] - right.core[index];
    if (difference !== 0) return Math.sign(difference);
  }
  return comparePrerelease(left.prerelease, right.prerelease);
}

export function compareVersions(leftValue, rightValue) {
  return compareParsedVersions(parseVersion(leftValue), parseVersion(rightValue));
}

export function assertClientVersionSupported(clientVersion, manifest) {
  const client = parseVersion(clientVersion, "invalid_config");
  let minimum;
  try {
    minimum = parseVersion(manifest.compatibility.minClientVersion);
  } catch {
    throw new ClientSyncError("manifest_invalid", "manifest minimum client version is invalid");
  }
  if (compareParsedVersions(client, minimum) < 0) {
    throw new ClientSyncError(
      "client_version_incompatible",
      "manifest requires a newer client version",
    );
  }
}
