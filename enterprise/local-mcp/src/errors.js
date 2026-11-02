export class LocalMcpError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "LocalMcpError";
    this.code = code;
  }
}

export function localMcpError(code, message) {
  return new LocalMcpError(code, message);
}

export function asLocalMcpError(error, fallbackCode = "internal_error") {
  if (error instanceof LocalMcpError) return error;
  return new LocalMcpError(fallbackCode, "local MCP operation failed");
}

export function publicError(error) {
  return { code: asLocalMcpError(error).code };
}
