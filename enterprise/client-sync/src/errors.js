export class ClientSyncError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ClientSyncError";
    this.code = code;
  }
}

export function asClientSyncError(error) {
  if (error instanceof ClientSyncError) return error;
  return new ClientSyncError("internal_error", "client sync failed");
}

export function publicError(error) {
  return { code: asClientSyncError(error).code };
}
