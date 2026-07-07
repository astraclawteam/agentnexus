export class HTTPError extends Error {
  status: number;
  code: string;
  safeMessage: string;
  details?: unknown;

  constructor(status: number, safeMessage: string, code = "http_error", details?: unknown) {
    super(safeMessage);
    this.name = "HTTPError";
    this.status = status;
    this.code = code;
    this.safeMessage = safeMessage;
    this.details = details;
  }
}

export async function readJSON<T>(response: Response): Promise<T> {
  if (response.ok) {
    return (await response.json()) as T;
  }

  const payload = await readErrorPayload(response);
  throw new HTTPError(response.status, payload.message, payload.code, payload.details);
}

async function readErrorPayload(response: Response): Promise<{ message: string; code: string; details?: unknown }> {
  try {
    const payload = (await response.json()) as { error?: string; code?: string; details?: unknown };
    return {
      message: payload.error || `Request failed with status ${response.status}`,
      code: payload.code || "http_error",
      details: payload.details
    };
  } catch {
    return {
      message: `Request failed with status ${response.status}`,
      code: "http_error"
    };
  }
}

