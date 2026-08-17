export const PROTOCOL_NAME = "orphanode.typescript-worker";
export const PROTOCOL_VERSION = 1;
export const MAX_MESSAGE_BYTES = 1024 * 1024;
export const MAX_BATCH_QUERIES = 256;
export const DEFAULT_REQUEST_TIMEOUT_MS = 5_000;
export const MAX_REQUEST_TIMEOUT_MS = 30_000;

export class ProtocolError extends Error {
  constructor(code, message, requestId = null) {
    super(message);
    this.name = "ProtocolError";
    this.code = code;
    this.requestId = requestId;
  }
}

export class JsonLineDecoder {
  #buffer = Buffer.alloc(0);
  #maxMessageBytes;

  constructor(maxMessageBytes = MAX_MESSAGE_BYTES) {
    if (!Number.isSafeInteger(maxMessageBytes) || maxMessageBytes < 1) {
      throw new TypeError("maxMessageBytes must be a positive safe integer");
    }
    this.#maxMessageBytes = maxMessageBytes;
  }

  push(chunk) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    this.#buffer = Buffer.concat([this.#buffer, bytes]);
    const lines = [];

    while (true) {
      const newline = this.#buffer.indexOf(0x0a);
      if (newline === -1) {
        if (this.#buffer.length > this.#maxMessageBytes) {
          throw new ProtocolError(
            "message_too_large",
            `request exceeds ${this.#maxMessageBytes} bytes`,
          );
        }
        break;
      }
      if (newline > this.#maxMessageBytes) {
        throw new ProtocolError(
          "message_too_large",
          `request exceeds ${this.#maxMessageBytes} bytes`,
        );
      }

      let line = this.#buffer.subarray(0, newline);
      this.#buffer = this.#buffer.subarray(newline + 1);
      if (line.at(-1) === 0x0d) {
        line = line.subarray(0, line.length - 1);
      }
      lines.push(line);
    }

    return lines;
  }

  finish() {
    if (this.#buffer.length === 0) {
      return [];
    }
    if (this.#buffer.length > this.#maxMessageBytes) {
      throw new ProtocolError(
        "message_too_large",
        `request exceeds ${this.#maxMessageBytes} bytes`,
      );
    }
    const line = this.#buffer;
    this.#buffer = Buffer.alloc(0);
    return [line];
  }
}

export function parseRequestLine(line) {
  if (line.length === 0) {
    throw new ProtocolError("empty_message", "empty JSON-lines messages are invalid");
  }

  let request;
  try {
    request = JSON.parse(line.toString("utf8"));
  } catch {
    throw new ProtocolError("invalid_json", "request is not valid JSON");
  }
  if (!isRecord(request)) {
    throw new ProtocolError("invalid_request", "request must be a JSON object");
  }

  const requestId = isRequestId(request.id) ? request.id : null;
  if (request.protocol !== PROTOCOL_NAME) {
    throw new ProtocolError(
      "unsupported_protocol",
      `protocol must be ${PROTOCOL_NAME}`,
      requestId,
    );
  }
  if (request.protocolVersion !== PROTOCOL_VERSION) {
    throw new ProtocolError(
      "unsupported_protocol_version",
      `protocolVersion must be ${PROTOCOL_VERSION}`,
      requestId,
    );
  }
  if (!isRequestId(request.id)) {
    throw new ProtocolError(
      "invalid_request_id",
      "id must be a string or safe integer",
    );
  }
  if (typeof request.method !== "string" || request.method.length === 0) {
    throw new ProtocolError(
      "invalid_method",
      "method must be a non-empty string",
      request.id,
    );
  }
  if (request.params !== undefined && !isRecord(request.params)) {
    throw new ProtocolError(
      "invalid_params",
      "params must be a JSON object",
      request.id,
    );
  }
  if (request.timeoutMs !== undefined) {
    if (
      !Number.isSafeInteger(request.timeoutMs) ||
      request.timeoutMs < 1 ||
      request.timeoutMs > MAX_REQUEST_TIMEOUT_MS
    ) {
      throw new ProtocolError(
        "invalid_timeout",
        `timeoutMs must be an integer from 1 through ${MAX_REQUEST_TIMEOUT_MS}`,
        request.id,
      );
    }
  }

  return {
    protocol: PROTOCOL_NAME,
    protocolVersion: PROTOCOL_VERSION,
    id: request.id,
    method: request.method,
    params: request.params ?? {},
    timeoutMs: request.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS,
  };
}

export function successResponse(id, result) {
  return {
    protocol: PROTOCOL_NAME,
    protocolVersion: PROTOCOL_VERSION,
    id,
    result,
  };
}

export function errorResponse(id, code, message) {
  return {
    protocol: PROTOCOL_NAME,
    protocolVersion: PROTOCOL_VERSION,
    id,
    error: { code, message },
  };
}

export function encodeMessage(message) {
  const payload = Buffer.from(JSON.stringify(message), "utf8");
  if (payload.length > MAX_MESSAGE_BYTES) {
    throw new ProtocolError(
      "response_too_large",
      `response exceeds ${MAX_MESSAGE_BYTES} bytes`,
      message.id ?? null,
    );
  }
  return Buffer.concat([payload, Buffer.from("\n")]);
}

export function protocolDescriptor() {
  return {
    name: PROTOCOL_NAME,
    version: PROTOCOL_VERSION,
    framing: "json-lines",
    limits: {
      maxMessageBytes: MAX_MESSAGE_BYTES,
      maxBatchQueries: MAX_BATCH_QUERIES,
      defaultRequestTimeoutMs: DEFAULT_REQUEST_TIMEOUT_MS,
      maxRequestTimeoutMs: MAX_REQUEST_TIMEOUT_MS,
    },
    timeoutContract: {
      workerChecksDeadlinesBetweenQueries: true,
      hardTimeoutEnforcement: "host-must-terminate-worker-process",
      reason:
        "TypeScript APIs are synchronous and cannot be interrupted safely mid-call",
    },
  };
}

export async function withRequestTimeout(timeoutMs, operation) {
  const controller = new AbortController();
  const deadlineMs = Date.now() + timeoutMs;
  let timeout;
  const timedOut = new Promise((_, reject) => {
    timeout = setTimeout(() => {
      controller.abort();
      reject(
        new ProtocolError(
          "request_timeout",
          `request exceeded its ${timeoutMs} ms timeout`,
        ),
      );
    }, timeoutMs);
    timeout.unref?.();
  });

  try {
    return await Promise.race([
      Promise.resolve().then(() => operation({ signal: controller.signal, deadlineMs })),
      timedOut,
    ]);
  } finally {
    clearTimeout(timeout);
  }
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isRequestId(value) {
  return (
    (typeof value === "string" && value.length > 0) ||
    Number.isSafeInteger(value)
  );
}
