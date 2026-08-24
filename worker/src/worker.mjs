#!/usr/bin/env node

import { pathToFileURL } from "node:url";

import {
  JsonLineDecoder,
  ProtocolError,
  encodeMessage,
  errorResponse,
  parseRequestLine,
  successResponse,
} from "./protocol.mjs";
import { createWorkerService, dispatchRequest } from "./service.mjs";

export async function runWorker({ input = process.stdin, output = process.stdout } = {}) {
  const decoder = new JsonLineDecoder();
  const service = createWorkerService();
  let shouldShutdown = false;

  try {
    for await (const chunk of input) {
      const lines = decoder.push(chunk);
      for (const line of lines) {
        shouldShutdown = await processLine(service, line, output);
        if (shouldShutdown) {
          return 0;
        }
      }
    }
    for (const line of decoder.finish()) {
      shouldShutdown = await processLine(service, line, output);
      if (shouldShutdown) {
        return 0;
      }
    }
  } catch (error) {
    const protocolError = normalizeError(error);
    writeResponse(
      output,
      errorResponse(
        protocolError.requestId,
        protocolError.code,
        protocolError.message,
      ),
    );
    return protocolError.code === "message_too_large" ? 2 : 1;
  }

  return 0;
}

async function processLine(service, line, output) {
  let request;
  try {
    request = parseRequestLine(line);
    const result = await dispatchRequest(service, request);
    writeResponse(output, successResponse(request.id, result));
    return result.shutdown === true;
  } catch (error) {
    const protocolError = normalizeError(error, request?.id ?? null);
    writeResponse(
      output,
      errorResponse(
        protocolError.requestId,
        protocolError.code,
        protocolError.message,
      ),
    );
    return false;
  }
}

function writeResponse(output, response) {
  try {
    output.write(encodeMessage(response));
  } catch (error) {
    const protocolError = normalizeError(error, response.id ?? null);
    output.write(
      encodeMessage(
        errorResponse(
          protocolError.requestId,
          protocolError.code,
          protocolError.message,
        ),
      ),
    );
  }
}

function normalizeError(error, requestId = null) {
  if (error instanceof ProtocolError) {
    return error.requestId === null && requestId !== null
      ? new ProtocolError(error.code, error.message, requestId)
      : error;
  }
  if (error && typeof error.code === "string") {
    return new ProtocolError(error.code, safeErrorMessage(error), requestId);
  }
  return new ProtocolError(
    "internal_worker_error",
    "the worker failed without exposing project source or a stack trace",
    requestId,
  );
}

function safeErrorMessage(error) {
  if (error.code === "request_timeout") {
    return "the TypeScript query batch exceeded its deadline";
  }
  return "the worker could not complete the request";
}

const isMain =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  process.exitCode = await runWorker();
}
