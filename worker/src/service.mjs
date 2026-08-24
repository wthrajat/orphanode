import {
  MAX_BATCH_QUERIES,
  ProtocolError,
  protocolDescriptor,
  withRequestTimeout,
} from "./protocol.mjs";
import { initializeTypeScriptOracle } from "./typescript-oracle.mjs";

export function createWorkerService(options = {}) {
  const initializeOracle =
    options.initializeOracle ?? initializeTypeScriptOracle;
  let state = {
    status: "unavailable",
    reason: "not_initialized",
    capabilityNote: "initialize must succeed before deep queries are available",
  };

  return {
    async handle(request, context) {
      switch (request.method) {
        case "capabilities":
          return {
            ...protocolDescriptor(),
            queryKinds: [
              "memberUsage",
              "receiverCandidates",
              "overrideRelationships",
            ],
            deepAnalysis: publicState(state),
          };
        case "initialize": {
          let initialized;
          try {
            initialized = await initializeOracle(request.params);
          } catch {
            initialized = {
              status: "unavailable",
              reason: "typescript_initialization_failed",
              capabilityNote:
                "the TypeScript worker failed without exposing project source or a stack trace",
            };
          }
          state = initialized;
          return publicState(initialized);
        }
        case "query": {
          if (state.status !== "ready") {
            return {
              status: "unavailable",
              reason: state.reason,
              capabilityNote: state.capabilityNote,
              results: [],
            };
          }
          const queries = request.params.queries;
          if (!Array.isArray(queries)) {
            throw new ProtocolError(
              "invalid_params",
              "query params must contain a queries array",
              request.id,
            );
          }
          if (queries.length > MAX_BATCH_QUERIES) {
            throw new ProtocolError(
              "batch_too_large",
              `query batch exceeds ${MAX_BATCH_QUERIES} entries`,
              request.id,
            );
          }
          return {
            status: "resolved",
            results: state.oracle.queryBatch(queries, context),
          };
        }
        case "shutdown":
          return { status: "ok", shutdown: true };
        default:
          throw new ProtocolError(
            "method_not_found",
            `unsupported method ${request.method}`,
            request.id,
          );
      }
    },
  };
}

export async function dispatchRequest(service, request) {
  return withRequestTimeout(request.timeoutMs, (context) =>
    service.handle(request, context),
  );
}

function publicState(state) {
  if (state.status === "ready") {
    return {
      status: "ready",
      typescriptVersion: state.typescriptVersion,
      typescriptIdentity: state.typescriptIdentity,
      configPath: state.configPath,
      loadedProjectCode: true,
      capabilityNote:
        "the explicitly authorized workspace TypeScript package is loaded in this worker process",
    };
  }
  const result = {
    status: "unavailable",
    reason: state.reason,
    capabilityNote: state.capabilityNote,
  };
  if (Array.isArray(state.diagnostics)) {
    result.diagnostics = state.diagnostics;
  }
  return result;
}
