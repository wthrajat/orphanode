import fs from "node:fs";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import path from "node:path";

export async function initializeTypeScriptOracle(params) {
  if (params.allowProjectTypeScript !== true) {
    return unavailable(
      "project_typescript_not_authorized",
      "deep analysis did not authorize loading the workspace TypeScript package",
    );
  }
  if (typeof params.workspaceRoot !== "string" || params.workspaceRoot.length === 0) {
    return unavailable(
      "workspace_root_missing",
      "workspaceRoot is required to locate project TypeScript",
    );
  }

  let workspaceRoot;
  try {
    workspaceRoot = fs.realpathSync(params.workspaceRoot);
  } catch {
    return unavailable(
      "workspace_root_unavailable",
      "workspaceRoot does not resolve to a readable directory",
    );
  }
  if (!fs.statSync(workspaceRoot).isDirectory()) {
    return unavailable(
      "workspace_root_unavailable",
      "workspaceRoot does not resolve to a readable directory",
    );
  }

  const requestedResolutionRoot =
    typeof params.typescriptResolutionRoot === "string" &&
    params.typescriptResolutionRoot.length > 0
      ? params.typescriptResolutionRoot
      : workspaceRoot;
  let typescriptResolutionRoot;
  try {
    typescriptResolutionRoot = fs.realpathSync(
      path.resolve(workspaceRoot, requestedResolutionRoot),
    );
  } catch {
    return unavailable(
      "typescript_resolution_root_unavailable",
      "typescriptResolutionRoot does not resolve to a readable directory",
    );
  }
  if (
    !isWithin(workspaceRoot, typescriptResolutionRoot) ||
    !fs.statSync(typescriptResolutionRoot).isDirectory()
  ) {
    return unavailable(
      "typescript_resolution_root_outside_workspace",
      "typescriptResolutionRoot must be a directory inside workspaceRoot",
    );
  }

  const workspaceRequire = createRequire(
    path.join(typescriptResolutionRoot, "package.json"),
  );
  const requestedTypeScript =
    typeof params.typescriptPath === "string" && params.typescriptPath.length > 0
      ? params.typescriptPath
      : "typescript";
  let typescriptEntry;
  let ts;
  try {
    typescriptEntry = workspaceRequire.resolve(requestedTypeScript);
    const realTypeScriptEntry = fs.realpathSync(typescriptEntry);
    if (!isWithin(workspaceRoot, realTypeScriptEntry)) {
      return unavailable(
        "typescript_outside_workspace",
        "the selected TypeScript package is outside workspaceRoot",
      );
    }
    ts = workspaceRequire(realTypeScriptEntry);
    typescriptEntry = realTypeScriptEntry;
  } catch {
    return unavailable(
      "typescript_unavailable",
      "a compatible TypeScript package could not be loaded from the workspace",
    );
  }

  if (!hasCompatibleApi(ts)) {
    return unavailable(
      "typescript_incompatible",
      "the selected TypeScript package does not provide the required compiler API",
    );
  }

  const requestedConfig =
    typeof params.tsconfigPath === "string" && params.tsconfigPath.length > 0
      ? params.tsconfigPath
      : "tsconfig.json";
  let configPath;
  try {
    configPath = fs.realpathSync(path.resolve(workspaceRoot, requestedConfig));
  } catch {
    return unavailable(
      "tsconfig_unavailable",
      "tsconfigPath does not resolve to a readable file",
    );
  }
  if (!isWithin(workspaceRoot, configPath)) {
    return unavailable(
      "tsconfig_outside_workspace",
      "tsconfigPath must remain inside workspaceRoot",
    );
  }

  const config = ts.readConfigFile(configPath, ts.sys.readFile);
  if (config.error) {
    return unavailable(
      "tsconfig_unavailable",
      diagnosticMessage(ts, config.error),
    );
  }
  const parsed = ts.parseJsonConfigFileContent(
    config.config,
    ts.sys,
    path.dirname(configPath),
    undefined,
    configPath,
  );
  if (parsed.errors.length > 0) {
    return {
      ...unavailable(
        "tsconfig_invalid",
        "TypeScript rejected the selected project configuration",
      ),
      diagnostics: parsed.errors.map((diagnostic) => ({
        code: diagnostic.code,
        message: diagnosticMessage(ts, diagnostic),
      })),
    };
  }

  let program;
  try {
    program = ts.createProgram({
      rootNames: parsed.fileNames,
      options: parsed.options,
      projectReferences: parsed.projectReferences,
    });
  } catch {
    return unavailable(
      "typescript_program_unavailable",
      "TypeScript could not construct the configured project",
    );
  }

  return {
    status: "ready",
    typescriptVersion: String(ts.version ?? "unknown"),
    typescriptIdentity: createHash("sha256")
      .update(String(ts.version ?? "unknown"))
      .update("\0")
      .update(fs.readFileSync(typescriptEntry))
      .digest("hex"),
    configPath: projectPath(workspaceRoot, configPath),
    oracle: new TypeScriptOracle(ts, program, workspaceRoot),
  };
}

class TypeScriptOracle {
  #ts;
  #program;
  #checker;
  #workspaceRoot;

  constructor(ts, program, workspaceRoot) {
    this.#ts = ts;
    this.#program = program;
    this.#checker = program.getTypeChecker();
    this.#workspaceRoot = workspaceRoot;
  }

  queryBatch(queries, context) {
    const results = [];
    for (const query of queries) {
      checkDeadline(context);
      results.push(this.#query(query));
      checkDeadline(context);
    }
    return results;
  }

  #query(query) {
    if (!isRecord(query) || !isQueryId(query.id)) {
      return incomplete(null, "invalid_query", "query.id must be a string or safe integer");
    }
    if (query.kind === "memberUsage") {
      return this.#memberUsage(query);
    }
    if (query.kind === "receiverCandidates") {
      return this.#receiverCandidates(query);
    }
    if (query.kind === "overrideRelationships") {
      return this.#overrideRelationships(query);
    }
    return incomplete(
      query.id,
      "unsupported_query_kind",
      "query.kind must be memberUsage, receiverCandidates, or overrideRelationships",
    );
  }

  #memberUsage(query) {
    const resolved = this.#memberAtLocation(query);
    if (resolved.status !== "ready") {
      return { queryId: query.id, ...resolved };
    }
    const { member, memberSymbol, owner } = resolved;
    const memberName = memberSymbol.getName();
    const ownerType = this.#checker.getTypeAtLocation(owner);
    const references = this.#symbolReferences(memberSymbol);
    const overrides = collectBaseMembers(ownerType, memberName).map((symbol) =>
      this.#overrideRelationship(symbol),
    );
    return {
      queryId: query.id,
      kind: "memberUsage",
      status: "resolved",
      member: this.#symbolIdentity(memberSymbol),
      references,
      overrides: deduplicateSymbols(overrides),
    };
  }

  #receiverCandidates(query) {
    const location = this.#location(query);
    if (location.status !== "ready") {
      return { queryId: query.id, ...location };
    }
    const { sourceFile, position } = location;
    const nodes = nodePathAtPosition(sourceFile, position);
    const access = [...nodes].reverse().find((node) =>
      this.#ts.isPropertyAccessExpression(node) ||
      this.#ts.isElementAccessExpression(node),
    );
    if (!access) {
      return incomplete(
        query.id,
        "receiver_not_found",
        "position is not inside a property or element access",
      );
    }

    const receiverType = this.#checker.getTypeAtLocation(access.expression);
    const candidateTypes = receiverType.isUnionOrIntersection?.()
      ? receiverType.types
      : [receiverType];
    const candidates = deduplicateSymbols(
      candidateTypes
        .map((type) => type.aliasSymbol ?? type.getSymbol?.())
        .filter(Boolean)
        .map((symbol) => this.#symbolIdentity(symbol)),
    );
    const propertyName = propertyAccessName(this.#ts, access);

    return {
      queryId: query.id,
      kind: "receiverCandidates",
      status: "resolved",
      propertyName,
      receiverCandidates: candidates,
    };
  }

  #overrideRelationships(query) {
    const resolved = this.#memberAtLocation(query);
    if (resolved.status !== "ready") {
      return { queryId: query.id, ...resolved };
    }
    const { memberSymbol, owner } = resolved;

    const memberName = memberSymbol.getName();
    const ownerType = this.#checker.getTypeAtLocation(owner);
    const overridden = collectBaseMembers(ownerType, memberName).map((symbol) =>
      this.#symbolIdentity(symbol),
    );

    return {
      queryId: query.id,
      kind: "overrideRelationships",
      status: "resolved",
      member: this.#symbolIdentity(memberSymbol),
      overrides: deduplicateSymbols(overridden),
    };
  }

  #memberAtLocation(query) {
    const location = this.#location(query);
    if (location.status !== "ready") {
      return location;
    }
    const { sourceFile, position } = location;
    const nodes = nodePathAtPosition(sourceFile, position);
    const member = [...nodes].reverse().find((node) =>
      isClassLikeMember(this.#ts, node),
    );
    if (!member || !member.name) {
      return {
        status: "incomplete",
        reason: "member_not_found",
        capabilityNote:
          "position is not inside a supported class or interface member",
      };
    }
    const memberSymbol = this.#checker.getSymbolAtLocation(member.name);
    if (!memberSymbol) {
      return {
        status: "incomplete",
        reason: "member_symbol_unavailable",
        capabilityNote:
          "TypeScript did not provide a symbol for the selected member",
      };
    }
    const owner = [...nodes].reverse().find((node) =>
      this.#ts.isClassLike(node) || this.#ts.isInterfaceDeclaration(node),
    );
    if (!owner) {
      return {
        status: "incomplete",
        reason: "member_owner_unavailable",
        capabilityNote: "selected member has no class or interface owner",
      };
    }
    return { status: "ready", member, memberSymbol, owner };
  }

  #location(query) {
    if (typeof query.file !== "string" || query.file.length === 0) {
      return {
        status: "incomplete",
        reason: "invalid_file",
        capabilityNote: "query.file must be a non-empty project-relative path",
      };
    }
    const absolutePath = path.resolve(this.#workspaceRoot, query.file);
    if (!isWithin(this.#workspaceRoot, absolutePath)) {
      return {
        status: "incomplete",
        reason: "file_outside_workspace",
        capabilityNote: "query.file must remain inside workspaceRoot",
      };
    }
    if (!Number.isSafeInteger(query.position) || query.position < 0) {
      return {
        status: "incomplete",
        reason: "invalid_position",
        capabilityNote: "query.position must be a non-negative safe integer",
      };
    }
    const sourceFile = this.#program.getSourceFile(absolutePath);
    if (!sourceFile) {
      return {
        status: "incomplete",
        reason: "file_not_in_program",
        capabilityNote: "query.file is not part of the configured TypeScript program",
      };
    }
    if (query.position >= sourceFile.getEnd()) {
      return {
        status: "incomplete",
        reason: "position_out_of_range",
        capabilityNote: "query.position lies outside query.file",
      };
    }
    return { status: "ready", sourceFile, position: query.position };
  }

  #symbolIdentity(symbol) {
    const name = symbol.getName();
    const declarations = (symbol.declarations ?? [])
      .map((declaration) => declarationSpan(this.#workspaceRoot, declaration))
      .filter(Boolean)
      .sort(compareDeclarationSpans);
    const first = declarations[0];
    const id = first
      ? `${first.path}:${first.start}:${first.end}:${name}`
      : `external:${name}`;
    return { id, name, declarations };
  }

  #symbolReferences(targetSymbol) {
    const declarationNames = new Set(
      (targetSymbol.declarations ?? [])
        .map((declaration) => declaration.name)
        .filter(Boolean),
    );
    const references = [];
    for (const sourceFile of this.#program.getSourceFiles()) {
      if (sourceFile.isDeclarationFile) {
        continue;
      }
      const visit = (node) => {
        if (node.name && !declarationNames.has(node.name)) {
          const symbol = this.#checker.getSymbolAtLocation(node.name);
          if (sameSymbol(this.#ts, this.#checker, symbol, targetSymbol)) {
            references.push(referenceSpan(this.#workspaceRoot, node.name));
          }
        }
        node.forEachChild(visit);
      };
      sourceFile.forEachChild(visit);
    }
    return references.filter(Boolean).sort(compareDeclarationSpans);
  }

  #overrideRelationship(symbol) {
    const ownerNode = (symbol.declarations ?? [])
      .map((declaration) => declaration.parent)
      .find((parent) =>
        this.#ts.isClassLike(parent) || this.#ts.isInterfaceDeclaration(parent),
      );
    const ownerSymbol = ownerNode?.name
      ? this.#checker.getSymbolAtLocation(ownerNode.name)
      : undefined;
    const ownerExported =
      ownerNode?.modifiers?.some(
        (modifier) =>
          modifier.kind === this.#ts.SyntaxKind.ExportKeyword ||
          modifier.kind === this.#ts.SyntaxKind.DefaultKeyword,
      ) ?? false;
    return {
      symbol: this.#symbolIdentity(symbol),
      owner: ownerSymbol ? this.#symbolIdentity(ownerSymbol) : null,
      ownerExported,
      references: this.#symbolReferences(symbol),
    };
  }
}

function unavailable(reason, capabilityNote) {
  return { status: "unavailable", reason, capabilityNote };
}

function incomplete(queryId, reason, capabilityNote) {
  return { queryId, status: "incomplete", reason, capabilityNote };
}

function hasCompatibleApi(ts) {
  return (
    ts &&
    typeof ts.createProgram === "function" &&
    typeof ts.readConfigFile === "function" &&
    typeof ts.parseJsonConfigFileContent === "function" &&
    ts.sys &&
    typeof ts.sys.readFile === "function"
  );
}

function diagnosticMessage(ts, diagnostic) {
  return ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n");
}

function checkDeadline({ signal, deadlineMs }) {
  if (signal.aborted || Date.now() >= deadlineMs) {
    throw Object.assign(new Error("TypeScript query batch exceeded its deadline"), {
      code: "request_timeout",
    });
  }
}

function nodePathAtPosition(sourceFile, position) {
  const nodes = [];
  function visit(node) {
    if (position < node.getFullStart() || position >= node.getEnd()) {
      return;
    }
    nodes.push(node);
    node.forEachChild(visit);
  }
  visit(sourceFile);
  return nodes;
}

function propertyAccessName(ts, access) {
  if (ts.isPropertyAccessExpression(access)) {
    return access.name.text;
  }
  const argument = access.argumentExpression;
  if (argument && (ts.isStringLiteral(argument) || ts.isNumericLiteral(argument))) {
    return argument.text;
  }
  return null;
}

function isClassLikeMember(ts, node) {
  return (
    ts.isMethodDeclaration(node) ||
    ts.isMethodSignature(node) ||
    ts.isPropertyDeclaration(node) ||
    ts.isPropertySignature(node) ||
    ts.isGetAccessorDeclaration(node) ||
    ts.isSetAccessorDeclaration(node)
  );
}

function declarationSpan(workspaceRoot, declaration) {
  const sourceFile = declaration.getSourceFile();
  const relativePath = projectPath(workspaceRoot, sourceFile.fileName);
  if (relativePath === null) {
    return null;
  }
  return {
    path: relativePath,
    start: declaration.getStart(sourceFile, false),
    end: declaration.getEnd(),
  };
}

function referenceSpan(workspaceRoot, node) {
  const sourceFile = node.getSourceFile();
  const relativePath = projectPath(workspaceRoot, sourceFile.fileName);
  if (relativePath === null) {
    return null;
  }
  return {
    path: relativePath,
    start: node.getStart(sourceFile, false),
    end: node.getEnd(),
  };
}

function projectPath(workspaceRoot, absolutePath) {
  const relative = path.relative(workspaceRoot, path.resolve(absolutePath));
  if (relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative))) {
    return relative.split(path.sep).join("/") || ".";
  }
  return null;
}

function isWithin(root, target) {
  const relative = path.relative(root, target);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function deduplicateSymbols(symbols) {
  const byId = new Map();
  for (const symbol of symbols) {
    const identity = symbol.symbol ?? symbol;
    byId.set(identity.id, symbol);
  }
  return [...byId.values()].sort((left, right) => {
    const leftIdentity = left.symbol ?? left;
    const rightIdentity = right.symbol ?? right;
    return leftIdentity.id.localeCompare(rightIdentity.id);
  });
}

function compareDeclarationSpans(left, right) {
  return (
    left.path.localeCompare(right.path) ||
    left.start - right.start ||
    left.end - right.end
  );
}

function collectBaseMembers(ownerType, memberName) {
  const overridden = [];
  const visited = new Set();
  const pending = [...(ownerType.getBaseTypes?.() ?? [])];
  while (pending.length > 0) {
    const baseType = pending.pop();
    if (!baseType || visited.has(baseType)) {
      continue;
    }
    visited.add(baseType);
    const baseMember = baseType.getProperty?.(memberName);
    if (baseMember) {
      overridden.push(baseMember);
    }
    pending.push(...(baseType.getBaseTypes?.() ?? []));
  }
  return overridden;
}

function sameSymbol(ts, checker, left, right) {
  if (!left || !right) {
    return false;
  }
  const unwrap = (symbol) => {
    try {
      return symbol.flags & ts.SymbolFlags.Alias
        ? checker.getAliasedSymbol(symbol)
        : symbol;
    } catch {
      return symbol;
    }
  };
  return unwrap(left) === unwrap(right);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isQueryId(value) {
  return (
    (typeof value === "string" && value.length > 0) ||
    Number.isSafeInteger(value)
  );
}
