export function execute(): string {
  return liveLeaf();
}

function liveLeaf(): string {
  return "reachable symbol";
}

export function deadA(): string {
  return deadB();
}

export function deadB(): string {
  return deadA();
}
