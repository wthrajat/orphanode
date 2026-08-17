import { workspaceSubpath } from "@fixture/closed/feature";

export function publicApi() {
  return `open-world export: ${workspaceSubpath}`;
}
