import type { PublicOptions } from "../types/public.js";

export function contractName(options: PublicOptions): string {
  return options.contract.name;
}
