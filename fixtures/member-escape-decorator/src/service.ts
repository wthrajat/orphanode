const registeredClasses = new Set<Function>();

function registered(value: Function): void {
  registeredClasses.add(value);
}

@registered
export class Service {
  #secret = "private value";

  usedMethod(): string {
    return this.#secret;
  }

  unusedPrivateMethod(): string {
    return "no direct call";
  }

  publicHook(): string {
    return "visible after escape";
  }
}

export function runService(): string {
  const service = new Service();
  const host = globalThis as typeof globalThis & {
    fixtureSink?: (value: unknown) => void;
  };

  host.fixtureSink?.(service);
  Reflect.ownKeys(service);
  return service.usedMethod();
}
