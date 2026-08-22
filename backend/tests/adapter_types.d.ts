declare module "@earendil-works/pi-coding-agent" {
  export interface ExtensionAPI {
    on(
      name: "tool_call" | "session_start",
      handler: (event: unknown, context: { sessionManager: { getSessionId(): string } }) => unknown,
    ): void;
  }
}

declare module "openclaw/plugin-sdk/plugin-entry" {
  interface PluginApi {
    on(
      name: "before_tool_call",
      handler: (event: never, context: never) => unknown,
      options?: { priority?: number; timeoutMs?: number },
    ): void;
  }

  interface PluginEntry {
    id: string;
    name: string;
    description?: string;
    register(api: PluginApi): void;
  }

  export function definePluginEntry(entry: PluginEntry): PluginEntry;
}
