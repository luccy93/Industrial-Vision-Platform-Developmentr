import { appConfig } from "../config";

export type WsStatus = "connected" | "disconnected" | "disabled";

/** Minimal WebSocket abstraction for future live detection/event streams. */
export function createEventSocket(
  path = "/api/v1/events",
  onMessage?: (data: unknown) => void
): { url: string; enabled: boolean; connect: () => WebSocket | null } {
  const enabled = process.env.NEXT_PUBLIC_WS_ENABLED !== "false";
  const url = `${appConfig.wsUrl}${path}`;
  return {
    url,
    enabled,
    connect: () => {
      if (!enabled || typeof window === "undefined") return null;
      const ws = new WebSocket(url);
      ws.onmessage = (ev) => onMessage?.(ev.data);
      return ws;
    }
  };
}
