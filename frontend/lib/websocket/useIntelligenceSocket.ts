import { useEffect, useState } from "react";
import { appConfig } from "../config";
import { dispatchUnauthorized } from "../auth/session";

export type WsFeedStatus = "live" | "reconnecting" | "polling";

export type IntelligenceWsMessage =
  | { type: "intelligence_event"; camera_id: string; event: Record<string, unknown> }
  | { type: "risk_cluster"; camera_id: string; [key: string]: unknown }
  | { type: "risk_update"; camera_id: string; [key: string]: unknown };

const WANTED = new Set(["intelligence_event", "risk_cluster", "risk_update"]);

// Bounded reconnect budget; then park in polling (REST stays authoritative).
const MAX_ATTEMPTS = 6;
// Server close codes (backend/app/auth/ws.py): terminal for this socket.
const WS_CLOSE_UNAUTHORIZED = 4401;
const WS_CLOSE_FORBIDDEN = 4403;

/**
 * Live intelligence feed with exponential-backoff reconnect. When WebSocket
 * streaming is disabled the hook stays in polling mode and the page relies
 * on REST refresh instead — callers always keep polling as a fallback.
 *
 * Resilience (V20): reconnects are bounded; after the budget is exhausted the
 * feed parks in `polling`. A 4401 close clears the session and triggers the
 * global unauthorized redirect; a 4403 close stops reconnecting without
 * treating it as a login failure. Sockets are released before replacement.
 *
 * V16: optional stable `getTicket(scope)` provides the single-use ticket
 * for `/ws/cameras/{cameraId}` (`camera:{id}` scope).
 */
export function useIntelligenceSocket(
  cameraId: string | null,
  onMessage: (message: IntelligenceWsMessage) => void,
  getTicket?: (scope: string) => Promise<string | null>
): WsFeedStatus {
  const [feedStatus, setFeedStatus] = useState<WsFeedStatus>("polling");

  useEffect(() => {
    if (!cameraId) return;
    if (process.env.NEXT_PUBLIC_WS_ENABLED === "false") {
      setFeedStatus("polling");
      return;
    }
    let socket: WebSocket | null = null;
    let closed = false;
    let terminal = false;
    let attempts = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const connect = () => {
      if (closed || terminal || typeof window === "undefined") return;
      void connectAsync();
    };

    const connectAsync = async () => {
      if (closed || terminal || typeof window === "undefined") return;
      // Release any previous socket before opening a replacement (no leak).
      if (socket) {
        try {
          socket.close();
        } catch {
          // Already gone.
        }
        socket = null;
      }
      let query = "";
      if (getTicket && cameraId) {
        let ticket: string | null = null;
        try {
          ticket = await getTicket(`camera:${cameraId}`);
        } catch {
          ticket = null;
        }
        if (closed || terminal) return;
        if (!ticket) {
          setFeedStatus("reconnecting");
          schedule();
          return;
        }
        query = `?ticket=${encodeURIComponent(ticket)}`;
      }
      let ws: WebSocket;
      try {
        ws = new WebSocket(`${appConfig.wsUrl}/ws/cameras/${cameraId}${query}`);
      } catch {
        schedule();
        return;
      }
      socket = ws;
      ws.onopen = () => {
        attempts = 0;
        setFeedStatus("live");
      };
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data) as IntelligenceWsMessage;
          if (data && WANTED.has(data.type)) onMessage(data);
        } catch {
          // Ignore non-JSON frames; polling keeps state fresh.
        }
      };
      ws.onerror = () => {
        try {
          ws.close();
        } catch {
          // Fall through to reconnect scheduling below.
        }
      };
      ws.onclose = (event?: CloseEvent) => {
        if (closed || terminal) return;
        if (socket === ws) socket = null;
        const code = event?.code;
        if (code === WS_CLOSE_UNAUTHORIZED) {
          terminal = true;
          setFeedStatus("polling");
          dispatchUnauthorized();
          return;
        }
        if (code === WS_CLOSE_FORBIDDEN) {
          terminal = true;
          setFeedStatus("polling");
          return;
        }
        setFeedStatus("reconnecting");
        schedule();
      };
    };
    const schedule = () => {
      if (closed || terminal) return;
      attempts += 1;
      if (attempts > MAX_ATTEMPTS) {
        terminal = true;
        setFeedStatus("polling");
        return;
      }
      const delay = Math.min(1000 * 2 ** attempts, 15000);
      timer = setTimeout(connect, delay);
    };

    connect();
    return () => {
      closed = true;
      if (timer !== undefined) clearTimeout(timer);
      try {
        socket?.close();
      } catch {
        // Socket already gone; nothing to clean up.
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cameraId]);

  return feedStatus;
}
