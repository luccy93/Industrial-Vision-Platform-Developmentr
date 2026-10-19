import { useEffect, useState } from "react";
import { appConfig } from "../config";
import { dispatchUnauthorized } from "../auth/session";
import type { OperationsWsMessage } from "../../types";

export type OpsFeedStatus = "live" | "reconnecting" | "polling" | "disabled";

const MAX_DELAY_MS = 15000;
const BASE_DELAY_MS = 1000;
// After this many consecutive failed (re)connects the hook gives up on the
// socket and falls back to REST polling instead of retrying forever.
const MAX_ATTEMPTS = 6;
// Server close codes (backend/app/auth/ws.py): 4401 = unauthenticated,
// 4403 = authenticated but forbidden. Both are terminal for the socket.
const WS_CLOSE_UNAUTHORIZED = 4401;
const WS_CLOSE_FORBIDDEN = 4403;

function backoffDelay(attempts: number): number {
  const exponential = Math.min(BASE_DELAY_MS * 2 ** attempts, MAX_DELAY_MS);
  return exponential / 2 + Math.random() * (exponential / 2);
}

/**
 * One shared operations-socket connection per dashboard session.
 *
 * Connects to the additive `/ws/operations` feed (cross-camera lifecycle
 * deltas + bus events; never frames/detections/tracking). Unknown or
 * malformed messages are ignored at the boundary; callers keep REST
 * polling as the authoritative fallback and re-baseline on reconnect.
 *
 * Resilience (V20): reconnects are bounded; once the budget is exhausted the
 * feed parks in `polling` (REST stays authoritative). A 4401 close clears the
 * session and triggers the global unauthorized redirect; a 4403 close stops
 * reconnecting (the caller lacks the scope) without treating it as a login
 * failure. Sockets are always released before a new one is opened.
 *
 * V16: when `getTicket` is provided, a fresh single-use ticket is
 * acquired before every (re)connect and sent as `?ticket=`. Pass a
 * stable (useCallback-memoized) getter to avoid reconnect churn.
 */
export function useOperationsSocket(
  enabled: boolean,
  wantedTypes: ReadonlySet<string> | null,
  onMessage: (message: OperationsWsMessage) => void,
  getTicket?: (scope: string) => Promise<string | null>
): OpsFeedStatus {
  const [feedStatus, setFeedStatus] = useState<OpsFeedStatus>("polling");

  useEffect(() => {
    if (!enabled) {
      setFeedStatus("disabled");
      return;
    }
    if (process.env.NEXT_PUBLIC_WS_ENABLED === "false") {
      setFeedStatus("polling");
      return;
    }
    let socket: WebSocket | null = null;
    let closed = false;
    let terminal = false;
    let attempts = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let visible = typeof document === "undefined" ? true : !document.hidden;

    const handleVisibility = () => {
      visible = !document.hidden;
      if (visible && !terminal && (socket === null || socket.readyState !== WebSocket.OPEN)) {
        connect();
      }
    };
    if (typeof document !== "undefined") {
      document.addEventListener("visibilitychange", handleVisibility);
    }

    const connect = () => {
      if (closed || terminal || typeof window === "undefined" || !visible) return;
      void connectAsync();
    };

    const connectAsync = async () => {
      if (closed || terminal || typeof window === "undefined" || !visible) return;
      // Release any previous socket before opening a replacement (no leak).
      if (socket) {
        try {
          socket.close();
        } catch {
          // Already gone.
        }
        socket = null;
      }
      const params = new URLSearchParams();
      if (wantedTypes && wantedTypes.size > 0) {
        params.set("event_types", Array.from(wantedTypes).join(","));
      }
      if (getTicket) {
        let ticket: string | null = null;
        try {
          ticket = await getTicket("operations");
        } catch {
          ticket = null;
        }
        if (closed || terminal || !visible) return;
        if (!ticket) {
          // No ticket (expired session, CSRF failure): back off and retry
          // rather than opening a socket the server must reject.
          setFeedStatus("reconnecting");
          schedule();
          return;
        }
        params.set("ticket", ticket);
      }
      const query = params.toString();
      let ws: WebSocket;
      try {
        ws = new WebSocket(`${appConfig.wsUrl}/ws/operations${query ? `?${query}` : ""}`);
      } catch {
        schedule();
        return;
      }
      socket = ws;
      ws.onopen = () => {
        attempts = 0;
        setFeedStatus("live");
      };
      ws.onmessage = (event: MessageEvent) => {
        if (typeof event.data !== "string") return;
        let data: OperationsWsMessage;
        try {
          data = JSON.parse(event.data) as OperationsWsMessage;
        } catch {
          return; // non-JSON frames ignored; REST keeps state fresh
        }
        if (!data || typeof data !== "object") return;
        const kind = String(data.type ?? data.event_type ?? "");
        if (wantedTypes && wantedTypes.size > 0 && !wantedTypes.has(kind)) return;
        onMessage(data);
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
      timer = setTimeout(connect, backoffDelay(attempts));
    };

    connect();
    return () => {
      closed = true;
      if (timer !== undefined) clearTimeout(timer);
      if (typeof document !== "undefined") {
        document.removeEventListener("visibilitychange", handleVisibility);
      }
      try {
        socket?.close();
      } catch {
        // Socket already gone; nothing to clean up.
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled]);

  return feedStatus;
}
