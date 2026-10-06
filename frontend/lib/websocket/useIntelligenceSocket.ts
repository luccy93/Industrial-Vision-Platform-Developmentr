import { useEffect, useState } from "react";
import { appConfig } from "../config";

export type WsFeedStatus = "live" | "reconnecting" | "polling";

export type IntelligenceWsMessage =
  | { type: "intelligence_event"; camera_id: string; event: Record<string, unknown> }
  | { type: "risk_cluster"; camera_id: string; [key: string]: unknown }
  | { type: "risk_update"; camera_id: string; [key: string]: unknown };

const WANTED = new Set(["intelligence_event", "risk_cluster", "risk_update"]);

/**
 * Live intelligence feed with exponential-backoff reconnect. When WebSocket
 * streaming is disabled the hook stays in polling mode and the page relies
 * on REST refresh instead — callers always keep polling as a fallback.
 */
export function useIntelligenceSocket(
  cameraId: string | null,
  onMessage: (message: IntelligenceWsMessage) => void
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
    let attempts = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const connect = () => {
      if (closed || typeof window === "undefined") return;
      try {
        socket = new WebSocket(`${appConfig.wsUrl}/ws/cameras/${cameraId}`);
      } catch {
        schedule();
        return;
      }
      socket.onopen = () => {
        attempts = 0;
        setFeedStatus("live");
      };
      socket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data) as IntelligenceWsMessage;
          if (data && WANTED.has(data.type)) onMessage(data);
        } catch {
          // Ignore non-JSON frames; polling keeps state fresh.
        }
      };
      socket.onerror = () => {
        try {
          socket?.close();
        } catch {
          // Fall through to reconnect scheduling below.
        }
      };
      socket.onclose = () => {
        if (closed) return;
        setFeedStatus("reconnecting");
        schedule();
      };
    };
    const schedule = () => {
      attempts += 1;
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
