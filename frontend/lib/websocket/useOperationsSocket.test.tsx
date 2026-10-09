import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useOperationsSocket } from "./useOperationsSocket";
import type { OperationsWsMessage } from "../../types";

type Handler = ((event: { data: string }) => void) | null;

class MockSocket {
  static instances: MockSocket[] = [];
  url: string;
  onopen: (() => void) | null = null;
  onmessage: Handler = null;
  onerror: (() => void) | null = null;
  onclose: (() => void) | null = null;
  closed = false;
  readyState = 1;

  constructor(url: string) {
    this.url = url;
    MockSocket.instances.push(this);
  }

  close() {
    this.closed = true;
  }

  serverOpen() {
    this.onopen?.();
  }

  serverMessage(payload: unknown) {
    this.onmessage?.({ data: typeof payload === "string" ? payload : JSON.stringify(payload) });
  }

  serverClose() {
    this.onclose?.();
  }
}

describe("useOperationsSocket", () => {
  beforeEach(() => {
    MockSocket.instances = [];
    vi.stubGlobal("WebSocket", MockSocket);
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("opens one shared connection to /ws/operations", () => {
    const onMessage = vi.fn();
    renderHook(() => useOperationsSocket(true, null, onMessage));
    expect(MockSocket.instances).toHaveLength(1);
    expect(MockSocket.instances[0].url).toContain("/ws/operations");
  });

  it("delivers wanted messages and ignores malformed frames", () => {
    const received: OperationsWsMessage[] = [];
    renderHook(() =>
      useOperationsSocket(true, new Set(["safety_event"]), (m) => void received.push(m))
    );
    const socket = MockSocket.instances[0];
    act(() => {
      socket.serverOpen();
    });
    act(() => {
      socket.serverMessage({ type: "safety_event", camera_id: "c" });
      socket.serverMessage("not-json{{{");
      socket.serverMessage({ type: "frame" });
    });
    expect(received).toHaveLength(1);
    expect(received[0]).toMatchObject({ type: "safety_event" });
  });

  it("reconnects with backoff and cleans up on unmount", () => {
    const onMessage = vi.fn();
    const { result, unmount } = renderHook(() => useOperationsSocket(true, null, onMessage));
    act(() => {
      MockSocket.instances[0].serverOpen();
    });
    expect(result.current).toBe("live");
    act(() => {
      MockSocket.instances[0].serverClose();
    });
    expect(result.current).toBe("reconnecting");
    act(() => {
      vi.advanceTimersByTime(2000);
    });
    expect(MockSocket.instances.length).toBeGreaterThanOrEqual(2);
    unmount();
    expect(MockSocket.instances.at(-1)?.closed).toBe(true);
  });

  it("stays polling when disabled or switched off", () => {
    const { result, rerender } = renderHook(
      ({ enabled }: { enabled: boolean }) => useOperationsSocket(enabled, null, () => {}),
      { initialProps: { enabled: true } }
    );
    rerender({ enabled: false });
    expect(result.current).toBe("disabled");
    expect(MockSocket.instances.length).toBeLessThanOrEqual(1);
  });
});
