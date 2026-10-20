import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useOperationsSocket } from "./useOperationsSocket";
import { useIntelligenceSocket } from "./useIntelligenceSocket";
import { UNAUTHORIZED_EVENT } from "../auth/session";

class MockSocket {
  static instances: MockSocket[] = [];
  url: string;
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onerror: (() => void) | null = null;
  onclose: ((event?: { code?: number }) => void) | null = null;
  closed = false;
  readyState = 1;

  constructor(url: string) {
    this.url = url;
    MockSocket.instances.push(this);
  }

  close() {
    this.closed = true;
  }

  open() {
    this.onopen?.();
  }

  serverClose(code?: number) {
    this.onclose?.(code === undefined ? undefined : { code });
  }

  static last(): MockSocket {
    return MockSocket.instances[MockSocket.instances.length - 1];
  }
}

function collectUnauthorized(): { events: string[]; stop: () => void } {
  const events: string[] = [];
  const handler = () => void events.push(UNAUTHORIZED_EVENT);
  window.addEventListener(UNAUTHORIZED_EVENT, handler);
  return { events, stop: () => window.removeEventListener(UNAUTHORIZED_EVENT, handler) };
}

describe("WebSocket resilience (V20)", () => {
  beforeEach(() => {
    MockSocket.instances = [];
    vi.stubGlobal("WebSocket", MockSocket);
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  describe("useOperationsSocket", () => {
    it("treats a 4401 close as terminal and signals unauthorized", () => {
      const watch = collectUnauthorized();
      const { result } = renderHook(() => useOperationsSocket(true, null, () => {}));
      act(() => MockSocket.last().open());
      act(() => MockSocket.last().serverClose(4401));
      expect(result.current).toBe("polling");
      expect(watch.events).toContain(UNAUTHORIZED_EVENT);
      const count = MockSocket.instances.length;
      act(() => vi.advanceTimersByTime(60000));
      expect(MockSocket.instances.length).toBe(count);
      watch.stop();
    });

    it("treats a 4403 close as terminal without signalling unauthorized", () => {
      const watch = collectUnauthorized();
      const { result } = renderHook(() => useOperationsSocket(true, null, () => {}));
      act(() => MockSocket.last().open());
      act(() => MockSocket.last().serverClose(4403));
      expect(result.current).toBe("polling");
      expect(watch.events).toHaveLength(0);
      const count = MockSocket.instances.length;
      act(() => vi.advanceTimersByTime(60000));
      expect(MockSocket.instances.length).toBe(count);
      watch.stop();
    });

    it("stops reconnecting after the bounded attempt budget", () => {
      const { result } = renderHook(() => useOperationsSocket(true, null, () => {}));
      for (let i = 0; i < 7; i += 1) {
        act(() => MockSocket.last().serverClose());
        act(() => vi.advanceTimersByTime(20000));
      }
      expect(result.current).toBe("polling");
      const count = MockSocket.instances.length;
      act(() => vi.advanceTimersByTime(120000));
      expect(MockSocket.instances.length).toBe(count);
    });
  });

  describe("useIntelligenceSocket", () => {
    it("treats a 4401 close as terminal and signals unauthorized", () => {
      const watch = collectUnauthorized();
      const { result } = renderHook(() => useIntelligenceSocket("cam-1", () => {}));
      act(() => MockSocket.last().open());
      expect(result.current).toBe("live");
      act(() => MockSocket.last().serverClose(4401));
      expect(result.current).toBe("polling");
      expect(watch.events).toContain(UNAUTHORIZED_EVENT);
      watch.stop();
    });

    it("opens a replacement after an ordinary close", () => {
      renderHook(() => useIntelligenceSocket("cam-1", () => {}));
      const first = MockSocket.instances[0];
      act(() => first.open());
      act(() => first.serverClose());
      act(() => vi.advanceTimersByTime(2000));
      expect(MockSocket.instances.length).toBeGreaterThanOrEqual(2);
      expect(MockSocket.last()).not.toBe(first);
    });
  });
});
