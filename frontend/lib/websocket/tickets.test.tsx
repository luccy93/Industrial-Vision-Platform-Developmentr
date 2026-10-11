import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { useOperationsSocket } from "./useOperationsSocket";

class MockSocket {
  static instances: MockSocket[] = [];
  url: string;
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onerror: (() => void) | null = null;
  onclose: (() => void) | null = null;
  readyState = 1;

  constructor(url: string) {
    this.url = url;
    MockSocket.instances.push(this);
  }

  close() {}
}

describe("useOperationsSocket tickets", () => {
  beforeEach(() => {
    MockSocket.instances = [];
    vi.stubGlobal("WebSocket", MockSocket);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("appends a fresh ticket to every connection", async () => {
    const getTicket = vi.fn(async (scope: string) => `${scope}-ticket-1`);
    const onMessage = vi.fn();
    renderHook(() => useOperationsSocket(true, null, onMessage, getTicket));
    await waitFor(() => {
      expect(MockSocket.instances.length).toBeGreaterThanOrEqual(1);
    });
    expect(MockSocket.instances[0].url).toContain("ticket=operations-ticket-1");
    expect(getTicket).toHaveBeenCalledWith("operations");
  });

  it("backs off without opening a socket when no ticket is available", async () => {
    const getTicket = vi.fn(async (_scope: string) => null);
    const onMessage = vi.fn();
    const { result } = renderHook(() => useOperationsSocket(true, null, onMessage, getTicket));
    await waitFor(() => {
      expect(getTicket).toHaveBeenCalled();
    });
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(MockSocket.instances).toHaveLength(0);
    expect(result.current).toBe("reconnecting");
  });
});
