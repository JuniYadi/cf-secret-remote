import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  getPrivateKey,
  getPublicKey,
  getStatus,
  IDLE_LOCK_MS,
  lock,
  subscribeKeys,
  touch,
  unlock,
  watchActivity,
} from "./keystore.ts";

const KEYS = { publicKey: "PUB-TEST", privateKey: "PRIV-SECRET-TEST" };
const MINUTE = 60_000;

beforeEach(() => {
  vi.useFakeTimers();
  lock();
});

afterEach(() => {
  lock();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("key store (ADR 24)", () => {
  it("holds the unlocked key in memory only", () => {
    expect(getPrivateKey()).toBeNull();
    unlock(KEYS);
    expect(getPrivateKey()).toBe(KEYS.privateKey);
    expect(getPublicKey()).toBe(KEYS.publicKey);
    expect(getStatus()).toMatchObject({ unlocked: true, warning: false });
  });

  it("never writes the key to any browser storage", () => {
    const setItem = vi.fn();
    const storage = {
      getItem: vi.fn(),
      setItem,
      removeItem: vi.fn(),
      clear: vi.fn(),
      key: vi.fn(),
      length: 0,
    };
    vi.stubGlobal("localStorage", storage);
    vi.stubGlobal("sessionStorage", storage);
    unlock(KEYS);
    vi.advanceTimersByTime(14 * MINUTE);
    touch();
    lock();
    expect(setItem).not.toHaveBeenCalled();
  });

  it("lock() clears the key and the status", () => {
    unlock(KEYS);
    lock();
    expect(getPrivateKey()).toBeNull();
    expect(getPublicKey()).toBeNull();
    expect(getStatus()).toEqual({ unlocked: false, warning: false, lockAt: null });
  });

  it("notifies subscribers on unlock and lock", () => {
    const listener = vi.fn();
    const stop = subscribeKeys(listener);
    unlock(KEYS);
    lock();
    expect(listener).toHaveBeenCalledTimes(2);
    stop();
    unlock(KEYS);
    expect(listener).toHaveBeenCalledTimes(2);
  });
});

describe("idle auto-lock (ADR 24)", () => {
  it("shows the warning at 14 minutes idle", () => {
    unlock(KEYS);
    vi.advanceTimersByTime(14 * MINUTE - 1);
    expect(getStatus().warning).toBe(false);
    vi.advanceTimersByTime(1);
    expect(getStatus().warning).toBe(true);
    expect(getPrivateKey()).toBe(KEYS.privateKey);
  });

  it("locks and drops the key at 15 minutes idle", () => {
    unlock(KEYS);
    vi.advanceTimersByTime(IDLE_LOCK_MS - 1);
    expect(getPrivateKey()).toBe(KEYS.privateKey);
    vi.advanceTimersByTime(1);
    expect(getPrivateKey()).toBeNull();
    expect(getStatus()).toMatchObject({ unlocked: false, warning: false });
  });

  it("activity restarts the timer and hides the warning", () => {
    unlock(KEYS);
    vi.advanceTimersByTime(14 * MINUTE);
    expect(getStatus().warning).toBe(true);
    touch();
    expect(getStatus().warning).toBe(false);
    vi.advanceTimersByTime(10 * MINUTE);
    expect(getPrivateKey()).toBe(KEYS.privateKey);
    vi.advanceTimersByTime(5 * MINUTE);
    expect(getPrivateKey()).toBeNull();
  });

  it("activity before the warning pushes the warning back", () => {
    unlock(KEYS);
    vi.advanceTimersByTime(13 * MINUTE);
    touch();
    vi.advanceTimersByTime(13 * MINUTE);
    expect(getStatus().warning).toBe(false);
    expect(getPrivateKey()).toBe(KEYS.privateKey);
  });

  it("watchActivity counts DOM-style events as activity", () => {
    const target = new EventTarget();
    const stop = watchActivity(target);
    unlock(KEYS);
    vi.advanceTimersByTime(14 * MINUTE);
    expect(getStatus().warning).toBe(true);
    target.dispatchEvent(new Event("keydown"));
    expect(getStatus().warning).toBe(false);
    stop();
    vi.advanceTimersByTime(14 * MINUTE);
    expect(getStatus().warning).toBe(true);
  });

  it("does nothing when locked", () => {
    touch();
    expect(getStatus()).toEqual({ unlocked: false, warning: false, lockAt: null });
  });

  it("explicit lock cancels the pending timers", () => {
    unlock(KEYS);
    lock();
    unlock({ publicKey: "P2", privateKey: "K2" });
    vi.advanceTimersByTime(14 * MINUTE);
    // The second unlock starts its own timer. The first lock's timers must not fire on it.
    expect(getStatus().warning).toBe(true);
    expect(getPrivateKey()).toBe("K2");
    vi.advanceTimersByTime(MINUTE);
    expect(getPrivateKey()).toBeNull();
  });
});
