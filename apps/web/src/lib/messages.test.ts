import { afterEach, describe, expect, it } from "vitest";
import { ApiError } from "./api.ts";
import { setLang } from "./i18n.ts";
import { durationText, endsIn, messageFor } from "./messages.ts";

afterEach(() => setLang("en", undefined));

describe("relative durations", () => {
  it("writes hours and minutes, and minutes alone under an hour", () => {
    expect(durationText(4320, "en")).toBe("1 h 12 min");
    expect(durationText(600, "en")).toBe("10 min");
    expect(durationText(30, "en")).toBe("under 1 min");
  });

  it("says Ended once the time has passed", () => {
    expect(endsIn(1000, 2000)).toBe("Ended");
    expect(endsIn(2000 + 4320, 2000)).toBe("in 1 h 12 min");
  });
});

describe("messages for API failures", () => {
  it("maps each kind to a sentence, and never shows the server's text", () => {
    expect(messageFor(new ApiError("forbidden", 403))).toBe("You don't have access to this.");
    expect(messageFor(new ApiError("rate-limited", 429))).toContain("Too many attempts");
    expect(messageFor(new ApiError("unavailable", 503))).toContain("00:00 UTC");
    expect(messageFor(new Error("secret body text"))).not.toContain("secret body text");
  });

  it("switches to Indonesian with the language choice", () => {
    setLang("id", undefined);
    expect(messageFor(new ApiError("forbidden", 403))).toBe("Kamu tidak punya akses ke ini.");
  });
});
