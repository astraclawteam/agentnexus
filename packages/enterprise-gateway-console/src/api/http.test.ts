import { describe, expect, it } from "vitest";
import { HTTPError, readJSON } from "./http";

describe("readJSON", () => {
  it("throws a safe HTTPError with response details", async () => {
    await expect(
      readJSON(new Response(JSON.stringify({ error: "missing secret", code: "missing" }), { status: 400, headers: { "Content-Type": "application/json" } }))
    ).rejects.toMatchObject({
      name: "HTTPError",
      status: 400,
      code: "missing",
      safeMessage: "missing secret"
    });
  });

  it("can be narrowed with HTTPError", async () => {
    try {
      await readJSON(new Response("bad", { status: 503 }));
    } catch (error) {
      expect(error).toBeInstanceOf(HTTPError);
      expect((error as HTTPError).status).toBe(503);
    }
  });
});

