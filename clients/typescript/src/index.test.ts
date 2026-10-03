import { describe, expect, test } from "bun:test";
import { Cordon, CordonError } from "./index";

const ok = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

describe("Cordon", () => {
  test("resolve sends the owner, the path and an explicit inherit", async () => {
    let seen: { url: string; body: unknown } | undefined;
    const c = new Cordon("http://x", async (url, init) => {
      seen = { url, body: JSON.parse(String(init?.body)) };
      return ok({ resolved: "/w/a.md", exists: true });
    });

    const out = await c.resolve(["acme", "budi"], "a.md");

    expect(seen?.url).toBe("http://x/v1/resolve");
    expect(seen?.body).toEqual({ owner: ["acme", "budi"], path: "a.md", inherit: false });
    expect(out.resolved).toBe("/w/a.md");
    expect(out.exists).toBe(true);
  });

  test("a refusal becomes a typed error carrying the code and the status", async () => {
    const c = new Cordon("http://x", async () =>
      ok({ error: { code: "path_escapes_workspace", message: "no" } }, 403),
    );

    const err = await c.resolve(["acme", "budi"], "../ani/x").catch((e) => e);
    expect(err).toBeInstanceOf(CordonError);
    expect(err.code).toBe("path_escapes_workspace");
    expect(err.status).toBe(403);
    expect(err.message).toBe("no");
  });

  test("run returns artifacts and artifact fetches one by token", async () => {
    const calls: string[] = [];
    const c = new Cordon("http://x", async (url) => {
      calls.push(url);
      if (url.includes("/v1/run")) {
        return ok({
          exit_code: 0,
          stdout: "",
          stderr: "",
          truncated: false,
          duration_ms: 3,
          network: "none",
          artifacts: [{ token: "art_abc", path: "out/r.txt", bytes: 2 }],
        });
      }
      return new Response(new Uint8Array([104, 105]));
    });

    const res = await c.run({ owner: ["acme", "budi"], entrypoint: "true" });
    expect(res.artifacts[0].token).toBe("art_abc");

    const bytes = new Uint8Array(await c.artifact("art_abc", ["acme", "budi"]));
    expect([...bytes]).toEqual([104, 105]);
    expect(calls[1]).toBe("http://x/v1/artifact/art_abc?owner=acme%2Fbudi");
  });

  test("the owner is sent url encoded, so a segment cannot smuggle a separator", async () => {
    let seen = "";
    const c = new Cordon("http://x", async (url) => {
      seen = url;
      return new Response(new Uint8Array([1]));
    });
    await c.artifact("art_abc", ["acme", "legal", "budi"]);
    expect(seen).toBe("http://x/v1/artifact/art_abc?owner=acme%2Flegal%2Fbudi");
  });

  test("a non JSON error body still produces a CordonError, not a parse crash", async () => {
    const c = new Cordon("http://x", async () =>
      new Response("<html>502</html>", { status: 502 }),
    );
    const err = await c.resolve(["acme", "budi"], "a.md").catch((e) => e);
    expect(err).toBeInstanceOf(CordonError);
    expect(err.status).toBe(502);
  });

  test("a token is sent when one is configured", async () => {
    let headers: Headers | undefined;
    const c = new Cordon(
      "http://x",
      async (_u, init) => {
        headers = new Headers(init?.headers);
        return ok({ resolved: "/w", exists: false });
      },
      "s3cret",
    );
    await c.resolve(["a"], "b");
    expect(headers?.get("authorization")).toBe("Bearer s3cret");
  });

  test("no token means no authorization header", async () => {
    let headers: Headers | undefined;
    const c = new Cordon("http://x", async (_u, init) => {
      headers = new Headers(init?.headers);
      return ok({ resolved: "/w", exists: false });
    });
    await c.resolve(["a"], "b");
    expect(headers?.get("authorization")).toBeNull();
  });

  test("network and hosts go through as given", async () => {
    let body: any;
    const c = new Cordon("http://x", async (_u, init) => {
      body = JSON.parse(String(init?.body));
      return ok({ exit_code: 0, stdout: "", stderr: "", truncated: false,
                  duration_ms: 1, network: "open", artifacts: [] });
    });
    const res = await c.run({
      owner: ["acme", "budi"],
      entrypoint: "true",
      network: "open",
      hosts: { "litellm.internal": "10.0.0.5" },
    });
    expect(body.network).toBe("open");
    expect(body.hosts).toEqual({ "litellm.internal": "10.0.0.5" });
    // And the response says what it got, rather than echoing what was asked.
    expect(res.network).toBe("open");
  });

  test("fork passes both owners", async () => {
    let body: unknown;
    const c = new Cordon("http://x", async (_u, init) => {
      body = JSON.parse(String(init?.body));
      return ok({ forked: "acme/copy", skipped_links: 0 });
    });
    const out = await c.fork(["acme", "budi"], ["acme", "copy"]);
    expect(body).toEqual({ from: ["acme", "budi"], to: ["acme", "copy"] });
    expect(out.forked).toBe("acme/copy");
  });
});
