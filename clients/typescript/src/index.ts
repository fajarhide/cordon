/**
 * The cordon client. It builds requests and reads answers, and holds no rule of
 * its own: a rule implemented twice is a rule that drifts, so every decision
 * about what a path means belongs to the daemon.
 *
 * Apache 2.0, unlike the AGPL daemon, so linking this into a closed source
 * application is fine.
 */

export class CordonError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "CordonError";
  }
}

export interface ResolveResult {
  resolved: string;
  exists: boolean;
}

export interface Artifact {
  token: string;
  path: string;
  bytes: number;
}

export interface RunResult {
  exit_code: number;
  stdout: string;
  stderr: string;
  truncated: boolean;
  duration_ms: number;
  /** What the job actually got, which is not always what it asked for. */
  network: "none" | "open";
  artifacts: Artifact[];
}

export interface RunRequest {
  owner: string[];
  entrypoint: string;
  args?: string[];
  stdin?: string;
  collect?: string[];
  inherit?: boolean;
  /**
   * "none" gives the job no network. "open" gives it the host's outbound
   * access: there is no packet filter in v1, so open means open. Absent lets
   * the backend use what it can provide, and `RunResult.network` says which.
   */
  network?: "none" | "open";
  /** Name to address pins, only with "open". A convenience, not a restriction. */
  hosts?: Record<string, string>;
  backend?: "process" | "container";
  limits?: { wall_ms: number; memory_mb: number; stdout_kb: number };
}

type Fetcher = (url: string, init?: RequestInit) => Promise<Response>;

export class Cordon {
  constructor(
    private readonly base: string,
    private readonly fetcher: Fetcher = fetch,
    private readonly token?: string,
  ) {}

  /** Call this before touching a file on an owner's behalf. */
  resolve(owner: string[], path: string, inherit = false): Promise<ResolveResult> {
    return this.post<ResolveResult>("/v1/resolve", { owner, path, inherit });
  }

  run(req: RunRequest): Promise<RunResult> {
    return this.post<RunResult>("/v1/run", req);
  }

  fork(from: string[], to: string[]): Promise<{ forked: string; skipped_links: number }> {
    return this.post("/v1/fork", { from, to });
  }

  /**
   * The owner is required. A token alone is not enough, deliberately: it is
   * bound to one owner on the daemon and omitting the owner used to skip the
   * check rather than fail it.
   */
  async artifact(token: string, owner: string[]): Promise<ArrayBuffer> {
    const q = encodeURIComponent(owner.join("/"));
    const res = await this.fetcher(`${this.base}/v1/artifact/${token}?owner=${q}`, {
      headers: this.headers(),
    });
    if (!res.ok) {
      throw new CordonError("artifact_not_found", "no such artifact", res.status);
    }
    return res.arrayBuffer();
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = { "content-type": "application/json" };
    if (this.token) h.authorization = `Bearer ${this.token}`;
    return h;
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const res = await this.fetcher(this.base + path, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(body),
    });

    // A gateway in front of the daemon can answer with HTML, so the body is
    // never assumed to be JSON.
    let parsed: unknown;
    try {
      parsed = await res.json();
    } catch {
      parsed = undefined;
    }
    if (!res.ok) {
      const e = (parsed as { error?: { code?: string; message?: string } } | undefined)?.error;
      throw new CordonError(e?.code ?? "unknown", e?.message ?? res.statusText, res.status);
    }
    return parsed as T;
  }
}
