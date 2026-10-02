# cordon

Give every user, team and agent its own workspace on disk, and make it
impossible for one to read another's files. One binary, no KVM, runs on a 1 GB
VPS.

Built for AI agent runtimes, where the model decides which file to open and you
need that decision to be checked by something the model cannot talk its way
past.

## See it refuse

One command. No daemon, no Docker, no configuration.

```
$ cordon demo

cordon demo
  root      /tmp/cordon-demo-72540
  owner a   demo/owner-a
  owner b   demo/owner-b   holds secret.md
  planted   a/peek and a/theirs, both symlinks into b

owner a reads its own file
  ok        notes.md -> /tmp/cordon-demo-72540/owners/demo/owner-a/notes.md

owner a cannot read owner b, nine ways
  refused   parent then sibling          path_escapes_workspace
  refused   many parents                 path_escapes_workspace
  refused   absolute path                absolute_path_rejected
  refused   symlink to their file        path_escapes_workspace
  refused   symlink to their directory   path_escapes_workspace
  refused   percent encoded              path_escapes_workspace
  refused   backslash separator          path_escapes_workspace
  refused   parent hidden mid path       path_escapes_workspace
  refused   nul byte smuggled in         path_escapes_workspace

9 of 9 attempts refused
```

Owner a has a symlink sitting in its own directory pointing straight at owner
b's file. It still cannot read it, because cordon resolves the path on the
filesystem first and judges where it actually landed. Checking the string is
what symlinks are for.

## Install

```sh
cargo install --git https://github.com/fajarhide/cordon
cordon serve
```

That is the whole install. A 1.2 MB static binary, six dependencies, no runtime and no container needed.

## Prove it on your own box

`cordon verify` fires the same attacks at a daemon you are already running, so
you do not have to take this README's word for anything.

```
$ cordon verify http://127.0.0.1:7777

ok   parent traversal         status 403, code path_escapes_workspace
ok   deep traversal           status 403, code path_escapes_workspace
ok   absolute path            status 400, code absolute_path_rejected
ok   percent encoded          status 403, code path_escapes_workspace
ok   backslash separator      status 403, code path_escapes_workspace
ok   dotdot owner             status 400, code invalid_owner
ok   separator in owner       status 400, code invalid_owner
ok   non ascii owner          status 400, code invalid_owner
ok   reach the token store    status 403, code path_escapes_workspace

all 9 checks passed
```

It exits non-zero on any failure, so it belongs in your deploy pipeline. A 403
with an empty body does not count as a pass: a check only passes on a 4xx that
carries a machine readable code.

## The cheapest way to adopt it

One endpoint. Ask before you open a file, and you are done.

```sh
$ curl -s -X POST localhost:7777/v1/resolve -H 'content-type: application/json' \
    -d '{"owner":["acme","budi"],"path":"notes.md"}'
{"exists":true,"resolved":"/var/lib/cordon/owners/acme/budi/notes.md"}

$ curl -s -X POST localhost:7777/v1/resolve -H 'content-type: application/json' \
    -d '{"owner":["acme","budi"],"path":"../ani/secret.md"}'
{"error":{"code":"path_escapes_workspace","detail":{"path":"../ani/secret.md"},
          "message":"the path resolves outside the owner workspace"}}
```

No job execution, no container, no change to how your code reads files. You get
a path back, or a refusal with a code you can branch on.

## Run a job and get its output back

```sh
$ curl -s -X POST localhost:7777/v1/run -H 'content-type: application/json' -d '{
    "owner":["acme","budi"],
    "entrypoint":"sh",
    "args":["-c","mkdir -p out; printf \"laporan selesai\" > out/report.txt; echo done"],
    "collect":["out/*"],
    "limits":{"wall_ms":5000,"memory_mb":128,"stdout_kb":64}
  }'
{"artifacts":[{"bytes":15,"path":"out/report.txt",
               "token":"art_ca0a49fb851175de1a08cb0dba96ddc2"}],
 "duration_ms":15,"exit_code":0,"stderr":"","stdout":"done\n","truncated":false}
```

Output comes back as a token, never a path:

```sh
$ curl -s localhost:7777/v1/artifact/art_ca0a49fb851175de1a08cb0dba96ddc2
laporan selesai
```

Present that same token as a different owner and it is gone, with a response
byte identical to one for a token that never existed, so the answer does not
confirm the token is real:

```sh
$ curl -s 'localhost:7777/v1/artifact/art_ca0a49fb851175de1a08cb0dba96ddc2?owner=acme/ani'
{"error":{"code":"artifact_not_found","message":"no such artifact"}}
```

## Wiring it into an agent runtime

The whole integration is one call in front of your file tool. The model picks
the path; cordon decides whether that path was allowed.

```ts
import { Cordon, CordonError } from "@cordon/client";

const cordon = new Cordon("http://127.0.0.1:7777");

// Your existing read_file tool, with one line in front of it.
async function readFile(session: Session, path: string) {
  try {
    const { resolved, exists } = await cordon.resolve(session.owner, path);
    if (!exists) return { error: "file not found" };
    return { content: await Bun.file(resolved).text() };
  } catch (e) {
    // The model asked for someone else's file. Tell it no and carry on; this
    // is a normal turn, not an incident.
    if (e instanceof CordonError) return { error: e.code };
    throw e;
  }
}
```

`session.owner` is whatever your tenancy already looks like: `["acme", "budi"]`,
`["org_42", "team_legal", "u_991"]`, a single `["u_991"]`. cordon does not care,
as long as it is the same array every turn for the same user.

## What is guaranteed, and what is not

The table a reader actually needs. It lists the gaps too, because a table of
only wins is a table nobody believes.

| | process backend | container backend |
| --- | --- | --- |
| one owner cannot read another's files | yes | yes |
| symlink out of the workspace refused | yes | yes |
| wall clock and output size capped | yes | yes |
| memory capped | `RLIMIT_AS`, advisory on macOS | yes, cgroup |
| filesystem outside the workspace | readable | no, read only root |
| network | **host network, wide open** | none by default |
| egress allowlist | **refused, cannot honour it** | host level, not port level |
| runs as root | as the daemon's user | no, uid 65534 |
| kernel level escape | shares the host kernel | shares the host kernel |

Two things to read twice. The **process backend has no network isolation**: it
is for code you wrote, on a box where that is already true. And the container
backend's **egress allowlist is host level**: a job allowed to reach
`db.internal:5432` can reach that host on any port. Both are v2 items and both
are stated here rather than left to be discovered.

cordon is not a hypervisor. It shares the host kernel either way. A kernel
level escape defeats it, and nothing in this README claims otherwise.

One more gap, in the ownership model rather than the sandbox. With
`inherit: true` an owner reaches the files sitting directly in its ancestors'
workspaces, and nothing deeper. The ownership tree is the directory tree, so
every subdirectory of `acme/legal` is or could become another owner, and
granting the subtree would grant the sibling. A team that needs a shared folder
tree is its own owner, or you `/v1/fork` the template into the member's
workspace.

## Which backend

**process**, the default. One process, cwd pinned to the workspace, scrubbed
environment, rlimits applied between fork and exec, its own session so a
timeout takes the children too. Runs on a 1 GB VPS with nothing installed.

**container**, `CORDON_BACKEND=container`. Needs Docker or podman's docker
alias. Never needs KVM or nested virtualisation. `--network none`,
`--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`,
`--pids-limit 128`, uid 65534, and a `noexec` tmpfs for scratch.

Pick by who wrote the code. Yours: process. The model's, or your customer's:
container.

If Docker is down, a container job answers 503 `backend_unavailable`. It never
silently falls back to the process backend, because that would hand a caller
weaker isolation than it asked for without telling it.

## API

| | |
| --- | --- |
| `GET /v1/health` | liveness |
| `POST /v1/resolve` | may this owner touch this path, and does it exist |
| `POST /v1/run` | run a job in the owner's workspace, collect its output |
| `GET /v1/artifact/{token}` | fetch one collected file by token |
| `POST /v1/fork` | copy a workspace to a new owner, never overwriting |

Every refusal is a 4xx carrying a stable `code`: `invalid_owner`,
`absolute_path_rejected`, `path_escapes_workspace`, `limit_exceeded`,
`backend_cannot_honour_request`, `backend_unavailable`, `artifact_not_found`,
`destination_exists`, `source_not_found`. Only a daemon fault is a 5xx.

## Configuration

| variable | default | |
| --- | --- | --- |
| `CORDON_ROOT` | `/var/lib/cordon` | where workspaces live |
| `CORDON_LISTEN` | `unix:/run/cordond.sock` | or `tcp:127.0.0.1:7777` |
| `CORDON_TOKEN` | unset | required for a non loopback listener |
| `CORDON_BACKEND` | `process` | or `container` |
| `CORDON_IMAGE` | `alpine:3.20` | the container backend's image |
| `CORDON_ARTIFACT_TTL` | `24h` | `s`, `m`, `h` or `d` |
| `CORDON_MAX_WALL_MS` | `60000` | ceiling a request may lower, never raise |
| `CORDON_MAX_MEMORY_MB` | `1024` | same |

The daemon refuses to start on a listener the network can reach with no token.
That is not a warning in a log, it is an exit.

## Footprint

Measured by `tests/footprint.rs`, which starts the release binary, sends it 50
requests and reads its RSS:

```
daemon RSS while serving: 4960 KB
test result: ok. 1 passed
```

The budget is 20 MB and it is a test, not a sentence.

## Status

v1. The guarantee has 85 tests behind it, and the four mutations that matter
were each confirmed to break the suite: forcing the path check to pass, skipping
the on-disk resolution, forcing ancestor reach on, and dropping the
nul/percent/backslash rejection.

Not verified yet: no container has actually been run. The container backend's
isolation policy is asserted at the argument level, with every flag under test,
but the two tests that need a live Docker skip on a machine without it. Treat
the container backend as unproven until it runs on your Linux host and
`cordon verify` passes there.

## Licence

The daemon is AGPL 3.0. Run it, embed it, put it behind your product: the
licence only asks that if you modify the daemon itself and offer it over a
network, you publish those modifications.

The clients under `clients/` are Apache 2.0, so linking one into a closed source
application needs nothing from you.
