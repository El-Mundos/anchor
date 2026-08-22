# anchor

Keeps each Docker Compose stack's secrets current, from Infisical, without a deploy wrapper.

Belay catches the fall. anchor is what you're tied to.

## The problem it solves

A stack whose secrets are injected by a deploy script is correct only when that script is the thing
that started it. Anything else that recreates the container — an updater, a colleague, `docker
compose up -d`, a reboot that recreates rather than restarts — silently drops them.

The failure is quiet by construction. An unguarded `${A}.${B}` interpolates to `.`, the container
starts healthy, and the missing credential surfaces whenever it was next actually needed. Weeks,
usually.

anchor removes the wrapper from the path: secrets live in a file beside the compose file, kept
current by a controller that reconciles. Any caller then works, including the ones you didn't
anticipate.

## Design rules

These are not style preferences; each one is a failure that has happened.

**All or nothing.** A partial fetch is a failure. Rendering three of four secrets produces a file
that looks complete and is not. An empty value counts as missing, because empty is exactly what a
blank interpolation produces.

**Atomic writes.** Temporary file, `fsync`, rename — so a container starting mid-write reads either
the whole old file or the whole new one.

**Hashes, never timestamps.** Change is detected by comparing content hashes. `mtime` involves two
clocks, survives a restore-from-backup that replaced the content, and says nothing about what the
running container actually holds.

**Stale beats absent.** If the secret store is unreachable, keep the last good file. Containers boot
from last-known-good and converge when the store returns. This is what keeps the store off the boot
path — and avoids the circular dependency where the proxy that publishes your secret store needs
that store to start.

**A revocation is an answer, not an outage.** "The store is unreachable" and "the store says this
key is gone" are different, and only the first should be ridden out quietly.

**Half-done must be visible.** Every action is judged by what a partial success looks like:
`on_change: none` means the file has moved ahead of the process, so that gap is reported rather than
ignored; a `reload` the application silently ignores looks exactly like one it honoured, so reload
is opt-in and recreate is the default.

**Shared state is not rotatable.** A database password in the store is a copy of state inside the
database, which only reads it at initialisation. Rotating it there and recreating the app produces
an outage caused by a successful rotation. Those secrets are marked, rendered, and never acted on
automatically.

## Manifest

Lives beside the compose file it configures, so the declaration travels with the thing it describes.

```yaml
project: 6553ccb2b7da580d7f6e7260   # Infisical project id
env: prod
path: /
identity_file: /etc/anchor/traefik-edge.json   # this stack's own machine identity

render: env            # env -> .env beside the compose file | file -> a file the service reads
destination: .env

secrets:
  - key: IONOS_API_PREFIX
  - key: IONOS_API_SECRET
  - key: POSTGRES_PASSWORD
    shared_state: true   # rendered, but never acted on: rotating it here does not rotate the database

services:
  - name: traefik
    on_change: recreate  # none | reload (opt-in, needs signal) | recreate (default)
    on_revoke: stop      # stop (default) | leave — what to do if the identity is revoked
```

### A stack that already has a `.env`

anchor edits its own keys and leaves everything else alone. The manifest already says which keys are
anchor's, so it never needs to be told what it may touch — every other line in the file belongs to
somebody else and is preserved exactly.

This matters because a stack being migrated usually already has a `.env` holding more than secrets:
ports, hostnames, feature flags, a timezone. Rendering only the declared keys over the top of that
would delete the rest, and compose interpolates a missing variable to an **empty string** rather than
failing — so the container comes up healthy with a blank value in it. That is the incident anchor
exists to prevent, and reproducing it during a migration *to* anchor would be a poor joke.

Existing keys are updated where they stand, so the file keeps whatever order and grouping its author
gave it; newly declared ones are appended, sorted. Where a key is assigned twice, anchor rewrites the
**last** one and drops the earlier duplicates, because the last is the one compose uses.

Revocation follows the same rule: it deletes anchor's declared keys and nothing else. The stack still
refuses to start, because the `${VAR:?}` guards abort — which is the point — but configuration anchor
never supplied is not anchor's to destroy. If nothing but comments would remain, the file goes too.

An edit to a variable anchor does not manage will not recreate anything. "The file changed" and
"anchor's values changed" are separate questions, and only the second authorises an action.

`on_revoke` is a separate question from `on_change` because a revoked secret is not a changed one:
the right outcome may be an outage. A revocation purges the rendered file and, by default, stops the
service — a running container keeps the environment it was created with, so until it stops, the
secret you revoked is still in use. `leave` is for services that are genuinely useful without the
secret. There is no `restart`: the file is already gone, so a restart either crash-loops against a
guarded variable or comes back healthy with blank values.

Per-stack identities are deliberate: a leaked identity should expose one stack's secrets, not the
fleet's.

## Commands

```
anchor check            validate every manifest and exit; touches nothing
anchor render [stack]   render once, now, and exit — never touches containers
anchor run              reconcile continuously
```

`render` exists because a fresh stack has no file and the `${VAR:?}` guards mean it cannot start
without one. It deliberately does not act on containers: rendering a file is safe on a running host,
and nobody should get a restart from a command called "render".

## Installing

`deploy/` holds everything needed to put anchor on a host. Nothing in it starts or restarts a
service: it renders the file a stack needs in order to boot, and stops there.

```
deploy/
  anchor.service        systemd unit for the daemon
  config.example.yml    host-wide settings -> /etc/anchor/config.yml
  anchor.example.yml    a worked stack manifest -> <root>/<stack>/anchor.yml
  install.sh            ./install.sh <stack> [stack-root], run as root on the host
  anchor-watchdog.*     timer + script that notices anchor itself being down
  local/                your filled-in copies. NOT tracked.
```

The split exists because the two halves have different audiences. The examples are documentation
and belong in the repo; a filled-in manifest names your Infisical project, your host paths and every
secret a stack uses, so it stays out.

```sh
go build -o deploy/anchor ./cmd/anchor
mkdir -p deploy/local
cp deploy/config.example.yml  deploy/local/config.yml
cp deploy/anchor.example.yml  deploy/local/<stack>.anchor.yml
# edit both, copy deploy/ to the host, then:
sudo ./install.sh <stack>
```

### The one thing install.sh cannot do for you

Each stack authenticates with its own Infisical **machine identity**, and the client secret can only
be minted by a human. In Infisical: **Access Control -> Identities -> _your stack_ -> Universal Auth
-> Create Client Secret**. Use the identity that already exists rather than making a new one, or it
will not carry the project permissions the old one has.

That gives you two values, which go in a JSON file at the `identity_file` path from the manifest:

```json
{"client_id": "...", "client_secret": "..."}
```

It must be `0600 root:root`. anchor refuses to start if either field is empty, rather than
discovering it at the first poll.

### Watching the watcher

anchor runs `Restart=always` with no start limit, so it restarts forever and never enters systemd's
failed state. That is deliberate: anchor is not a boot dependency for anything, and a transient
problem should not permanently stop every stack getting its rotations. The cost is that a
crash-looping anchor is invisible — systemd is content, the unit reports active, and nothing says
rotations stopped an hour ago.

Letting it fail instead would trade a silent failure for a louder but worse one, since systemd would
stop retrying. So `anchor-watchdog.timer` runs every five minutes and alerts if anchor is not active
or has restarted repeatedly since the last check. It has to be a separate process for the same
reason a heartbeat needs a receiver: anchor cannot report that anchor is down.

## Adding a new stack

anchor removes one class of failure completely: a stack can no longer start with blank or partially
rendered secrets. It does not remove every class. The list below is the difference between the two,
in the order it bites.

1. **Guard every interpolated variable in the compose file.** `${FOO}` becomes an empty string when
   `FOO` is missing — compose treats that as success. `${FOO:?...}` aborts instead. anchor guarantees
   it will never *write* a partial file, but it cannot help before the first render, or after a
   revocation deliberately removes the keys. Without the guard those cases are silent, and silence is
   the whole problem. This is the single most important item here.
2. **Give the stack its own Infisical identity**, and use the **Universal Auth Client ID** from the
   Universal Auth panel — not the identity's own ID, which is also a UUID and sits one panel away.
   Getting this wrong produces `401 Invalid credentials`, indistinguishable from a revocation on the
   wire. anchor treats a refusal before any successful login as a misconfiguration rather than a
   revocation for exactly this reason, so it will not act — but it will not work either.
3. **Put the stack one level under a configured root**: `<stack_root>/<name>/anchor.yml`, beside its
   compose file. Discovery does not recurse, on purpose.
4. **Mark shared state.** Any secret that is a *copy* of state living in another system — a database
   password the database only reads at initialisation — needs `shared_state: true`. anchor renders
   these and refuses to act on them, because applying one would point the app at a credential the
   other system has never heard of. Rotating them stays a manual, coordinated procedure.
5. **Run `anchor check`, then `anchor render <stack>`, then start the stack.** In that order. render
   never touches containers, so the first start remains a deliberate act.
6. **Decide `on_revoke` per service.** `stop` is the default and makes a revocation real. `leave` is
   for services that are genuinely useful without the secret — an edge proxy whose DNS API key only
   affects certificate *renewal* keeps serving traffic, and stopping it would be a worse outage than
   the one being defended against.

### What anchor still cannot tell you

**A well-formed but wrong value looks exactly like a correct one.** anchor verifies that every
declared secret is present and non-empty, never that it is *right*. Only the application using the
credential can determine that, and applications that use a credential lazily — a signing key touched
only at submission time, a DNS API key touched only at renewal — will look perfectly healthy for
weeks. That is precisely the shape of the incident that caused anchor to exist.

A health check does not close this gap; it widens the false assurance, since the process starts and
serves happily. If it matters for a given stack, the check has to *exercise* the credential: an SMTP
`AUTH` with no message, loading and decrypting a signing key without signing anything.

**A rotation that breaks the application is not currently detected.** anchor reports that compose
exited cleanly, which means the container was created, not that what is inside it works.

## Alerting

anchor posts to Alertmanager, which Karma renders with no further integration.

Worth knowing if you are reading the alerting code: Alertmanager has no concept of an alert that is
"firing". It stores each alert with a start and an end and shows the ones whose window covers now,
and an alert posted without `endsAt` is given `endsAt = now + resolve_timeout` — five minutes by
default. That default suits Prometheus, which re-evaluates rules every few seconds and so renews the
lease for free. anchor does not: re-deriving a condition costs an API round trip, so it sets `endsAt`
explicitly and picks a lease per condition.

Conditions anchor re-checks every poll get a short lease, so a fix clears quickly. Conditions only a
human can clear — shared state that moved, a service on `on_change: none` — are remembered and
re-sent every 30 minutes against a one hour lease, because the version pre-check means no later poll
would ever mention them again. Nothing is ever explicitly resolved: a resolve that got lost would
leave a stale alert forever.

## Status

Working end to end, not yet deployed. Manifest, rendering, the Infisical client (with API version
negotiation and a version pre-check that keeps values off the wire in the steady state), the
reconcile loop, `on_change` actions, Alertmanager alerting and the watchdog are implemented and
tested.

Two known gaps:

**A recreate is not health-gated.** anchor recreates a container and reports whether compose exited
cleanly — which says the container was created, not that the application inside it works. If a
rotated secret is wrong, the container comes back broken and anchor does not know. Note that a
rollback would not obviously help: the thing that changed is the rendered file, so recreating again
just reapplies it. The useful version of this is anchor checking the container's health after its own
recreate and holding, which does not require coupling anchor to anything else.

**Reload is unverified per application.** It reports success once the signal is delivered, which is
why it is opt-in and `recreate` is the default.
