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

## Status

Working end to end, not yet deployed. Manifest, rendering, the Infisical client (with API version
negotiation and a version pre-check that keeps values off the wire in the steady state), the
reconcile loop, `on_change` actions and Alertmanager alerting are implemented and tested.

Two known gaps:

**Recreates do not yet route through Belay.** The design calls for it, so a rotation inherits Belay's
health gate and rollback. Belay currently exposes no machine API for a health-gated recreate — its
endpoints are form handlers behind SSO, and they update images rather than recreating in place with
new configuration. anchor recreates directly meanwhile, and says so at startup rather than letting
the difference pass unnoticed.

**Reload is unverified per application.** It reports success once the signal is delivered, which is
why it is opt-in and `recreate` is the default.
