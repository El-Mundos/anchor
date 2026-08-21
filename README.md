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
```

Per-stack identities are deliberate: a leaked identity should expose one stack's secrets, not the
fleet's.

## Status

Early. Manifest parsing and rendering are implemented and tested; the Infisical client, the
reconcile loop, `on_change` actions and alerting are not yet written.
