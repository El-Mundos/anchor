#!/usr/bin/env bash
# Install anchor and take over one stack's secrets.
#
#   ./install.sh <stack> [stack-root]
#
# Run as root, on the host that runs the stack. It does NOT start or restart anything: it renders
# the file the stack needs in order to boot, and then stops. Bringing the stack up stays a
# deliberate act, and so does enabling the daemon.
#
# Expects, beside this script:
#   anchor                       the built binary (go build ./cmd/anchor)
#   local/config.yml             from config.example.yml
#   local/<stack>.anchor.yml     from anchor.example.yml
#
# and ONE thing the script cannot produce for you: a client secret for the stack's machine identity
# in Infisical. See README.md, "Installing".
set -euo pipefail

STACK="${1:-}"
STACK_ROOT="${2:-/srv/infra}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -z "$STACK" ]; then
  echo "usage: $0 <stack> [stack-root]" >&2
  exit 2
fi
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

DIR="$STACK_ROOT/$STACK"
IDENTITY="$DIR/anchor-identity.json"
CONFIG="$HERE/local/config.yml"
MANIFEST="$HERE/local/$STACK.anchor.yml"

for f in "$HERE/anchor" "$CONFIG" "$MANIFEST"; do
  [ -r "$f" ] || { echo "FATAL: $f is missing or unreadable" >&2; exit 1; }
done
[ -d "$DIR" ] || { echo "FATAL: $DIR does not exist" >&2; exit 1; }

if [ ! -r "$IDENTITY" ]; then
  cat >&2 <<MSG
FATAL: $IDENTITY is missing.

Create it with a client secret for the EXISTING $STACK identity in Infisical
(Access Control -> Identities -> $STACK -> Universal Auth -> Create Client Secret).
Do not create a new identity: it would not carry the project permissions the
existing one already has.

  install -m 0600 -o root -g root /dev/null $IDENTITY
  cat > $IDENTITY <<'JSON'
  {"client_id": "...", "client_secret": "..."}
  JSON

Then run this script again.
MSG
  exit 1
fi

# 0600 root:root, in a directory that is typically deploy-owned and group-writable. These
# permissions are the only thing keeping the credential out of reach of anything that can write
# into that directory.
chown root:root "$IDENTITY"
chmod 0600 "$IDENTITY"

install -d -m 0755 /etc/anchor
install -m 0644 "$CONFIG" /etc/anchor/config.yml
install -m 0755 "$HERE/anchor" /usr/local/bin/anchor
install -m 0644 -o root -g root "$MANIFEST" "$DIR/anchor.yml"

# The watchdog is installed but not enabled, like everything else here. It is what notices anchor
# itself being down or crash-looping — anchor cannot report its own absence, and the unit is
# Restart=always precisely so it never enters a state systemd would complain about.
install -m 0755 "$HERE/anchor-watchdog.sh" /usr/local/bin/anchor-watchdog
install -m 0644 "$HERE/anchor-watchdog.service" /etc/systemd/system/
install -m 0644 "$HERE/anchor-watchdog.timer" /etc/systemd/system/

echo "== validating manifests (touches nothing) =="
/usr/local/bin/anchor check

echo
echo "== rendering $STACK's secrets =="
# render does not act on containers. The running stack is untouched; what changes is that a file
# now exists which lets it start again without the secret store being reachable.
/usr/local/bin/anchor render "$STACK"

echo
echo "== result =="
ls -l "$DIR/.env"
echo "keys rendered: $(grep -c '^[A-Z]' "$DIR/.env")"

cat <<MSG

Done. Nothing was restarted.

$STACK can now start from disk without Infisical being up. Next, when you want it:

  1. Verify compose is happy with the rendered file:
       cd $DIR && docker compose config --quiet
  2. Retire whatever used to write the secrets, once the file is proven in place.
  3. Install the daemon, for automatic rotation:
       install -m 0644 $HERE/anchor.service /etc/systemd/system/
       systemctl daemon-reload && systemctl enable --now anchor
  4. Enable the watchdog, so a dead or crash-looping anchor is not silent:
       systemctl enable --now anchor-watchdog.timer
MSG
