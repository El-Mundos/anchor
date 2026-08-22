#!/usr/bin/env bash
# Watch anchor itself, and say so in Alertmanager when it is not well.
#
# WHY THIS EXISTS, since next to systemd it looks redundant:
#
# anchor.service is Restart=always with StartLimitIntervalSec=0, so anchor restarts forever and
# never enters the failed state. That is deliberate — anchor is not a boot dependency for anything,
# and a transient problem should not permanently stop every stack getting its rotations. The cost is
# that a crash-looping anchor is completely invisible: systemd is content, the unit reports active,
# and nothing anywhere says rotations stopped happening an hour ago.
#
# Letting anchor enter `failed` instead would trade a silent failure for a louder but worse one:
# systemd would stop retrying, so a blip that would have healed itself becomes a permanent outage of
# the very thing whose job is keeping secrets current. So anchor keeps restarting forever, and
# something that is NOT anchor watches it.
#
# It has to be something else for the same reason a heartbeat needs a receiver: anchor cannot report
# that anchor is down. Absence is silence unless another process is looking for it.
set -uo pipefail

UNIT="${ANCHOR_UNIT:-anchor.service}"
STATE="${ANCHOR_WATCHDOG_STATE:-/run/anchor-watchdog.restarts}"
CONFIG="${ANCHOR_CONFIG:-/etc/anchor/config.yml}"

# Flapping threshold: restarts observed since the previous run. One restart is a deploy, a config
# change, or an operator. Several within a single interval is a loop.
FLAP_THRESHOLD="${ANCHOR_FLAP_THRESHOLD:-3}"

# The lease must outlive the timer's interval, or the alert expires between runs and the problem
# blinks in and out of Karma. Alertmanager shows alerts whose window covers now and has no notion of
# one being "firing", so staying visible means saying so again before the window closes. 15 minutes
# against a 5 minute timer leaves room for two missed runs.
LEASE_SECONDS="${ANCHOR_WATCHDOG_LEASE:-900}"

# Read the Alertmanager URL out of anchor's own config, so there is one place to set it. A watchdog
# holding its own copy of the address is a watchdog that goes on pointing at the old one.
URL="$(sed -n 's/^alertmanager_url:[[:space:]]*"\?\([^"]*\)"\?[[:space:]]*$/\1/p' "$CONFIG" 2>/dev/null | head -1)"

# fire <severity> <summary> <description>
fire() {
  if [ -z "$URL" ]; then
    # Say it where journald keeps it rather than exiting quietly, which would make an unconfigured
    # watchdog look exactly like a healthy one.
    echo "anchor-watchdog: $1: $2 — $3 (no alertmanager_url in $CONFIG)" >&2
    return
  fi
  # Labels match anchor's own convention so these group alongside it in Karma rather than landing in
  # a group of their own.
  jq -n --arg sev "$1" --arg sum "$2" --arg desc "$3" \
     --arg starts "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)" \
     --arg ends "$(date -u -d "+${LEASE_SECONDS} seconds" +%Y-%m-%dT%H:%M:%S.000Z)" \
     '[{labels:    {alertname:"(anchor) watchdog", stack:"-", severity:$sev, source:"anchor"},
        annotations:{summary:$sum, description:$desc},
        startsAt:$starts, endsAt:$ends}]' \
  | curl -sS --max-time 10 -X POST "$URL" -H 'Content-Type: application/json' --data-binary @- \
      >/dev/null || echo "anchor-watchdog: could not reach Alertmanager at $URL" >&2
}

active="$(systemctl is-active "$UNIT" 2>/dev/null)"
restarts="$(systemctl show "$UNIT" -p NRestarts --value 2>/dev/null)"
[ -n "$restarts" ] || restarts=0

previous=0
[ -r "$STATE" ] && previous="$(cat "$STATE" 2>/dev/null || echo 0)"
delta=$(( restarts - previous ))
# NRestarts resets on `systemctl reset-failed` and on reboot. A negative delta means one of those
# happened; treating it as a large negative number would quietly disable the flap check until the
# counter caught up again.
[ "$delta" -lt 0 ] && delta=0
printf '%s' "$restarts" > "$STATE"

if [ "$active" != "active" ]; then
  fire critical "anchor is not running" \
"systemctl is-active $UNIT reports '$active'. Nothing on this host is reconciling secrets. Rendered \
files are frozen at their last value, so stacks still start and keep running — but rotations are \
not being applied and a revocation would not be acted on. Check: journalctl -u $UNIT -n 50"
  exit 0
fi

if [ "$delta" -ge "$FLAP_THRESHOLD" ]; then
  fire critical "anchor is restarting repeatedly" \
"$delta restarts since the last check (NRestarts=$restarts). anchor is crash-looping, so \
reconciliation is not happening even though the unit reports active — which is why systemd is not \
reporting a problem. Check: journalctl -u $UNIT -n 50"
  exit 0
fi

# Healthy: send nothing at all. Alertmanager expires what stops being re-sent, so a recovery clears
# itself without an explicit resolve — and a resolve that got lost would leave a stale alert forever.
exit 0
