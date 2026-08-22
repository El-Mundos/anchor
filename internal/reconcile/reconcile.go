// Package reconcile is the loop that keeps one stack's secrets current.
//
// It is written as a single idempotent pass (Once) with the daemon as a thin wrapper, because every
// interesting property is about what a pass does when something goes wrong — and a pass you can
// call once is a pass you can test exhaustively.
//
// The order of the three questions matters and is not interchangeable:
//
//  1. Has anything moved? (versions — cheap, no secret crosses the wire)
//  2. What are the values? (only if 1 says yes)
//  3. Is the file different? (content hash — the ONLY thing that authorises an action)
//
// A version can move without the value changing, so step 3 exists to stop a republished secret
// restarting a healthy container. And the hash is computed over the rendered bytes rather than the
// fetched values, so a change in how anchor formats a file is indistinguishable from a change in
// the secrets — which is why Dotenv output has to be deterministic.
package reconcile

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"time"

	"github.com/El-Mundos/anchor/internal/manifest"
	"github.com/El-Mundos/anchor/internal/render"
	"github.com/El-Mundos/anchor/internal/store"
)

// Outcome says what a pass did. Reported rather than inferred from logs, so a caller — a test, or
// `anchor render --now` deciding its exit code — can act on it.
type Outcome string

const (
	// OutcomeUnchanged: nothing moved, nothing written, nothing touched. The steady state.
	OutcomeUnchanged Outcome = "unchanged"
	// OutcomeRendered: the file changed, no service needed acting on.
	OutcomeRendered Outcome = "rendered"
	// OutcomeActed: the file changed and services were recreated or reloaded.
	OutcomeActed Outcome = "acted"
	// OutcomeRodeOut: the store could not answer; the last-good file stands. NOT a failure.
	OutcomeRodeOut Outcome = "rode-out"
	// OutcomePurged: the identity was revoked; the file is gone and services were dealt with.
	OutcomePurged Outcome = "purged"
	// OutcomeHeld: something is wrong that anchor will not act on — a missing key, an
	// unintelligible store, or a change confined to shared state. The file is left as it is.
	OutcomeHeld Outcome = "held"
)

// Actor performs the effects. An interface because the two implementations differ in a way that
// matters — a recreate through Belay inherits a health gate and a rollback, a direct one does not —
// and because tests must be able to assert that nothing was touched.
type Actor interface {
	Recreate(ctx context.Context, dir, service string) error
	Reload(ctx context.Context, dir, service, signal string) error
	Stop(ctx context.Context, dir, service string) error
}

// Alerter delivers an alert. Errors are logged and swallowed by the caller: failing to alert must
// never stop anchor doing the thing it was alerting about.
type Alerter interface {
	Alert(ctx context.Context, a Alert) error
}

// Alert is one thing a human needs to know.
type Alert struct {
	Stack    string
	Summary  string
	Detail   string
	Severity string // "warning" | "critical"

	// Lease is how long this alert should stay visible without being re-sent. Zero means the
	// delivery default. It belongs on the alert rather than the alerter because it is a property of
	// the CONDITION: one anchor re-checks every poll should expire quickly so a fix shows up
	// quickly, while one that persists until somebody does maintenance must outlive the gap
	// between re-sends or it will look resolved when it is not.
	Lease time.Duration
}

// Reconciler keeps one stack in step with the store.
type Reconciler struct {
	Manifest *manifest.Manifest
	Store    store.Store
	Actor    Actor
	Alerter  Alerter
	Log      *slog.Logger

	// HeldLease is how long a held alert stays visible without being re-sent. The daemon re-sends
	// well inside it. Zero means DefaultHeldLease.
	HeldLease time.Duration

	// lastVersions is the pre-check baseline. In-memory only: on restart anchor re-fetches once,
	// which is cheap and correct, whereas persisting it would mean trusting a cache across a
	// process that may have died halfway through writing a file.
	lastVersions map[string]store.Meta

	// held are the conditions anchor has deliberately declined to resolve, keyed by reason.
	//
	// This exists because the version pre-check severs the path back to the alert. A stack whose
	// secrets are incomplete, or whose shared state moved, alerts once — and on the next pass the
	// versions match the baseline, the pass short-circuits to "unchanged", and the alert is never
	// sent again. Five minutes later Alertmanager expires it and the stack is left running secrets
	// anchor has explicitly refused to apply, with no trace anywhere.
	//
	// So these alerts are remembered rather than re-derived, and the daemon re-sends them.
	held map[reason]Alert
}

// reason identifies a held condition, so that resolving one does not silently clear another.
type reason string

const (
	// heldIncomplete: the store answered but the set was not renderable. anchor CAN observe this
	// clearing — a later pass that renders successfully proves it — so it is released.
	heldIncomplete reason = "incomplete"
	// heldSharedState: shared state moved and was not applied. anchor can NEVER observe this
	// clearing. The store considers the key current, so every later poll reports no change; the
	// condition ends when a human performs the coordinated rotation, which is invisible from here.
	heldSharedState reason = "shared-state"
	// heldDrift: a service declares on_change: none, so the file is ahead of the process. Also
	// invisible to anchor, since it never recreates that service and so never learns it caught up.
	heldDrift reason = "drift"
)

// DefaultHeldLease is how long a held alert survives without renewal. Comfortably longer than the
// interval at which the daemon re-sends, so failing to deliver one re-send does not make the
// condition disappear.
const DefaultHeldLease = time.Hour

// Held returns every condition this stack is currently held on.
//
// Exported so the daemon can re-send them. The Reconciler cannot do that itself: it only knows
// about a single pass, and "how often to repeat myself" is a question about time between passes.
func (r *Reconciler) Held() []Alert {
	out := make([]Alert, 0, len(r.held))
	for _, a := range r.held {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Summary < out[j].Summary })
	return out
}

// hold records a condition that will not clear on its own, and alerts about it now.
func (r *Reconciler) hold(ctx context.Context, why reason, a Alert) {
	if a.Lease == 0 {
		a.Lease = r.HeldLease
		if a.Lease == 0 {
			a.Lease = DefaultHeldLease
		}
	}
	if r.held == nil {
		r.held = map[reason]Alert{}
	}
	r.held[why] = a
	r.alert(ctx, a)
}

// release clears one held condition, by reason.
//
// Keyed rather than wholesale because the conditions are not equivalent. Clearing everything on a
// successful render would let an ordinary secret rotation silently retract a shared-state warning
// that is still true — the database password would still be unapplied, and the one record of that
// would be gone. Only heldIncomplete is ever released this way; the other two persist until anchor
// restarts, which is the operator's way of saying the maintenance is done.
func (r *Reconciler) release(why reason) { delete(r.held, why) }

// Pass configures a single reconciliation pass.
type Pass struct {
	// Force fetches unconditionally instead of trusting the version pre-check. Used by `anchor
	// render`, where the point is to produce a file for a stack that has never had one — and where
	// the pre-check would correctly conclude "nothing has moved" and leave the disk empty.
	Force bool

	// NoAct renders but touches no container.
	//
	// This is what `anchor render` uses, and the distinction is not cosmetic: rendering a file is
	// safe on a running host, while recreating containers is not something anyone should get from a
	// command called "render". It also makes the first-run order sane — write the file, let the
	// operator start the stack — rather than anchor deciding to bring services up by itself.
	NoAct bool
}

// Once performs a single reconciliation pass.
func (r *Reconciler) Once(ctx context.Context, p Pass) (Outcome, error) {
	m := r.Manifest
	stack := m.Stack()

	// 1. Cheap pre-check.
	changedKeys, skip, err := r.moved(ctx, p.Force)
	if err != nil {
		return r.fault(ctx, p, err)
	}
	if skip {
		return OutcomeUnchanged, nil
	}

	// 2. Values, only now.
	values, err := r.Store.Values(ctx, m.Keys())
	if err != nil {
		return r.fault(ctx, p, err)
	}

	// 3. Merge into whatever is already on disk, and compare.
	//
	// Read first, because anchor edits its own keys rather than owning the file. A read error other
	// than "not there" is treated as an empty file only after being surfaced — silently starting
	// from scratch would delete the very lines this exists to keep.
	existing, readErr := os.ReadFile(m.Destination)
	if readErr != nil && !os.IsNotExist(readErr) {
		return OutcomeHeld, fmt.Errorf("reading %s: %w", m.Destination, readErr)
	}
	wanted := m.Rename(values)
	content, err := render.Merge(existing, wanted, m.Names())
	if err != nil {
		// Incomplete: all-or-nothing refuses, and the previous file stands. This is a hold rather
		// than a failure precisely because the old file is still serving.
		//
		// Held rather than merely alerted: the store is answering perfectly well, so the next poll
		// sees unchanged versions and says nothing. Without a remembered alert, "your stack is
		// running on secrets I refused to update" would be a single message that expired.
		r.hold(ctx, heldIncomplete, Alert{Stack: stack, Severity: "critical",
			Summary: "refused to render an incomplete secret set",
			Detail:  err.Error()})
		return OutcomeHeld, err
	}

	// Whether OUR keys moved, decided before the write and independently of the file as a whole.
	//
	// These are two different questions and were previously one. The file can change without any
	// managed value changing — somebody edits PORT, or a first merge tidies formatting — and acting
	// on that would recreate a container because of an edit anchor had nothing to do with.
	previous := render.Parse(existing)
	managedChanged := false
	for _, n := range m.Names() {
		if old, had := previous[n]; !had || old != wanted[n] {
			managedChanged = true
			break
		}
	}

	if _, err := render.Write(m.Destination, content, 0o600); err != nil {
		return OutcomeHeld, err
	}
	if !managedChanged {
		// The store moved but our values did not — a republished secret with an unchanged value.
		// Acting here would restart a healthy container for nothing.
		r.Log.Debug("versions moved but the managed values are identical", "stack", stack)
		return OutcomeUnchanged, nil
	}
	// A render got all the way through, which is the one held condition anchor can prove is over.
	r.release(heldIncomplete)
	r.Log.Info("rendered", "stack", stack, "file", m.Destination, "hash", render.Hash(content)[:12])

	if p.NoAct {
		return OutcomeRendered, nil
	}

	// 4. Act — but not on shared state.
	return r.act(ctx, changedKeys)
}

// moved runs the version pre-check, returning the keys whose versions changed.
//
// It reports skip=true only when it is certain nothing needs doing, and treats a missing file as a
// reason to render regardless of versions: a purge, a wiped tmpfs or a first deployment all leave
// the store looking unchanged while the disk has nothing on it.
func (r *Reconciler) moved(ctx context.Context, force bool) (changed []string, skip bool, err error) {
	m := r.Manifest

	// Versions are fetched even when forcing. They cost nothing (no secret crosses the wire) and
	// seeding the baseline here is what makes the NEXT pass a real steady state — without it, the
	// pass after a forced render has no baseline, concludes everything changed, and re-fetches every
	// value. That was invisible except as traffic, and it also made a shared-state-only rotation
	// look like a general one, which would have recreated a container the rule exists to protect.
	metas, err := r.Store.Versions(ctx, m.Keys())
	if err != nil {
		return nil, false, err
	}
	previous := r.lastVersions
	r.lastVersions = metas

	if force {
		return m.Keys(), false, nil
	}
	if _, statErr := os.Stat(m.Destination); statErr != nil {
		// No file. Whatever the versions say, there is nothing on disk for a container to read.
		return m.Keys(), false, nil
	}
	if previous == nil {
		// First pass of this process: no baseline, so we cannot claim nothing moved.
		return m.Keys(), false, nil
	}
	for k, meta := range metas {
		prev, seen := previous[k]
		if !seen || prev.Version != meta.Version || !prev.UpdatedAt.Equal(meta.UpdatedAt) {
			changed = append(changed, k)
		}
	}
	return changed, len(changed) == 0, nil
}

// act applies on_change to each declared service, unless the only thing that moved is shared state.
func (r *Reconciler) act(ctx context.Context, changedKeys []string) (Outcome, error) {
	m := r.Manifest
	stack := m.Stack()

	if onlyShared(m, changedKeys) {
		// The store's copy of a database password is a mirror of state inside the database, which
		// only read it at initialisation. Recreating the app now would point it at a password the
		// database has never heard of: an outage caused by a successful rotation.
		r.Log.Warn("shared-state secrets changed; rendered but NOT acted on",
			"stack", stack, "keys", changedKeys)
		// Held indefinitely. Nothing anchor can see will ever clear this: the store now considers
		// the key current, so every later poll reports no change at all. The condition ends when a
		// human performs the coordinated rotation, and the way to tell anchor that is to restart
		// it — which is also when it would re-read the world anyway.
		r.hold(ctx, heldSharedState, Alert{Stack: stack, Severity: "warning",
			Summary: "shared-state secret changed and was not applied",
			Detail: fmt.Sprintf("%v changed in the store. The running system still uses the old "+
				"value; rotating these requires a coordinated procedure per system.", changedKeys)})
		return OutcomeHeld, nil
	}

	acted := false
	for _, sv := range m.Services {
		var err error
		switch sv.Action {
		case manifest.ActionNone:
			// Legal, but the file has now moved ahead of the process. Reported rather than ignored,
			// because invisible drift is how a stack ends up running secrets nobody can name.
			r.Log.Warn("secrets changed but on_change is none; rendered file is ahead of the "+
				"running process", "stack", stack, "service", sv.Name)
			r.hold(ctx, heldDrift, Alert{Stack: stack, Severity: "warning",
				Summary: "rendered secrets are ahead of the running service",
				Detail: fmt.Sprintf("service %s has on_change: none, so the rendered file has "+
					"moved ahead of the process. It will pick the new values up whenever "+
					"something next recreates it.", sv.Name)})
			continue
		case manifest.ActionReload:
			err = r.Actor.Reload(ctx, m.Dir, sv.Name, sv.Signal)
		case manifest.ActionRecreate:
			err = r.Actor.Recreate(ctx, m.Dir, sv.Name)
		}
		if err != nil {
			r.alert(ctx, Alert{Stack: stack, Severity: "critical",
				Summary: fmt.Sprintf("failed to apply new secrets to %s", sv.Name),
				Detail:  err.Error()})
			return OutcomeHeld, err
		}
		acted = true
	}
	if !acted {
		return OutcomeRendered, nil
	}
	return OutcomeActed, nil
}

// fault turns a store failure into the one behaviour that is right for it.
func (r *Reconciler) fault(ctx context.Context, p Pass, err error) (Outcome, error) {
	m := r.Manifest
	stack := m.Stack()

	var se *store.Error
	if !errors.As(err, &se) {
		return OutcomeHeld, err
	}

	switch se.Fault {
	case store.FaultTransient:
		// The whole point of stale-beats-absent. Not an alert on its own — a blip every so often is
		// normal, and paging on it would train everyone to ignore anchor. Staleness that PERSISTS
		// is what deserves an alert, and that is the daemon's job to notice, not this pass's.
		r.Log.Info("store unreachable; keeping last-good file", "stack", stack, "err", se)
		return OutcomeRodeOut, nil

	case store.FaultIdentityRevoked:
		return r.revoked(ctx, p, se)

	case store.FaultIdentityRejected:
		// Credentials that have never worked. Almost always a wrong identity file rather than a
		// revocation, so nothing is purged and nothing is stopped: an install with a typo in it must
		// not be able to take down a stack that is currently running perfectly well.
		r.Log.Error("identity refused and has never authenticated; treating as misconfiguration, "+
			"NOT a revocation", "stack", stack, "err", se)
		r.hold(ctx, heldIncomplete, Alert{Stack: stack, Severity: "critical",
			Summary: "identity file is not accepted by the secret store",
			Detail: fmt.Sprintf("%s. These credentials have never authenticated, so this is "+
				"being read as a wrong identity file rather than a revocation: nothing has been "+
				"purged and no service has been touched.", se)})
		return OutcomeHeld, nil

	case store.FaultSecretMissing:
		// Our identity works and a declared key is not there. The last-good file stands: this is far
		// more often a rename or a typo'd path than an intentional deletion, and destroying a
		// working stack over a misspelling is not a trade anyone would choose.
		r.Log.Error("declared secret missing from the store", "stack", stack, "err", se)
		r.alert(ctx, Alert{Stack: stack, Severity: "critical",
			Summary: "a declared secret is missing from the store",
			Detail:  se.Error()})
		return OutcomeHeld, nil

	default:
		r.Log.Error("unrecognised store failure", "stack", stack, "err", se)
		r.alert(ctx, Alert{Stack: stack, Severity: "critical",
			Summary: "unrecognised failure talking to the secret store",
			Detail:  se.Error()})
		return OutcomeHeld, nil
	}
}

// revoked purges and then deals with the running services.
//
// Order is deliberate: ALERT FIRST. The stop can fail — an unreachable daemon, a container wedged
// in removal, a hanging SIGTERM handler, a restart policy putting it straight back — and that is
// precisely the case where silence would be worst. An alert conditional on the action succeeding is
// an alert that is missing exactly when it matters.
func (r *Reconciler) revoked(ctx context.Context, p Pass, se *store.Error) (Outcome, error) {
	m := r.Manifest
	stack := m.Stack()

	r.Log.Error("identity revoked; removing this stack's secrets", "stack", stack, "err", se)
	r.alert(ctx, Alert{Stack: stack, Severity: "critical",
		Summary: "identity revoked — secrets removed and services stopping",
		Detail: fmt.Sprintf("%s. This stack's declared keys have been deleted from %s, so it will "+
			"NOT start until a working identity is restored. Any other variables in that file were "+
			"left alone.", se, m.Destination)})

	removed, err := render.RemoveKeys(m.Destination, m.Names())
	if err != nil {
		return OutcomeHeld, err
	}
	r.Log.Info("purge complete", "stack", stack, "keys-removed", removed)

	if p.NoAct {
		// `anchor render` must not stop containers, on this path least of all. Reaching a revocation
		// during a manual render is far more often an operator discovering a broken identity than a
		// real disownment, and a command named "render" that stops production services is not a
		// thing anyone should have to anticipate. The file is gone, which is the durable half of the
		// response; stopping is the daemon's job.
		r.Log.Warn("identity revoked, but this pass may not touch containers; "+
			"services left running", "stack", stack)
		return OutcomePurged, nil
	}

	var firstErr error
	for _, sv := range m.Services {
		if sv.Revoke == manifest.RevokeLeave {
			// Declared as useful without the secret. It keeps the environment it was created with,
			// so this defers the outage rather than avoiding it: the next recreate finds no file.
			r.Log.Warn("leaving service running with revoked secrets, as declared",
				"stack", stack, "service", sv.Name)
			continue
		}
		if err := r.Actor.Stop(ctx, m.Dir, sv.Name); err != nil {
			r.Log.Error("failed to stop service after revocation", "stack", stack,
				"service", sv.Name, "err", err)
			r.alert(ctx, Alert{Stack: stack, Severity: "critical",
				Summary: fmt.Sprintf("could not stop %s after a revocation", sv.Name),
				Detail: fmt.Sprintf("%v — the service is STILL RUNNING with secrets that have "+
					"been revoked", err)})
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return OutcomePurged, firstErr
}

// onlyShared reports whether every changed key is shared state.
//
// Mixed sets act: if a session secret and a database password rotate together, refusing to act
// would leave the session secret unapplied, and the shared-state rule exists to prevent an outage,
// not to freeze the stack.
func onlyShared(m *manifest.Manifest, changed []string) bool {
	if len(changed) == 0 {
		return false
	}
	shared := map[string]bool{}
	for _, k := range m.SharedStateKeys() {
		shared[k] = true
	}
	for _, k := range changed {
		if !shared[k] {
			return false
		}
	}
	return true
}

func (r *Reconciler) alert(ctx context.Context, a Alert) {
	if r.Alerter == nil {
		return
	}
	if err := r.Alerter.Alert(ctx, a); err != nil {
		// Swallowed on purpose: an alerting outage must not stop anchor doing the thing it was
		// trying to tell someone about.
		r.Log.Error("could not deliver alert", "stack", a.Stack, "summary", a.Summary, "err", err)
	}
}
