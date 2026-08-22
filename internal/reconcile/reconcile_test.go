package reconcile

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/El-Mundos/anchor/internal/manifest"
	"github.com/El-Mundos/anchor/internal/store"
)

// fakeActor records what was done, so a test can assert that NOTHING was — which is the assertion
// most of these cases actually care about.
type fakeActor struct {
	recreated, reloaded, stopped []string
	stopErr                      error
}

func (f *fakeActor) Recreate(_ context.Context, _, s string) error {
	f.recreated = append(f.recreated, s)
	return nil
}
func (f *fakeActor) Reload(_ context.Context, _, s, _ string) error {
	f.reloaded = append(f.reloaded, s)
	return nil
}
func (f *fakeActor) Stop(_ context.Context, _, s string) error {
	f.stopped = append(f.stopped, s)
	return f.stopErr
}

type fakeAlerter struct{ alerts []Alert }

func (f *fakeAlerter) Alert(_ context.Context, a Alert) error {
	f.alerts = append(f.alerts, a)
	return nil
}

func (f *fakeAlerter) sawSummary(substr string) bool {
	for _, a := range f.alerts {
		if len(substr) > 0 && contains(a.Summary, substr) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

const manifestBody = `
project: proj
identity_file: /dev/null
secrets:
  - key: NS_SESSION_SECRET
    as: SESSION_SECRET
  - key: NS_POSTGRES_PASSWORD
    as: POSTGRES_PASSWORD
    shared_state: true
services:
  - name: api
`

func setup(t *testing.T, body string) (*Reconciler, *store.Fake, *fakeActor, *fakeAlerter) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "anchor.yml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	fs := &store.Fake{
		Values_: map[string]string{"NS_SESSION_SECRET": "s3cret", "NS_POSTGRES_PASSWORD": "pgpass"},
		Metas: map[string]store.Meta{
			"NS_SESSION_SECRET":    {Version: 1, UpdatedAt: time.Unix(1000, 0)},
			"NS_POSTGRES_PASSWORD": {Version: 1, UpdatedAt: time.Unix(1000, 0)},
		},
	}
	actor, alerter := &fakeActor{}, &fakeAlerter{}
	return &Reconciler{
		Manifest: m, Store: fs, Actor: actor, Alerter: alerter,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, fs, actor, alerter
}

// The steady state is the common case, so it is the one that must not cost anything. If a poll
// fetches values when nothing moved, anchor is shipping secrets across the network every minute
// forever — invisible in behaviour, visible only in a packet capture.
func TestOnce_SteadyStateDoesNotFetchValuesOrAct(t *testing.T) {
	r, fs, actor, _ := setup(t, manifestBody)
	if _, err := r.Once(context.Background(), Pass{Force: true, NoAct: true}); err != nil { // seed the file
		t.Fatal(err)
	}
	before := fs.ValueCalls
	actor.recreated = nil

	out, err := r.Once(context.Background(), Pass{})
	if err != nil {
		t.Fatal(err)
	}
	if out != OutcomeUnchanged {
		t.Errorf("outcome = %q, want unchanged", out)
	}
	if fs.ValueCalls != before {
		t.Errorf("fetched values %d extra times in a steady state", fs.ValueCalls-before)
	}
	if len(actor.recreated) != 0 {
		t.Errorf("recreated %v on an unchanged poll", actor.recreated)
	}
}

// A purge, a wiped tmpfs or a first deploy all leave the store looking unchanged while the disk has
// nothing on it. Trusting the pre-check here would leave a stack unable to start, with anchor
// reporting that all is well.
func TestOnce_RendersWhenTheFileIsMissingEvenIfNothingMoved(t *testing.T) {
	r, _, _, _ := setup(t, manifestBody)
	ctx := context.Background()
	if _, err := r.Once(ctx, Pass{Force: true, NoAct: true}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(r.Manifest.Destination); err != nil {
		t.Fatal(err)
	}
	out, err := r.Once(ctx, Pass{})
	if err != nil {
		t.Fatal(err)
	}
	if out == OutcomeUnchanged {
		t.Fatal("reported unchanged while the destination did not exist")
	}
	if _, err := os.Stat(r.Manifest.Destination); err != nil {
		t.Fatalf("file was not restored: %v", err)
	}
}

// Stale beats absent: an unreachable store must leave the last-good file alone and touch nothing.
// The opposite behaviour puts Infisical on the boot path for every stack on the host.
func TestOnce_RidesOutAnUnreachableStoreAndKeepsTheFile(t *testing.T) {
	r, fs, actor, alerter := setup(t, manifestBody)
	ctx := context.Background()
	if _, err := r.Once(ctx, Pass{Force: true, NoAct: true}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(r.Manifest.Destination)
	if err != nil {
		t.Fatal(err)
	}

	fs.FailWith = &store.Error{Fault: store.FaultTransient, Op: "versions"}
	out, err := r.Once(ctx, Pass{})
	if err != nil {
		t.Fatalf("a transient failure must not surface as an error: %v", err)
	}
	if out != OutcomeRodeOut {
		t.Errorf("outcome = %q, want rode-out", out)
	}
	after, err := os.ReadFile(r.Manifest.Destination)
	if err != nil || string(after) != string(before) {
		t.Error("the last-good file was disturbed by an outage")
	}
	if len(actor.stopped)+len(actor.recreated) != 0 {
		t.Error("acted on a service during a store outage")
	}
	if len(alerter.alerts) != 0 {
		t.Error("paged on a single failed poll; only PERSISTENT staleness deserves that")
	}
}

// A revocation purges and stops — and the alert must go out FIRST, because the stop is the part
// that can fail.
func TestOnce_RevocationPurgesStopsAndAlerts(t *testing.T) {
	r, fs, actor, alerter := setup(t, manifestBody)
	ctx := context.Background()
	if _, err := r.Once(ctx, Pass{Force: true, NoAct: true}); err != nil {
		t.Fatal(err)
	}

	fs.FailWith = &store.Error{Fault: store.FaultIdentityRevoked, Op: "versions"}
	out, err := r.Once(ctx, Pass{})
	if err != nil {
		t.Fatal(err)
	}
	if out != OutcomePurged {
		t.Errorf("outcome = %q, want purged", out)
	}
	if _, statErr := os.Stat(r.Manifest.Destination); !os.IsNotExist(statErr) {
		t.Error("the rendered file survived a revocation")
	}
	if len(actor.stopped) != 1 || actor.stopped[0] != "api" {
		t.Errorf("stopped %v, want [api]", actor.stopped)
	}
	if !alerter.sawSummary("revoked") {
		t.Error("no alert mentioning the revocation")
	}
}

// The case the ordering exists for: if the stop fails, the service is STILL RUNNING with revoked
// secrets. An alert conditional on the stop succeeding would be missing exactly here.
func TestOnce_AlertsEvenWhenTheStopFails(t *testing.T) {
	r, fs, actor, alerter := setup(t, manifestBody)
	ctx := context.Background()
	if _, err := r.Once(ctx, Pass{Force: true, NoAct: true}); err != nil {
		t.Fatal(err)
	}
	actor.stopErr = os.ErrPermission
	fs.FailWith = &store.Error{Fault: store.FaultIdentityRevoked, Op: "versions"}

	out, err := r.Once(ctx, Pass{})
	if err == nil {
		t.Error("a failed stop must be reported to the caller")
	}
	if out != OutcomePurged {
		t.Errorf("outcome = %q, want purged", out)
	}
	if !alerter.sawSummary("revoked") || !alerter.sawSummary("could not stop") {
		t.Errorf("expected both a revocation alert and a failed-stop alert, got %v", alerter.alerts)
	}
}

// A service declared as surviving without its secrets keeps running; the file still goes.
func TestOnce_RevocationLeavesDeclaredServicesRunning(t *testing.T) {
	body := manifestBody + "    on_revoke: leave\n"
	r, fs, actor, _ := setup(t, body)
	ctx := context.Background()
	if _, err := r.Once(ctx, Pass{Force: true, NoAct: true}); err != nil {
		t.Fatal(err)
	}
	fs.FailWith = &store.Error{Fault: store.FaultIdentityRevoked, Op: "versions"}
	if _, err := r.Once(ctx, Pass{}); err != nil {
		t.Fatal(err)
	}
	if len(actor.stopped) != 0 {
		t.Errorf("stopped %v despite on_revoke: leave", actor.stopped)
	}
	if _, statErr := os.Stat(r.Manifest.Destination); !os.IsNotExist(statErr) {
		t.Error("on_revoke: leave must still purge the file; it only spares the process")
	}
}

// Rotating POSTGRES_PASSWORD in the store does not rotate it in Postgres, which only read it at
// initdb. Recreating the app would point it at a password the database has never heard of: an
// outage caused by a successful rotation.
func TestOnce_SharedStateIsRenderedButNeverActedOn(t *testing.T) {
	r, fs, actor, alerter := setup(t, manifestBody)
	ctx := context.Background()
	if _, err := r.Once(ctx, Pass{Force: true, NoAct: true}); err != nil {
		t.Fatal(err)
	}
	actor.recreated = nil

	fs.Metas["NS_POSTGRES_PASSWORD"] = store.Meta{Version: 2, UpdatedAt: time.Unix(2000, 0)}
	fs.Values_["NS_POSTGRES_PASSWORD"] = "rotated"

	out, err := r.Once(ctx, Pass{})
	if err != nil {
		t.Fatal(err)
	}
	if len(actor.recreated) != 0 {
		t.Fatalf("recreated %v for a shared-state rotation", actor.recreated)
	}
	if out != OutcomeHeld {
		t.Errorf("outcome = %q, want held", out)
	}
	if !alerter.sawSummary("shared-state") {
		t.Error("a shared-state change must be announced, not silently skipped")
	}
	// It must still be RENDERED — the file is the record of what the store holds.
	b, err := os.ReadFile(r.Manifest.Destination)
	if err != nil || !contains(string(b), "rotated") {
		t.Error("the shared-state value was not written to the file")
	}
}

// A shared-state secret rotating alongside an ordinary one must not freeze the ordinary one: the
// rule exists to prevent an outage, not to stop the stack getting its new session secret.
func TestOnce_MixedChangeStillActs(t *testing.T) {
	r, fs, actor, _ := setup(t, manifestBody)
	ctx := context.Background()
	if _, err := r.Once(ctx, Pass{Force: true, NoAct: true}); err != nil {
		t.Fatal(err)
	}
	actor.recreated = nil

	fs.Metas["NS_POSTGRES_PASSWORD"] = store.Meta{Version: 2, UpdatedAt: time.Unix(2000, 0)}
	fs.Metas["NS_SESSION_SECRET"] = store.Meta{Version: 2, UpdatedAt: time.Unix(2000, 0)}
	fs.Values_["NS_SESSION_SECRET"] = "new-session"

	out, err := r.Once(ctx, Pass{})
	if err != nil {
		t.Fatal(err)
	}
	if out != OutcomeActed || len(actor.recreated) != 1 {
		t.Errorf("outcome = %q, recreated = %v; want the ordinary secret applied", out, actor.recreated)
	}
}

// A version can be republished without the value changing. Acting on that would bounce a healthy
// container for nothing — which is why the hash, not the version, authorises an action.
func TestOnce_AVersionBumpWithIdenticalContentDoesNotAct(t *testing.T) {
	r, fs, actor, _ := setup(t, manifestBody)
	ctx := context.Background()
	if _, err := r.Once(ctx, Pass{Force: true, NoAct: true}); err != nil {
		t.Fatal(err)
	}
	actor.recreated = nil

	fs.Metas["NS_SESSION_SECRET"] = store.Meta{Version: 9, UpdatedAt: time.Unix(9000, 0)}
	// values deliberately unchanged

	out, err := r.Once(ctx, Pass{})
	if err != nil {
		t.Fatal(err)
	}
	if out != OutcomeUnchanged {
		t.Errorf("outcome = %q, want unchanged", out)
	}
	if len(actor.recreated) != 0 {
		t.Errorf("recreated %v for a republished but identical secret", actor.recreated)
	}
}

// All-or-nothing: a partial fetch must leave the previous file exactly as it was. Writing three of
// four secrets produces a file that looks complete and is not.
func TestOnce_IncompleteFetchLeavesThePreviousFileIntact(t *testing.T) {
	r, fs, actor, alerter := setup(t, manifestBody)
	ctx := context.Background()
	if _, err := r.Once(ctx, Pass{Force: true, NoAct: true}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(r.Manifest.Destination)
	if err != nil {
		t.Fatal(err)
	}

	fs.Metas["NS_SESSION_SECRET"] = store.Meta{Version: 2, UpdatedAt: time.Unix(2000, 0)}
	delete(fs.Values_, "NS_SESSION_SECRET") // the store answers, but incompletely

	out, err := r.Once(ctx, Pass{})
	if err == nil {
		t.Error("an incomplete set must be reported")
	}
	if out != OutcomeHeld {
		t.Errorf("outcome = %q, want held", out)
	}
	after, err := os.ReadFile(r.Manifest.Destination)
	if err != nil || string(after) != string(before) {
		t.Error("an incomplete fetch overwrote a good file")
	}
	if len(actor.recreated) != 0 {
		t.Error("acted on an incomplete render")
	}
	if !alerter.sawSummary("incomplete") {
		t.Error("no alert for an incomplete secret set")
	}
}

// A missing key is not a revocation: it is far more often a rename or a typo'd path, and destroying
// a working stack over a misspelling is not a trade anyone would choose.
func TestOnce_MissingKeyHoldsRatherThanPurging(t *testing.T) {
	r, fs, actor, alerter := setup(t, manifestBody)
	ctx := context.Background()
	if _, err := r.Once(ctx, Pass{Force: true, NoAct: true}); err != nil {
		t.Fatal(err)
	}
	fs.FailWith = &store.Error{Fault: store.FaultSecretMissing, Op: "versions"}

	out, err := r.Once(ctx, Pass{})
	if err != nil {
		t.Fatal(err)
	}
	if out != OutcomeHeld {
		t.Errorf("outcome = %q, want held", out)
	}
	if _, statErr := os.Stat(r.Manifest.Destination); statErr != nil {
		t.Error("a missing key purged the file; only a revocation may do that")
	}
	if len(actor.stopped) != 0 {
		t.Error("a missing key stopped a service; only a revocation may do that")
	}
	if !alerter.sawSummary("missing") {
		t.Error("a missing declared secret must alert")
	}
}

// The rendered file must use the manifest's names, not the store's. Getting this wrong produces a
// file whose keys the compose file does not recognise — and, with :? guards, a stack that will not
// start.
func TestOnce_RendersUnderTheRenamedKeys(t *testing.T) {
	r, _, _, _ := setup(t, manifestBody)
	if _, err := r.Once(context.Background(), Pass{Force: true, NoAct: true}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(r.Manifest.Destination)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(b), "SESSION_SECRET=s3cret") {
		t.Errorf("rendered file lacks the renamed key:\n%s", b)
	}
	if contains(string(b), "NS_SESSION_SECRET") {
		t.Errorf("rendered file leaked the store's namespaced key:\n%s", b)
	}
}

// The incident this prevents: a stack sits for a week running secrets anchor refused to apply, and
// Karma is empty the whole time.
//
// Alertmanager has no "firing" flag — it stores a window and shows what covers now — so an alert
// that stops being re-sent silently resolves. Every held condition here alerts exactly once, and
// the version pre-check then short-circuits every later pass to "unchanged", so nothing ever
// re-sends it. The alert has to be REMEMBERED, because it cannot be re-derived.
func TestOnce_HeldConditionsAreRememberedForResending(t *testing.T) {
	ctx := context.Background()

	t.Run("shared state", func(t *testing.T) {
		r, fs, _, _ := setup(t, manifestBody)
		if _, err := r.Once(ctx, Pass{Force: true, NoAct: true}); err != nil {
			t.Fatal(err)
		}
		fs.Metas["NS_POSTGRES_PASSWORD"] = store.Meta{Version: 2, UpdatedAt: time.Unix(2000, 0)}
		fs.Values_["NS_POSTGRES_PASSWORD"] = "rotated"
		if _, err := r.Once(ctx, Pass{}); err != nil {
			t.Fatal(err)
		}
		if len(r.Held()) != 1 {
			t.Fatalf("Held() = %v, want the shared-state condition", r.Held())
		}

		// The pass that matters: from the store's side everything is now in sync, so this returns
		// "unchanged" — and the condition must survive that, because it is still true.
		out, err := r.Once(ctx, Pass{})
		if err != nil {
			t.Fatal(err)
		}
		if out != OutcomeUnchanged {
			t.Fatalf("outcome = %q, want unchanged (the setup for this test is wrong)", out)
		}
		if len(r.Held()) != 1 {
			t.Error("the shared-state condition was forgotten on the next quiet poll; " +
				"Alertmanager would expire the alert while the database password is still unapplied")
		}
	})

	t.Run("incomplete set", func(t *testing.T) {
		r, fs, _, _ := setup(t, manifestBody)
		fs.Values_["NS_SESSION_SECRET"] = "" // empty is missing: it is what a blank interpolation writes
		if _, err := r.Once(ctx, Pass{Force: true, NoAct: true}); err == nil {
			t.Fatal("expected an incomplete-set error")
		}
		if len(r.Held()) != 1 {
			t.Fatalf("Held() = %v, want the incomplete condition", r.Held())
		}
	})

	t.Run("held alerts outlive the repeat interval", func(t *testing.T) {
		r, fs, _, _ := setup(t, manifestBody)
		if _, err := r.Once(ctx, Pass{Force: true, NoAct: true}); err != nil {
			t.Fatal(err)
		}
		fs.Metas["NS_POSTGRES_PASSWORD"] = store.Meta{Version: 2, UpdatedAt: time.Unix(2000, 0)}
		fs.Values_["NS_POSTGRES_PASSWORD"] = "rotated"
		if _, err := r.Once(ctx, Pass{}); err != nil {
			t.Fatal(err)
		}
		// A lease shorter than the daemon's repeat interval would leave a window in which a
		// still-true condition is invisible — the exact bug, reintroduced by a constant.
		for _, a := range r.Held() {
			if a.Lease < 30*time.Minute {
				t.Errorf("held alert %q has a %s lease, shorter than the daemon's repeat interval",
					a.Summary, a.Lease)
			}
		}
	})
}

// Releasing must be per-condition. An ordinary secret rotating is not evidence that the database
// password was ever applied, and clearing the lot would retract a warning that is still true.
func TestOnce_AnOrdinarySuccessDoesNotClearASharedStateHold(t *testing.T) {
	r, fs, _, _ := setup(t, manifestBody)
	ctx := context.Background()
	if _, err := r.Once(ctx, Pass{Force: true, NoAct: true}); err != nil {
		t.Fatal(err)
	}

	fs.Metas["NS_POSTGRES_PASSWORD"] = store.Meta{Version: 2, UpdatedAt: time.Unix(2000, 0)}
	fs.Values_["NS_POSTGRES_PASSWORD"] = "rotated"
	if _, err := r.Once(ctx, Pass{}); err != nil {
		t.Fatal(err)
	}
	if len(r.Held()) != 1 {
		t.Fatalf("Held() = %v, want the shared-state condition", r.Held())
	}

	// Now an ordinary secret rotates and is applied successfully.
	fs.Metas["NS_SESSION_SECRET"] = store.Meta{Version: 2, UpdatedAt: time.Unix(3000, 0)}
	fs.Values_["NS_SESSION_SECRET"] = "new-session"
	out, err := r.Once(ctx, Pass{})
	if err != nil {
		t.Fatal(err)
	}
	if out != OutcomeActed {
		t.Fatalf("outcome = %q, want acted", out)
	}
	if len(r.Held()) != 1 {
		t.Error("a successful unrelated rotation cleared the shared-state hold; the database " +
			"password is still unapplied and the only record of that is now gone")
	}
}

// The one hold anchor can prove is over: a render that gets all the way through.
func TestOnce_ASuccessfulRenderReleasesTheIncompleteHold(t *testing.T) {
	r, fs, _, _ := setup(t, manifestBody)
	ctx := context.Background()

	fs.Values_["NS_SESSION_SECRET"] = ""
	if _, err := r.Once(ctx, Pass{Force: true, NoAct: true}); err == nil {
		t.Fatal("expected an incomplete-set error")
	}
	if len(r.Held()) != 1 {
		t.Fatalf("Held() = %v, want the incomplete condition", r.Held())
	}

	// Somebody fills the secret in. The version moves, so an ordinary poll notices.
	fs.Values_["NS_SESSION_SECRET"] = "filled-in"
	fs.Metas["NS_SESSION_SECRET"] = store.Meta{Version: 2, UpdatedAt: time.Unix(2000, 0)}
	if _, err := r.Once(ctx, Pass{}); err != nil {
		t.Fatal(err)
	}
	if len(r.Held()) != 0 {
		t.Errorf("Held() = %v after a successful render; a fixed problem must clear itself",
			r.Held())
	}
}

// The incident this prevents, which actually happened on the first real install (2026-08-22):
// `anchor render` attempted to stop a production container.
//
// The identity file had the wrong client id, Infisical answered 401, anchor read that as a
// revocation and went down the purge-and-stop path — which never consulted NoAct at all. The stop
// only failed because the stack could not be interpolated without the very file anchor had not yet
// written. Nothing was harmed by design; it was luck.
func TestOnce_RenderNeverStopsContainersEvenOnRevocation(t *testing.T) {
	r, fs, actor, _ := setup(t, manifestBody)
	fs.FailWith = &store.Error{Fault: store.FaultIdentityRevoked, Op: "login", Status: 401}

	out, err := r.Once(context.Background(), Pass{Force: true, NoAct: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != OutcomePurged {
		t.Errorf("outcome = %q, want purged", out)
	}
	if len(actor.stopped) != 0 {
		t.Errorf("render stopped %v — a command called \"render\" must never touch a container",
			actor.stopped)
	}
}

// A revoked identity during the DAEMON's pass must still stop services: that is the whole point of
// the fault, and the test above must not be read as licence to skip it everywhere.
func TestOnce_TheDaemonStillStopsOnRevocation(t *testing.T) {
	r, fs, actor, _ := setup(t, manifestBody)
	fs.FailWith = &store.Error{Fault: store.FaultIdentityRevoked, Op: "login", Status: 401}

	if _, err := r.Once(context.Background(), Pass{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(actor.stopped) == 0 {
		t.Error("a revocation in the daemon must stop the service; otherwise the disowned secret " +
			"stays in use in the running container")
	}
}

// A wrong identity file must not be able to purge or stop anything. This is the bootstrap case: the
// stack is running fine and somebody is installing anchor beside it.
func TestOnce_ARejectedIdentityTouchesNothing(t *testing.T) {
	r, fs, actor, alerter := setup(t, manifestBody)
	// Give the stack a rendered file, as a running stack would have.
	if _, err := r.Once(context.Background(), Pass{Force: true, NoAct: true}); err != nil {
		t.Fatal(err)
	}
	fs.FailWith = &store.Error{Fault: store.FaultIdentityRejected, Op: "login", Status: 401}

	out, err := r.Once(context.Background(), Pass{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != OutcomeHeld {
		t.Errorf("outcome = %q, want held", out)
	}
	if len(actor.stopped) != 0 {
		t.Errorf("stopped %v for credentials that never worked", actor.stopped)
	}
	if _, statErr := os.Stat(r.Manifest.Destination); statErr != nil {
		t.Error("the rendered file was purged because an identity file was wrong; a running stack " +
			"would have lost its secrets over a typo")
	}
	if !alerter.sawSummary("identity file") {
		t.Error("a rejected identity must be alerted, or a broken install is silent")
	}
}

// The end-to-end version of the same incident: a stack with an existing .env must not be silently
// flattened to only the declared keys.
func TestOnce_RefusesToOverwriteAFileAnchorDidNotWrite(t *testing.T) {
	r, _, actor, alerter := setup(t, manifestBody)
	existing := "PORT=8080\nTZ=Europe/Madrid\nSESSION_SECRET=old\n"
	if err := os.WriteFile(r.Manifest.Destination, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := r.Once(context.Background(), Pass{Force: true, NoAct: true})
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if out != OutcomeHeld {
		t.Errorf("outcome = %q, want held", out)
	}
	b, readErr := os.ReadFile(r.Manifest.Destination)
	if readErr != nil || string(b) != existing {
		t.Errorf("the pre-existing file was modified; PORT and TZ would have been silently deleted "+
			"and compose would interpolate them to empty strings.\ngot: %q", string(b))
	}
	if len(actor.recreated) != 0 {
		t.Errorf("acted on services despite refusing to render: %v", actor.recreated)
	}
	if !alerter.sawSummary("did not write") {
		t.Error("a refusal to adopt must be alerted, not just returned as an error")
	}
}

// With adopt set, the operator has said they looked. anchor proceeds.
func TestOnce_AdoptTakesOverAnExistingFile(t *testing.T) {
	r, _, _, _ := setup(t, manifestBody+"adopt: true\n")
	if err := os.WriteFile(r.Manifest.Destination, []byte("PORT=8080\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := r.Once(context.Background(), Pass{Force: true, NoAct: true})
	if err != nil {
		t.Fatalf("adopt: true must permit the render: %v", err)
	}
	if out != OutcomeRendered {
		t.Errorf("outcome = %q, want rendered", out)
	}
	b, _ := os.ReadFile(r.Manifest.Destination)
	if !contains(string(b), "SESSION_SECRET") {
		t.Error("the file was not replaced with anchor's render")
	}
}
