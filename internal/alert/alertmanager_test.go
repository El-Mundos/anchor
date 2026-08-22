package alert

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/El-Mundos/anchor/internal/reconcile"
)

// capture stands up an Alertmanager that records the posted body.
func capture(t *testing.T, status int) (*Alertmanager, func() []amAlert) {
	t.Helper()
	var got []amAlert
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("undecodable body: %v", err)
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return &Alertmanager{URL: srv.URL}, func() []amAlert { return got }
}

func send(t *testing.T, a *Alertmanager, in reconcile.Alert) error {
	t.Helper()
	return a.Alert(context.Background(), in)
}

// The incident this prevents: an alert that quietly resolves itself while the problem is still
// there.
//
// Alertmanager has no "firing" flag. It stores a window and shows the alerts covering now, and an
// alert posted without endsAt gets endsAt = now + resolve_timeout — five minutes by default. anchor
// re-derives most conditions far less often than that, so leaving endsAt unset means the alert
// disappears long before anyone looks at Karma.
func TestAlert_SetsAnExplicitLease(t *testing.T) {
	am, got := capture(t, http.StatusOK)
	if err := send(t, am, reconcile.Alert{Stack: "kalos-cobra", Summary: "x", Lease: time.Hour}); err != nil {
		t.Fatal(err)
	}
	a := got()[0]
	if a.EndsAt.IsZero() {
		t.Fatal("endsAt was not set; Alertmanager will expire this in five minutes")
	}
	if lease := a.EndsAt.Sub(a.StartsAt); lease < 59*time.Minute || lease > 61*time.Minute {
		t.Errorf("lease = %s, want the requested hour", lease)
	}
}

func TestAlert_FallsBackToTheDefaultLease(t *testing.T) {
	am, got := capture(t, http.StatusOK)
	if err := send(t, am, reconcile.Alert{Stack: "s", Summary: "x"}); err != nil {
		t.Fatal(err)
	}
	a := got()[0]
	if lease := a.EndsAt.Sub(a.StartsAt); lease != DefaultLease {
		t.Errorf("lease = %s, want DefaultLease (%s)", lease, DefaultLease)
	}
}

// Alertmanager groups by label set. A single shared alertname would collapse every stack's problems
// into one group, so a second stack failing would join an existing group rather than appearing as
// news — which is the failure mode where you look at Karma, see one familiar alert, and move on.
func TestAlert_LabelsPerStackSoGroupsDoNotCollapse(t *testing.T) {
	am, got := capture(t, http.StatusOK)
	if err := send(t, am, reconcile.Alert{
		Stack: "kalos-cobra", Summary: "s", Detail: "d", Severity: "critical",
	}); err != nil {
		t.Fatal(err)
	}
	a := got()[0]
	if a.Labels["alertname"] != "(anchor) kalos-cobra" {
		t.Errorf("alertname = %q, want it to carry the stack", a.Labels["alertname"])
	}
	for k, want := range map[string]string{
		"stack": "kalos-cobra", "severity": "critical", "source": "anchor",
	} {
		if a.Labels[k] != want {
			t.Errorf("label %s = %q, want %q", k, a.Labels[k], want)
		}
	}
	if a.Annotations["summary"] != "s" || a.Annotations["description"] != "d" {
		t.Errorf("annotations lost the message: %v", a.Annotations)
	}
}

func TestAlert_DefaultsSeverityToWarning(t *testing.T) {
	am, got := capture(t, http.StatusOK)
	if err := send(t, am, reconcile.Alert{Stack: "s", Summary: "x"}); err != nil {
		t.Fatal(err)
	}
	if sev := got()[0].Labels["severity"]; sev != "warning" {
		t.Errorf("severity = %q, want warning — an unlabelled alert can be routed nowhere", sev)
	}
}

// An Alertmanager that rejects the post must not do so silently. reconcile logs and swallows this,
// but it can only do that if it is told.
func TestAlert_ReportsARejection(t *testing.T) {
	am, _ := capture(t, http.StatusBadRequest)
	if err := send(t, am, reconcile.Alert{Stack: "s", Summary: "x"}); err == nil {
		t.Error("a 400 from Alertmanager must be reported, not swallowed here")
	}
}

// No URL configured is a legitimate way to run — alerts degrade to log lines. It must not be an
// error, or every pass on an unconfigured host would look like a failure.
func TestAlert_NoURLIsNotAnError(t *testing.T) {
	if err := (&Alertmanager{}).Alert(context.Background(), reconcile.Alert{Summary: "x"}); err != nil {
		t.Errorf("an unconfigured alerter must be a no-op, got %v", err)
	}
}
