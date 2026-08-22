package act

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stubDocker puts a fake `docker` first on PATH and returns a function reading what it was called
// with.
//
// A stub on PATH rather than an injected exec function, because the thing worth pinning here IS the
// command line. A seam that let the test assert on arguments the real code never passes would prove
// nothing — the bug this package exists to prevent is a missing flag, and a missing flag is
// invisible unless the assertion is made against what actually reaches the process.
func stubDocker(t *testing.T, exitCode int, output string) func() []string {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "args")
	script := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" > " + log + "\n" +
		"printf 'cwd=%s\\n' \"$PWD\" >> " + log + "\n" +
		"echo " + output + "\n" +
		"exit " + itoa(exitCode) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() []string {
		b, err := os.ReadFile(log)
		if err != nil {
			t.Fatalf("docker was never invoked: %v", err)
		}
		return strings.Split(strings.TrimSpace(string(b)), "\n")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	return string(rune('0' + i))
}

func has(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

// The incident this prevents: a rotation that reports success and changes nothing.
//
// Without --force-recreate, compose sees an unchanged image and an unchanged config hash and does
// nothing at all, exiting 0. The container keeps the environment it was created with, so the new
// secret is rendered, the log says the rotation was applied, and the old credential stays live —
// which is precisely the shape of the incident that caused anchor to exist.
func TestRecreate_ForcesAndDoesNotTouchDependencies(t *testing.T) {
	args := stubDocker(t, 0, "ok")
	dir := t.TempDir()
	if err := (&Docker{}).Recreate(context.Background(), dir, "api"); err != nil {
		t.Fatal(err)
	}
	got := args()
	if !has(got, "--force-recreate") {
		t.Errorf("--force-recreate missing from %v; compose would no-op and report success", got)
	}
	if !has(got, "--no-deps") {
		t.Errorf("--no-deps missing from %v; rotating one secret would bounce the database", got)
	}
	if !has(got, "api") {
		t.Errorf("the service name is missing from %v", got)
	}
	if !has(got, "cwd="+dir) {
		t.Errorf("ran in the wrong directory: %v", got)
	}
}

// Stop, never down. Down takes the whole project with it — including the database, and including
// services whose secrets were never in question. A revocation is a reason to stop what held the
// credential, not to dismantle the stack around it.
func TestStop_DoesNotTakeTheProjectDown(t *testing.T) {
	args := stubDocker(t, 0, "ok")
	if err := (&Docker{}).Stop(context.Background(), t.TempDir(), "api"); err != nil {
		t.Fatal(err)
	}
	got := args()
	if has(got, "down") {
		t.Fatalf("used `down` for a revocation: %v", got)
	}
	if !has(got, "stop") {
		t.Errorf("expected `stop`, got %v", got)
	}
}

func TestReload_DefaultsToHUP(t *testing.T) {
	args := stubDocker(t, 0, "ok")
	if err := (&Docker{}).Reload(context.Background(), t.TempDir(), "api", ""); err != nil {
		t.Fatal(err)
	}
	got := args()
	if !has(got, "kill") || !has(got, "-s") || !has(got, "HUP") {
		t.Errorf("expected a kill -s HUP, got %v", got)
	}
}

// "exit status 1" tells nobody anything, and this error is going straight into an alert read by
// someone who does not have the terminal it came from.
func TestRun_PutsCommandOutputInTheError(t *testing.T) {
	stubDocker(t, 1, "no-such-service-frobnicate")
	err := (&Docker{}).Recreate(context.Background(), t.TempDir(), "api")
	if err == nil {
		t.Fatal("a non-zero exit must be an error")
	}
	if !strings.Contains(err.Error(), "frobnicate") {
		t.Errorf("compose's own output is missing from the error, leaving the alert unactionable: %v", err)
	}
}

// A compose command that hangs must not wedge the reconcile loop for every other stack on the host,
// and the resulting error has to say it was a timeout rather than looking like a compose failure.
func TestRun_TimesOutRatherThanHanging(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\nsleep 30\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	start := time.Now()
	err := (&Docker{Timeout: 100 * time.Millisecond}).Recreate(context.Background(), dir, "api")
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("took %s; the timeout is not being enforced", elapsed)
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("a timeout must say so, not look like a compose failure: %v", err)
	}
}
