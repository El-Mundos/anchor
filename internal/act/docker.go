// Package act performs the effects a secret change implies.
//
// It is deliberately thin. Everything interesting — whether to act at all, on which services, and
// what a half-done action looks like — is decided in reconcile; this package only carries it out
// and reports honestly whether it worked.
package act

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

// Docker acts through the compose CLI, in the stack's own directory.
//
// NOTE ON BELAY: routing recreates through Belay would let a rotation inherit its health gate and
// automatic rollback, which is the stated design. It is not implemented because Belay currently
// exposes no machine API for it — its endpoints are HTML-form handlers behind the SSO guard, and
// they update IMAGES rather than recreating a container in place with new configuration. Wiring
// anchor to them would be both an authentication problem and the wrong operation. The Actor
// interface exists so a Belay implementation can replace this without touching reconcile.
type Docker struct {
	// Timeout bounds a single compose invocation. A compose command that hangs must not wedge the
	// reconcile loop for every other stack on the host.
	Timeout time.Duration
}

func (d *Docker) timeout() time.Duration {
	if d.Timeout > 0 {
		return d.Timeout
	}
	return 3 * time.Minute
}

// run executes compose in dir, returning combined output on failure.
//
// Output is included in the error because "exit status 1" tells nobody anything, and this error
// travels straight into an alert that someone will read without access to the terminal it came
// from.
func (d *Docker) run(ctx context.Context, dir string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, d.timeout())
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", append([]string{"compose"}, args...)...)
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("docker compose %v timed out after %s in %s: %s",
				args, d.timeout(), dir, out.String())
		}
		return fmt.Errorf("docker compose %v in %s: %w: %s", args, dir, err, out.String())
	}
	return nil
}

// Recreate replaces the container so it picks up the new environment.
//
// --force-recreate is the entire point: without it, compose sees an unchanged image and an
// unchanged config hash and does nothing at all, reporting success. The container would keep the
// environment it was created with and the rotation would appear to have worked.
//
// --no-deps confines the blast radius to the service that needs it. A rotation of one service's
// secret is not a reason to bounce its database.
func (d *Docker) Recreate(ctx context.Context, dir, service string) error {
	return d.run(ctx, dir, "up", "-d", "--force-recreate", "--no-deps", service)
}

// Reload signals the process and trusts it to re-read.
//
// Opt-in in the manifest for a reason worth repeating here: this reports success as long as the
// signal was DELIVERED. Whether the application acted on it is invisible from the outside, and a
// signal an application ignores looks exactly like one it honoured.
func (d *Docker) Reload(ctx context.Context, dir, service, signal string) error {
	if signal == "" {
		signal = "HUP"
	}
	return d.run(ctx, dir, "kill", "-s", signal, service)
}

// Stop stops the service after a revocation.
//
// Plain stop rather than down: down would take the whole project with it, including services whose
// secrets were never in question, and including the database. A revocation is a reason to stop what
// held the revoked credential, not to dismantle the stack around it.
func (d *Docker) Stop(ctx context.Context, dir, service string) error {
	return d.run(ctx, dir, "stop", service)
}
