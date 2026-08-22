// Command anchor keeps each Compose stack's secrets current, from Infisical, without a deploy
// wrapper.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/El-Mundos/anchor/internal/act"
	"github.com/El-Mundos/anchor/internal/alert"
	"github.com/El-Mundos/anchor/internal/config"
	"github.com/El-Mundos/anchor/internal/manifest"
	"github.com/El-Mundos/anchor/internal/reconcile"
	"github.com/El-Mundos/anchor/internal/store"
)

const usage = `anchor — keeps Compose stacks' secrets current from Infisical

  anchor check            validate every manifest and exit; touches nothing
  anchor render [stack]   render once, now, and exit. Fetches unconditionally.
  anchor run              reconcile continuously

Flags:
  -config PATH            (default ` + config.DefaultPath + `)
`

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfgPath := flag.String("config", config.DefaultPath, "path to config.yml")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch cmd := flag.Arg(0); cmd {
	case "check":
		os.Exit(runCheck(cfg, log))
	case "render":
		os.Exit(runRender(ctx, cfg, log, flag.Arg(1)))
	case "run":
		os.Exit(runDaemon(ctx, cfg, log))
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		flag.Usage()
		os.Exit(2)
	}
}

// runCheck validates every manifest without talking to anything.
//
// Worth having as its own command: it is the difference between finding a typo now and finding it
// during a rotation, and it is safe to run on a production host at any time.
func runCheck(cfg *config.Config, log *slog.Logger) int {
	paths, err := cfg.Discover()
	if err != nil {
		log.Error("discovery", "err", err)
		return 1
	}
	if len(paths) == 0 {
		log.Warn("no manifests found", "roots", cfg.StackRoots)
		return 0
	}
	bad := 0
	for _, p := range paths {
		m, err := manifest.Load(p)
		if err != nil {
			fmt.Printf("INVALID  %s\n         %v\n", p, err)
			bad++
			continue
		}
		fmt.Printf("ok       %-16s %d secrets → %s\n", m.Stack(), len(m.Secrets), m.Destination)
		if shared := m.SharedStateKeys(); len(shared) > 0 {
			fmt.Printf("         shared state (rendered, never acted on): %v\n", shared)
		}
	}
	if bad > 0 {
		fmt.Printf("\n%d manifest(s) invalid\n", bad)
		return 1
	}
	return 0
}

// runRender does one forced pass per stack and exits.
//
// force is the whole point. A fresh stack has no rendered file, and the compose ${VAR:?} guards
// mean it cannot start without one — so the pre-check's "nothing has moved" answer, while true, is
// useless here. This is also the command to reach for after a purge or a wiped tmpfs.
func runRender(ctx context.Context, cfg *config.Config, log *slog.Logger, only string) int {
	stacks, err := build(cfg, log)
	if err != nil {
		log.Error("startup", "err", err)
		return 1
	}
	failed := 0
	for _, r := range stacks {
		if only != "" && r.Manifest.Stack() != only {
			continue
		}
		outcome, err := r.Once(ctx, reconcile.Pass{Force: true, NoAct: true})
		if err != nil {
			log.Error("render failed", "stack", r.Manifest.Stack(), "outcome", outcome, "err", err)
			failed++
			continue
		}
		log.Info("render", "stack", r.Manifest.Stack(), "outcome", outcome)
	}
	if failed > 0 {
		return 1
	}
	return 0
}

// runDaemon reconciles every stack on a fixed interval, forever.
func runDaemon(ctx context.Context, cfg *config.Config, log *slog.Logger) int {
	stacks, err := build(cfg, log)
	if err != nil {
		log.Error("startup", "err", err)
		return 1
	}
	log.Info("anchor running", "stacks", len(stacks), "interval", cfg.PollInterval)

	// Track how long each stack has been unable to reach the store. A single failed poll is
	// unremarkable and alerting on it would teach everyone to ignore anchor; staleness that
	// PERSISTS is the thing worth waking someone for, and only the daemon can tell them apart.
	staleSince := map[string]time.Time{}
	const staleAfter = 30 * time.Minute

	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	for {
		for _, r := range stacks {
			stack := r.Manifest.Stack()
			outcome, err := r.Once(ctx, reconcile.Pass{})
			if err != nil {
				log.Error("reconcile", "stack", stack, "outcome", outcome, "err", err)
			}

			if outcome == reconcile.OutcomeRodeOut {
				first, seen := staleSince[stack]
				if !seen {
					staleSince[stack] = time.Now()
					continue
				}
				if age := time.Since(first); age > staleAfter {
					r.Alerter.Alert(ctx, reconcile.Alert{ //nolint:errcheck // best-effort by design
						Stack: stack, Severity: "critical",
						Summary: "secrets have been stale for too long",
						Detail: fmt.Sprintf("the store has been unreachable for %s. The last-good "+
							"file is still in place and the stack is running, but rotations are "+
							"not being applied.", age.Round(time.Minute)),
					})
				}
				continue
			}
			delete(staleSince, stack)
		}

		select {
		case <-ctx.Done():
			log.Info("shutting down")
			return 0
		case <-ticker.C:
		}
	}
}

// build loads every manifest and wires a reconciler per stack.
//
// A stack whose manifest or identity is broken is refused at startup rather than skipped quietly: a
// manifest that is present but unusable is precisely the case that must be loud, since somebody
// wrote it expecting it to work.
func build(cfg *config.Config, log *slog.Logger) ([]*reconcile.Reconciler, error) {
	paths, err := cfg.Discover()
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no manifests found under %v", cfg.StackRoots)
	}

	actor := &act.Docker{}
	alerter := &alert.Alertmanager{URL: cfg.AlertmanagerURL}
	if cfg.AlertmanagerURL == "" {
		log.Warn("no alertmanager_url configured; alerts will only be logged")
	}
	if cfg.BelayURL != "" {
		// Stated plainly rather than silently ignored: the difference between a health-gated
		// recreate and a bare one is exactly the difference between a rotation that can roll back
		// and one that cannot.
		log.Warn("belay_url is set but recreates are NOT routed through Belay yet; " +
			"Belay exposes no machine API for a health-gated recreate")
	}

	var out []*reconcile.Reconciler
	for _, p := range paths {
		m, err := manifest.Load(p)
		if err != nil {
			return nil, err
		}
		id, err := store.LoadIdentity(m.IdentityFile)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", m.Stack(), err)
		}
		out = append(out, &reconcile.Reconciler{
			Manifest: m,
			Store: &store.Client{
				BaseURL:  cfg.InfisicalURL,
				Project:  m.Project,
				Env:      m.Env,
				Path:     m.Path,
				Identity: id,
			},
			Actor:   actor,
			Alerter: alerter,
			Log:     log,
		})
	}
	return out, nil
}
