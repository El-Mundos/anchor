package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func load(t *testing.T, body string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yml")
	write(t, p, body)
	return Load(p)
}

const minimal = `
infisical_url: http://localhost:8080
stack_roots: [/srv/infra]
`

// The incident this prevents: anchor finds a manifest inside a backup directory and starts
// rendering live secrets into a path nobody remembers exists.
//
// Discovery is the one place where being thorough is the wrong instinct. A recursive walk over
// /srv/infra will eventually meet an old checkout, a .bak copy, or a restored snapshot — each
// carrying a manifest that was valid when it was written and names a destination that is not.
func TestDiscover_LooksExactlyOneLevelDown(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "kalos-cobra", ManifestName), "x")
	write(t, filepath.Join(root, "traefik-edge", ManifestName), "x")

	// Every one of these is a real shape a server accumulates, and none may be discovered.
	write(t, filepath.Join(root, "kalos-cobra", "backup", ManifestName), "x")
	write(t, filepath.Join(root, "kalos-cobra", "backup", "2026-01", ManifestName), "x")
	write(t, filepath.Join(root, ManifestName), "x") // at the root itself, not in a stack dir
	write(t, filepath.Join(root, "notes.txt"), "x")

	c := &Config{StackRoots: []string{root}}
	found, err := c.Discover()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		filepath.Join(root, "kalos-cobra", ManifestName):  true,
		filepath.Join(root, "traefik-edge", ManifestName): true,
	}
	if len(found) != len(want) {
		t.Fatalf("Discover found %d manifests, want %d:\n%v", len(found), len(want), found)
	}
	for _, p := range found {
		if !want[p] {
			t.Errorf("Discover reached %s — a manifest outside a stack directory must not be "+
				"picked up; it would render secrets somewhere nobody is looking", p)
		}
	}
}

// A missing root is an error rather than an empty result. Silently managing nothing is how a
// daemon ends up looking healthy while every stack it was installed for drifts.
func TestDiscover_RefusesAMissingRoot(t *testing.T) {
	c := &Config{StackRoots: []string{filepath.Join(t.TempDir(), "does-not-exist")}}
	if _, err := c.Discover(); err == nil {
		t.Error("a stack root that does not exist must be an error, not an empty list")
	}
}

// KnownFields is what turns a typo into a startup failure instead of a setting that quietly does
// nothing. The failure mode without it is the worst kind: the file looks right.
func TestLoad_RejectsAnUnknownField(t *testing.T) {
	if _, err := load(t, minimal+"alertmanager_ur1: http://x\n"); err == nil {
		t.Error("an unknown field must be refused; otherwise a typo is a silent misconfiguration")
	}
}

func TestLoad_RequiresWhatItCannotInvent(t *testing.T) {
	cases := map[string]string{
		"no infisical_url": "stack_roots: [/srv/infra]\n",
		"no stack_roots":   "infisical_url: http://localhost:8080\n",
		"empty stack_roots": "infisical_url: http://localhost:8080\n" +
			"stack_roots: []\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := load(t, body); err == nil {
				t.Error("loaded a config that cannot possibly work")
			}
		})
	}
}

// Below the floor the version pre-check stops being a saving and becomes a denial-of-service
// against your own secret store — self-inflicted, and easy to reach by typing 1s to test something.
func TestLoad_RefusesAnAggressivePollInterval(t *testing.T) {
	if _, err := load(t, minimal+"poll_interval: 1s\n"); err == nil {
		t.Error("poll_interval: 1s must be refused")
	}
	if _, err := load(t, minimal+"poll_interval: 5s\n"); err != nil {
		t.Errorf("5s is the documented floor and must be accepted: %v", err)
	}
}

func TestLoad_DefaultsAndNormalises(t *testing.T) {
	c, err := load(t, "infisical_url: http://localhost:8080/\nstack_roots: [/srv/infra]\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.PollInterval != time.Minute {
		t.Errorf("PollInterval = %s, want the 1m default", c.PollInterval)
	}
	// Every request path is joined onto this. A trailing slash would produce //api/v4/secrets,
	// which some proxies serve and some reject — a difference that would only show up in prod.
	if c.InfisicalURL != "http://localhost:8080" {
		t.Errorf("InfisicalURL = %q, want the trailing slash trimmed", c.InfisicalURL)
	}
}
