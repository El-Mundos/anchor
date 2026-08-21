package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "anchor.yml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const minimal = `
project: abc123
identity_file: /etc/anchor/traefik-edge.json
secrets:
  - key: IONOS_API_PREFIX
  - key: IONOS_API_SECRET
services:
  - name: traefik
`

func TestLoad_DefaultsAreTheSafeOnes(t *testing.T) {
	m, err := Load(write(t, minimal))
	if err != nil {
		t.Fatal(err)
	}
	if m.Render != RenderEnv {
		t.Errorf("render defaulted to %q", m.Render)
	}
	if m.Destination != filepath.Join(m.Dir, ".env") {
		t.Errorf("destination defaulted to %q", m.Destination)
	}
	// Recreate is the only action that always works; a reload the app ignores looks like success.
	if m.Services[0].Action != ActionRecreate {
		t.Errorf("on_change defaulted to %q, want %q", m.Services[0].Action, ActionRecreate)
	}
}

// A typo in an action would otherwise sit in a file for months and then do nothing on the one day
// a secret rotates.
func TestLoad_RejectsTyposLoudly(t *testing.T) {
	for _, body := range []string{
		strings.Replace(minimal, "- name: traefik", "- name: traefik\n    on_change: recrate", 1),
		strings.Replace(minimal, "project: abc123", "porject: abc123", 1),
		strings.Replace(minimal, "  - key: IONOS_API_SECRET", "  - key: IONOS_API_PREFIX", 1),
	} {
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("expected a load error for:\n%s", body)
		}
	}
}

// reload cannot work when secrets arrive as environment variables: a restart reuses the environment
// baked in at creation, so the new value is never seen. Catching it at load beats discovering it
// during a rotation.
func TestLoad_RejectsReloadWithEnvRendering(t *testing.T) {
	body := strings.Replace(minimal, "- name: traefik", "- name: traefik\n    on_change: reload", 1)
	_, err := Load(write(t, body))
	if err == nil {
		t.Fatal("reload + render:env must be rejected")
	}
	if !strings.Contains(err.Error(), "recreate") {
		t.Errorf("the error should say what to use instead, got: %v", err)
	}
}

func TestLoad_RequiresAnIdentityAndSomeSecrets(t *testing.T) {
	noID := strings.Replace(minimal, "identity_file: /etc/anchor/traefik-edge.json\n", "", 1)
	if _, err := Load(write(t, noID)); err == nil {
		t.Error("a manifest without its own identity must fail")
	}
	noSecrets := "project: abc123\nidentity_file: /x\nservices:\n  - name: traefik\n"
	if _, err := Load(write(t, noSecrets)); err == nil {
		t.Error("a manifest that asks for nothing must fail")
	}
}

func TestSharedStateKeys(t *testing.T) {
	body := `
project: abc123
identity_file: /etc/anchor/cobra.json
secrets:
  - key: SESSION_SECRET
  - key: POSTGRES_PASSWORD
    shared_state: true
services:
  - name: api
`
	m, err := Load(write(t, body))
	if err != nil {
		t.Fatal(err)
	}
	got := m.SharedStateKeys()
	if len(got) != 1 || got[0] != "POSTGRES_PASSWORD" {
		t.Fatalf("got %v, want just POSTGRES_PASSWORD", got)
	}
}
