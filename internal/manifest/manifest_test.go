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
	// A revocation that leaves the secret in use in a running container has not happened yet.
	if m.Services[0].Revoke != RevokeStop {
		t.Errorf("on_revoke defaulted to %q, want %q", m.Services[0].Revoke, RevokeStop)
	}
}

// "restart" is the intuitive answer and a trap: the rendered file is already purged, so it either
// crash-loops on a guarded variable or comes back healthy with blank secrets. The error has to say
// so, because a generic "not a valid value" would send someone looking for a spelling mistake.
func TestLoad_RejectsRestartOnRevokeWithAnExplanation(t *testing.T) {
	body := strings.Replace(minimal, "- name: traefik", "- name: traefik\n    on_revoke: restart", 1)
	_, err := Load(write(t, body))
	if err == nil {
		t.Fatal("expected on_revoke: restart to be refused at load")
	}
	if !strings.Contains(err.Error(), "purged") || !strings.Contains(err.Error(), string(RevokeLeave)) {
		t.Errorf("error should explain why and offer the alternative, got: %v", err)
	}
}

// The opposite mistake: refusing "leave" would force an operator to choose between an unnecessary
// outage and not declaring the service at all.
func TestLoad_AllowsLeaveForServicesThatSurviveWithoutTheSecret(t *testing.T) {
	body := strings.Replace(minimal, "- name: traefik", "- name: traefik\n    on_revoke: leave", 1)
	m, err := Load(write(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if m.Services[0].Revoke != RevokeLeave {
		t.Errorf("on_revoke = %q, want %q", m.Services[0].Revoke, RevokeLeave)
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

// Namespaced store keys are normal (KALOS_COBRA_SESSION_SECRET) while compose wants the bare name,
// so the two cannot be assumed identical.
func TestSecretName_FallsBackToTheStoreKey(t *testing.T) {
	body := strings.Replace(minimal, "  - key: IONOS_API_SECRET",
		"  - key: PREFIXED_IONOS_API_SECRET\n    as: IONOS_API_SECRET", 1)
	m, err := Load(write(t, body))
	if err != nil {
		t.Fatal(err)
	}
	keys, names := m.Keys(), m.Names()
	if keys[1] != "PREFIXED_IONOS_API_SECRET" {
		t.Errorf("Keys()[1] = %q, want the STORE key", keys[1])
	}
	if names[1] != "IONOS_API_SECRET" {
		t.Errorf("Names()[1] = %q, want the RENDERED name", names[1])
	}
	if names[0] != keys[0] {
		t.Errorf("a secret with no 'as' must render under its own key, got %q", names[0])
	}
}

// Two keys rendering to one name would silently drop one: the map keeps the last write, the file
// looks complete, and all-or-nothing is satisfied. Caught at load, where it is still a typo.
func TestLoad_RejectsTwoSecretsRenderingToTheSameName(t *testing.T) {
	body := strings.Replace(minimal, "  - key: IONOS_API_SECRET",
		"  - key: OTHER_KEY\n    as: IONOS_API_PREFIX", 1)
	_, err := Load(write(t, body))
	if err == nil {
		t.Fatal("expected a collision between a key and another secret's rendered name")
	}
	if !strings.Contains(err.Error(), "overwrite") {
		t.Errorf("the error should say what would be lost, got: %v", err)
	}
}

// Rename must not invent values: a key the store did not return has to stay absent so the
// completeness check still sees the gap.
func TestRename_LeavesMissingKeysAbsent(t *testing.T) {
	body := strings.Replace(minimal, "  - key: IONOS_API_SECRET",
		"  - key: PREFIXED_IONOS_API_SECRET\n    as: IONOS_API_SECRET", 1)
	m, err := Load(write(t, body))
	if err != nil {
		t.Fatal(err)
	}
	got := m.Rename(map[string]string{"IONOS_API_PREFIX": "abc"})
	if _, present := got["IONOS_API_SECRET"]; present {
		t.Error("a key the store never returned was materialised by Rename")
	}
	if got["IONOS_API_PREFIX"] != "abc" {
		t.Errorf("Rename dropped a value it had: %v", got)
	}
}
