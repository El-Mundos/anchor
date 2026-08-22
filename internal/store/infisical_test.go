package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// server stands in for Infisical. handler decides what each request gets, so a test can describe a
// sequence — "401 the first time, fine the second" — which is the only way to reproduce a token
// expiring underneath a running poll.
func server(t *testing.T, handler http.HandlerFunc) (*Client, *int) {
	t.Helper()
	logins := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/universal-auth/login" {
			logins++
		}
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return &Client{
		BaseURL:  srv.URL,
		Project:  "proj",
		Env:      "prod",
		Path:     "/",
		Identity: Identity{ClientID: "id", ClientSecret: "secret"},
		HTTP:     srv.Client(),
	}, &logins
}

func writeLogin(w http.ResponseWriter, ttl int) {
	json.NewEncoder(w).Encode(map[string]any{"accessToken": "tok", "expiresIn": ttl})
}

func writeSecrets(w http.ResponseWriter, withValues bool) {
	value := ""
	if withValues {
		value = "real-secret"
	}
	json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{
		{"secretKey": "IONOS_API_PREFIX", "secretValue": value, "version": 3},
	}})
}

// The whole point of the two-call split. If a poll transports secret values, the steady state is
// leaking them across the network for no reason, and nothing about the behaviour would show it.
func TestVersions_DoesNotTransportSecretValues(t *testing.T) {
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/universal-auth/login" {
			writeLogin(w, 7200)
			return
		}
		if got := r.URL.Query().Get("viewSecretValue"); got != "false" {
			t.Errorf("viewSecretValue = %q, want \"false\" — values must not cross the wire", got)
		}
		writeSecrets(w, false)
	})
	metas, err := c.Versions(context.Background(), []string{"IONOS_API_PREFIX"})
	if err != nil {
		t.Fatal(err)
	}
	if metas["IONOS_API_PREFIX"].Version != 3 {
		t.Errorf("version = %d, want 3", metas["IONOS_API_PREFIX"].Version)
	}
}

// The incident this prevents is entirely self-inflicted: Universal Auth tokens expire (7200s by
// default), an expired token answers 401, and 401 is how a revoked identity announces itself. With
// no re-login, anchor would purge the file and stop the stack every two hours, on schedule.
func TestList_RetriesOnceWhenTheTokenExpiredRatherThanCallingItRevoked(t *testing.T) {
	served := 0
	c, logins := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/universal-auth/login" {
			writeLogin(w, 7200)
			return
		}
		served++
		if served == 1 {
			w.WriteHeader(http.StatusUnauthorized) // the cached token just died
			return
		}
		writeSecrets(w, false)
	})
	if _, err := c.Versions(context.Background(), []string{"IONOS_API_PREFIX"}); err != nil {
		t.Fatalf("an expired token must not surface as an error: %v", err)
	}
	if *logins != 2 {
		t.Errorf("logins = %d, want 2 (initial + one refresh)", *logins)
	}
}

// The other half: a 401 that survives a fresh login is a real revocation, and must be reported as
// one. Retrying forever here would leave a revoked identity looking like a flaky network.
func TestList_ReportsRevocationWhenAFreshLoginIsAlsoRefused(t *testing.T) {
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/universal-auth/login" {
			// First login succeeds so there is a cached token; afterwards the identity is gone.
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	_, err := c.Versions(context.Background(), []string{"IONOS_API_PREFIX"})
	var se *Error
	if !asError(err, &se) {
		t.Fatalf("want *store.Error, got %v", err)
	}
	if se.Fault != FaultIdentityRevoked {
		t.Errorf("fault = %v, want FaultIdentityRevoked", se.Fault)
	}
}

// An unreachable store must never look like a revocation: that would purge files and stop stacks
// because a network blipped, which is the exact opposite of "stale beats absent".
func TestList_AnUnreachableStoreIsTransient(t *testing.T) {
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/universal-auth/login" {
			writeLogin(w, 7200)
			return
		}
		w.WriteHeader(http.StatusBadGateway)
	})
	_, err := c.Versions(context.Background(), []string{"IONOS_API_PREFIX"})
	var se *Error
	if !asError(err, &se) || se.Fault != FaultTransient {
		t.Fatalf("want FaultTransient, got %v", err)
	}
}

// A declared key the store does not have is a missing key, not a revocation. Conflating them would
// let a typo'd manifest destroy a working stack.
func TestValues_MissingKeyIsNotARevocation(t *testing.T) {
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/universal-auth/login" {
			writeLogin(w, 7200)
			return
		}
		writeSecrets(w, true) // returns only IONOS_API_PREFIX
	})
	_, err := c.Values(context.Background(), []string{"IONOS_API_PREFIX", "IONOS_API_SECRET"})
	var se *Error
	if !asError(err, &se) {
		t.Fatalf("want *store.Error, got %v", err)
	}
	if se.Fault != FaultSecretMissing {
		t.Errorf("fault = %v, want FaultSecretMissing", se.Fault)
	}
}

// A 404 on the LISTING endpoint means the URL is wrong — a deprecated API version, a bad project
// id, a proxy answering for an unknown host. Reporting it as FaultSecretMissing would send someone
// to audit secrets that are sitting there perfectly intact.
func TestList_A404OnTheEndpointIsNotAMissingSecret(t *testing.T) {
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/universal-auth/login" {
			writeLogin(w, 7200)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	_, err := c.Versions(context.Background(), []string{"IONOS_API_PREFIX"})
	var se *Error
	if !asError(err, &se) {
		t.Fatalf("want *store.Error, got %v", err)
	}
	if se.Fault == FaultSecretMissing {
		t.Error("a 404 on the endpoint was reported as a missing secret")
	}
	if !strings.Contains(se.Error(), "no secrets endpoint") {
		t.Errorf("the error must point at the URL, not the secrets: %v", se)
	}
}

// v4 first, because v3 is deprecated at source and will eventually be withdrawn.
func TestList_PrefersV4AndRemembersIt(t *testing.T) {
	var paths []string
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/universal-auth/login" {
			writeLogin(w, 7200)
			return
		}
		paths = append(paths, r.URL.Path)
		writeSecrets(w, false)
	})
	for i := 0; i < 2; i++ {
		if _, err := c.Versions(context.Background(), []string{"IONOS_API_PREFIX"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range paths {
		if p != "/api/v4/secrets" {
			t.Errorf("requested %q, want /api/v4/secrets", p)
		}
	}
	if len(paths) != 2 {
		t.Fatalf("made %d listings, want 2", len(paths))
	}
}

// An older Infisical has no v4. Falling back keeps anchor working across the whole fleet instead of
// demanding every instance be upgraded in lockstep with it.
func TestList_FallsBackToV3AndThenStopsProbing(t *testing.T) {
	v4Tries, v3Tries := 0, 0
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/auth/universal-auth/login":
			writeLogin(w, 7200)
		case strings.HasPrefix(r.URL.Path, "/api/v4/"):
			v4Tries++
			w.WriteHeader(http.StatusNotFound)
		default:
			v3Tries++
			writeSecrets(w, false)
		}
	})
	for i := 0; i < 3; i++ {
		if _, err := c.Versions(context.Background(), []string{"IONOS_API_PREFIX"}); err != nil {
			t.Fatal(err)
		}
	}
	// The negotiation must cost one wasted request per process, not one per poll: a daemon polling
	// every 30s would otherwise 404 an endpoint forever, filling logs with a non-problem.
	if v4Tries != 1 {
		t.Errorf("probed v4 %d times, want 1 — the answer must be remembered", v4Tries)
	}
	if v3Tries != 3 {
		t.Errorf("used v3 %d times, want 3", v3Tries)
	}
}

// The dangerous shape: 200 OK, valid JSON, no "secrets" field. Read as an empty vault it would mean
// "every declared key is missing", which under all-or-nothing looks exactly like a real outage.
func TestList_TreatsAnUnrecognisedBodyAsWrongApiNotAnEmptyVault(t *testing.T) {
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/universal-auth/login" {
			writeLogin(w, 7200)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v4/") {
			w.Write([]byte(`{"data":{"items":[]}}`)) // 200, valid JSON, alien shape
			return
		}
		writeSecrets(w, false)
	})
	metas, err := c.Versions(context.Background(), []string{"IONOS_API_PREFIX"})
	if err != nil {
		t.Fatalf("should have fallen back to v3: %v", err)
	}
	if metas["IONOS_API_PREFIX"].Version != 3 {
		t.Error("fell back but did not read the v3 response")
	}
}

func TestLoadIdentity_RefusesAHalfFilledFile(t *testing.T) {
	path := t.TempDir() + "/id.json"
	if err := writeFile(path, `{"client_id":"abc"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentity(path); err == nil {
		t.Error("an identity with no client_secret must be refused at load, not at rotation time")
	}
}

func asError(err error, target **Error) bool { return errors.As(err, target) }

func writeFile(path, body string) error { return os.WriteFile(path, []byte(body), 0o600) }
