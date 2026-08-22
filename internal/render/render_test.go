package render

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The incident this package exists to prevent: three of four secrets resolved, and the render went
// ahead. The file looked complete, the container started healthy, and the missing credential was
// only noticed weeks later when it was needed.
func TestDotenv_RefusesAPartialSet(t *testing.T) {
	_, err := Dotenv(map[string]string{"A": "1", "B": "2"}, []string{"A", "B", "C"})
	if err == nil {
		t.Fatal("rendering with a missing key must fail, not produce a partial file")
	}
	if !strings.Contains(err.Error(), "C") {
		t.Errorf("the error must name what is missing, got: %v", err)
	}
}

// An empty value is what a blank interpolation produces — the exact shape of the traefik failure,
// where ${A}.${B} became ".". Treating it as present would reproduce the bug faithfully.
func TestDotenv_TreatsEmptyAsMissing(t *testing.T) {
	_, err := Dotenv(map[string]string{"A": "1", "B": "   "}, []string{"A", "B"})
	var inc *ErrIncomplete
	if err == nil {
		t.Fatal("an empty secret must not be rendered")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("want an 'empty' complaint, got: %v", err)
	}
	_ = inc
}

// Stable output is what makes hashing meaningful: unstable ordering would make every poll look like
// a change, and every change triggers a restart.
func TestDotenv_IsDeterministic(t *testing.T) {
	vals := map[string]string{"B": "2", "A": "1", "C": "3"}
	keys := []string{"C", "A", "B"}
	first, err := Dotenv(vals, keys)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, err := Dotenv(vals, []string{"A", "B", "C"})
		if err != nil {
			t.Fatal(err)
		}
		if Hash(first) != Hash(again) {
			t.Fatal("same secrets rendered to different bytes; hashes would be useless")
		}
	}
}

func TestPurge_RemovesAndIsRepeatable(t *testing.T) {
	// A purge runs on the revocation path, which is already an incident. It must not turn a second
	// poll into a second, different failure just because the first one succeeded.
	path := filepath.Join(t.TempDir(), "sub", ".env")
	if _, err := Write(path, []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	removed, err := Purge(path)
	if err != nil || !removed {
		t.Fatalf("Purge = (%v, %v), want (true, nil)", removed, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file still present after Purge: %v", err)
	}
	removed, err = Purge(path)
	if err != nil || removed {
		t.Fatalf("second Purge = (%v, %v), want (false, nil)", removed, err)
	}
}

func TestQuote(t *testing.T) {
	cases := map[string]string{
		"simple":            "simple",
		"has space":         `"has space"`,
		`has"quote`:         `"has\"quote"`,
		`with$dollar`:       `"with$dollar"`,
		"tricky\\backslash": `"tricky\\backslash"`,
	}
	for in, want := range cases {
		if got := quote(in); got != want {
			t.Errorf("quote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWrite_AtomicAndOnlyWhenChanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", ".env")

	changed, err := Write(path, []byte("A=1\n"), 0o600)
	if err != nil || !changed {
		t.Fatalf("first write: changed=%v err=%v", changed, err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("secrets file mode is %v, want 0600", fi.Mode().Perm())
	}

	// Identical content must not count as a change, or every poll would restart the service.
	if changed, err := Write(path, []byte("A=1\n"), 0o600); err != nil || changed {
		t.Errorf("rewriting identical content reported changed=%v err=%v", changed, err)
	}
	if changed, err := Write(path, []byte("A=2\n"), 0o600); err != nil || !changed {
		t.Errorf("new content should report a change, got changed=%v err=%v", changed, err)
	}

	// No temporary files left behind: they would hold secrets at a predictable path.
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".anchor-") {
			t.Errorf("left a temporary file behind: %s", e.Name())
		}
	}
}

// The incident this prevents: migrating a stack TO anchor destroys the config it already had.
//
// A stack being migrated almost always has a .env, and it usually holds more than secrets — ports,
// hostnames, feature flags. anchor renders only what the manifest declares, so overwriting such a
// file deletes the rest, and compose turns the missing variables into empty strings rather than an
// error. That is the original incident, reproduced by the tool built to prevent it.
func TestForeign_TellsAnchorsOwnFileFromSomebodyElses(t *testing.T) {
	dir := t.TempDir()

	missing := filepath.Join(dir, "absent.env")
	if foreign, err := Foreign(missing); err != nil || foreign {
		t.Errorf("Foreign(missing) = (%v, %v), want (false, nil) — a first render is not a conflict",
			foreign, err)
	}

	ours := filepath.Join(dir, "ours.env")
	content, err := Dotenv(map[string]string{"A": "1"}, []string{"A"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Write(ours, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if foreign, err := Foreign(ours); err != nil || foreign {
		t.Errorf("Foreign(anchor's own file) = (%v, %v), want (false, nil)", foreign, err)
	}

	theirs := filepath.Join(dir, "theirs.env")
	if err := os.WriteFile(theirs, []byte("PORT=8080\nTZ=Europe/Madrid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if foreign, err := Foreign(theirs); err != nil || !foreign {
		t.Errorf("Foreign(hand-written file) = (%v, %v), want (true, nil)", foreign, err)
	}

	// A file shorter than the header must not read past the end and must still count as foreign.
	stub := filepath.Join(dir, "stub.env")
	if err := os.WriteFile(stub, []byte("X=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if foreign, err := Foreign(stub); err != nil || !foreign {
		t.Errorf("Foreign(short file) = (%v, %v), want (true, nil)", foreign, err)
	}
}
