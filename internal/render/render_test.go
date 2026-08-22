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

// The incident this prevents: migrating a stack TO anchor deletes the configuration it already had.
//
// A stack being migrated usually already has a .env holding more than secrets — ports, hostnames,
// feature flags, a timezone. anchor renders only the DECLARED keys, so replacing the file wholesale
// would delete the rest, and compose interpolates a missing variable to an empty string rather than
// failing: the container starts healthy with a blank value in it. That is the original incident,
// reproduced by the tool built to prevent it.
func TestMerge_KeepsEverythingItDoesNotManage(t *testing.T) {
	existing := []byte("" +
		"# hand written, keep me\n" +
		"PORT=8080\n" +
		"\n" +
		"SESSION_SECRET=old-value\n" +
		"TZ=Europe/Madrid\n")

	got, err := Merge(existing, map[string]string{"SESSION_SECRET": "new-value", "SMTP_PASSWORD": "pw"},
		[]string{"SESSION_SECRET", "SMTP_PASSWORD"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	for _, keep := range []string{"# hand written, keep me", "PORT=8080", "TZ=Europe/Madrid"} {
		if !strings.Contains(s, keep) {
			t.Errorf("Merge dropped %q — undeclared configuration must survive:\n%s", keep, s)
		}
	}
	if !strings.Contains(s, "SESSION_SECRET=new-value") {
		t.Errorf("the managed key was not updated:\n%s", s)
	}
	if strings.Contains(s, "old-value") {
		t.Errorf("the old value is still present:\n%s", s)
	}
	if !strings.Contains(s, "SMTP_PASSWORD=pw") {
		t.Errorf("a newly declared key was not appended:\n%s", s)
	}
	// Position matters: updating in place keeps whatever grouping the author chose.
	if strings.Index(s, "SESSION_SECRET") > strings.Index(s, "TZ=") {
		t.Errorf("the existing key moved instead of being updated where it stood:\n%s", s)
	}
}

// Compose takes the LAST assignment when a file declares a key twice. Updating the first and
// leaving a stale second would leave the container reading the old value while the file looked right.
func TestMerge_RewritesTheOccurrenceComposeWouldUse(t *testing.T) {
	existing := []byte("SESSION_SECRET=first\nPORT=1\nSESSION_SECRET=second\n")
	got, err := Merge(existing, map[string]string{"SESSION_SECRET": "correct"}, []string{"SESSION_SECRET"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	if strings.Count(s, "SESSION_SECRET=") != 1 {
		t.Errorf("want exactly one assignment left, got:\n%s", s)
	}
	if !strings.Contains(s, "SESSION_SECRET=correct") || strings.Contains(s, "first") ||
		strings.Contains(s, "second") {
		t.Errorf("the effective value is wrong:\n%s", s)
	}
	if !strings.Contains(s, "PORT=1") {
		t.Errorf("unmanaged key lost:\n%s", s)
	}
}

func TestMerge_IsDeterministicAndStillAllOrNothing(t *testing.T) {
	existing := []byte("PORT=8080\n")
	vals := map[string]string{"B": "2", "A": "1"}
	first, err := Merge(existing, vals, []string{"A", "B"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := Merge(existing, vals, []string{"A", "B"})
		if err != nil || string(again) != string(first) {
			t.Fatalf("Merge is not deterministic; the content hash would be meaningless")
		}
	}
	if _, err := Merge(existing, map[string]string{"A": "1"}, []string{"A", "B"}); err == nil {
		t.Error("an incomplete set must still be refused, merge or not")
	}
}

// Revocation removes anchor's keys and nothing else. The stack still fails to start, because the
// compose ${VAR:?} guards abort — which is the point — but configuration anchor never supplied is
// not anchor's to destroy.
func TestRemoveKeys_DeletesOnlyWhatItManages(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", ".env")
	body := "# keep\nPORT=8080\nSESSION_SECRET=s\nTZ=Europe/Madrid\n"
	if _, err := Write(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	removed, err := RemoveKeys(path, []string{"SESSION_SECRET"})
	if err != nil || !removed {
		t.Fatalf("RemoveKeys = (%v, %v), want (true, nil)", removed, err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the file was deleted; unmanaged configuration went with it: %v", err)
	}
	s := string(b)
	if strings.Contains(s, "SESSION_SECRET") {
		t.Errorf("the revoked key survived:\n%s", s)
	}
	for _, keep := range []string{"# keep", "PORT=8080", "TZ=Europe/Madrid"} {
		if !strings.Contains(s, keep) {
			t.Errorf("RemoveKeys destroyed %q:\n%s", keep, s)
		}
	}
	// Repeatable: it runs on a path that is already an incident and must not invent a second one.
	if removed, err := RemoveKeys(path, []string{"SESSION_SECRET"}); err != nil || removed {
		t.Errorf("second RemoveKeys = (%v, %v), want (false, nil)", removed, err)
	}
}

// If anchor supplied everything in the file, nothing useful is left behind — remove it rather than
// leaving a stub of anchor's own header.
func TestRemoveKeys_DeletesTheFileWhenNothingSurvives(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	content, err := Dotenv(map[string]string{"A": "1", "B": "2"}, []string{"A", "B"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Write(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if removed, err := RemoveKeys(path, []string{"A", "B"}); err != nil || !removed {
		t.Fatalf("RemoveKeys = (%v, %v)", removed, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("a file containing only anchor's keys should be removed entirely: %v", err)
	}
}
