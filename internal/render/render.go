// Package render turns a set of fetched secrets into a file on disk.
//
// Two rules govern everything here, and both exist because of the same real incident: a stack whose
// credentials came from a deploy wrapper was recreated by something that did not run the wrapper.
// The variables interpolated to empty strings, "${A}.${B}" became ".", the container started
// perfectly healthy, and certificate renewal was silently dead for weeks.
//
//  1. ALL OR NOTHING. A partial result is a failure, not a partial success. Rendering three of four
//     secrets produces a file that looks complete and is not.
//  2. ATOMIC. Write to a temporary file and rename, so a container starting mid-write reads either
//     the whole old file or the whole new one, never half of either.
package render

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ErrIncomplete reports secrets that were requested but not usable. It names them, because "some
// secret was missing" is not something anyone can act on at 3am.
type ErrIncomplete struct {
	Missing []string
	Blank   []string
}

func (e *ErrIncomplete) Error() string {
	var parts []string
	if len(e.Missing) > 0 {
		parts = append(parts, "missing: "+strings.Join(e.Missing, ", "))
	}
	if len(e.Blank) > 0 {
		parts = append(parts, "empty: "+strings.Join(e.Blank, ", "))
	}
	return "refusing to render an incomplete secret set (" + strings.Join(parts, "; ") +
		") — the previous file has been left in place"
}

// Dotenv formats secrets as KEY=value lines, sorted so identical inputs always produce identical
// bytes. Stable output is what makes a content hash meaningful: without it, every render would look
// like a change and every poll would trigger a restart.
func Dotenv(values map[string]string, keys []string) ([]byte, error) {
	if err := complete(values, keys); err != nil {
		return nil, err
	}
	ordered := append([]string(nil), keys...)
	sort.Strings(ordered)
	var b strings.Builder
	b.WriteString("# rendered by anchor — do not edit; changes are overwritten\n")
	for _, k := range ordered {
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(quote(values[k]))
		b.WriteString("\n")
	}
	return []byte(b.String()), nil
}

// quote wraps a value only when it needs it. Compose parses .env with its own rules; a value
// containing whitespace or a quote must be quoted or it silently truncates.
func quote(v string) string {
	if v == "" {
		return `""`
	}
	if !strings.ContainsAny(v, " \t\"'$#\n\\") {
		return v
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return `"` + r.Replace(v) + `"`
}

// complete reports every declared key that is absent or empty.
//
// Empty counts as absent on purpose. An empty value is what a blank interpolation produces, and
// writing one would reproduce exactly the failure this package exists to prevent.
func complete(values map[string]string, keys []string) error {
	var missing, blank []string
	for _, k := range keys {
		v, ok := values[k]
		switch {
		case !ok:
			missing = append(missing, k)
		case strings.TrimSpace(v) == "":
			blank = append(blank, k)
		}
	}
	if len(missing) > 0 || len(blank) > 0 {
		return &ErrIncomplete{Missing: missing, Blank: blank}
	}
	return nil
}

// Hash fingerprints rendered content. Comparisons are made on this, never on file timestamps: two
// clocks disagree, mtime survives a restore-from-backup that replaces the content, and a touched
// file looks fresh while holding yesterday's secrets.
func Hash(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// Purge removes a rendered file, and reports whether there was one to remove.
//
// This is the deliberate exception to "stale beats absent". Everywhere else, an unreachable store
// means the last-good file stands and containers keep booting. Here the store has not gone quiet —
// it has refused this stack's identity, which only happens because somebody revoked it, and the
// point of revoking is that what it was reading should stop being used.
//
// So the stack loses its ability to start, and that is the intended outcome rather than a side
// effect: a deliberate revocation SHOULD take the stack down rather than let it come back up with
// secrets that have been disowned. Nothing here reaches a running container — it keeps the
// environment it was created with until something recreates it.
//
// Only ever call this for a revoked identity. Calling it for an unreachable store would put the
// secret store back on the boot path and hand every stack on the host to Infisical's uptime.
func Purge(path string) (removed bool, err error) {
	// Remove is atomic: a concurrent reader either opens the whole file or does not find it, and
	// never sees an emptied one.
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return false, nil // already gone; a purge that repeats is not a failure
		}
		return false, fmt.Errorf("purge %s: %w", path, err)
	}
	return true, nil
}

// Write atomically replaces path with content, owner-readable only. It reports whether the content
// actually changed, so an unchanged render never triggers a restart.
func Write(path string, content []byte, mode os.FileMode) (changed bool, err error) {
	if old, err := os.ReadFile(path); err == nil && Hash(old) == Hash(content) {
		return false, nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return false, err
	}
	// Same directory, so the rename is atomic: a cross-filesystem rename is a copy, and a copy can
	// be observed half-finished.
	tmp, err := os.CreateTemp(dir, ".anchor-*")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name()) // no-op once the rename succeeds
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return false, err
	}
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return false, err
	}
	// fsync before rename: a rename is atomic with respect to readers, not with respect to a power
	// cut, and a truncated secrets file that survives a crash is the worst of both worlds.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return false, fmt.Errorf("replace %s: %w", path, err)
	}
	return true, nil
}
