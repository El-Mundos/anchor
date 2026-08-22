package store

import (
	"errors"
	"testing"
)

func TestClassify_RidesOutAnUnreachableStore(t *testing.T) {
	// The whole point of "stale beats absent": if the store cannot answer, the last-good file stands
	// and containers keep booting. Anything here returning FaultRevoked puts Infisical back on the
	// boot path and reintroduces the circular dependency.
	cases := []struct {
		name   string
		status int
		err    error
	}{
		{"connection refused", 0, errors.New("dial tcp: connection refused")},
		{"context deadline", 0, errors.New("context deadline exceeded")},
		{"bad gateway", 502, nil},
		{"unavailable", 503, nil},
		{"gateway timeout", 504, nil},
		{"request timeout", 408, nil},
		{"rate limited", 429, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classify(c.status, c.err); got != FaultTransient {
				t.Fatalf("classify(%d, %v) = %v, want FaultTransient", c.status, c.err, got)
			}
		})
	}
}

func TestClassify_TreatsARefusedIdentityAsRevocation(t *testing.T) {
	// These deployments have no token expiry, so there is no reading of 401 that means "retry
	// later". A refused identity is someone's decision, and riding it out quietly would keep a
	// stolen identity fetching secrets for as long as the process lives.
	for _, status := range []int{401, 403} {
		if got := classify(status, nil); got != FaultIdentityRevoked {
			t.Fatalf("classify(%d, nil) = %v, want FaultIdentityRevoked", status, got)
		}
	}
}

func TestClassify_DoesNotTreatAMissingKeyAsARevocation(t *testing.T) {
	// A revocation purges the rendered file and takes the stack down. A 404 is far more often a
	// renamed secret or a typo'd path than a disownment, so conflating the two would mean a
	// misspelling in a manifest destroys a working stack's ability to boot.
	if got := classify(404, nil); got != FaultSecretMissing {
		t.Fatalf("classify(404, nil) = %v, want FaultSecretMissing", got)
	}
}

func TestClassify_RefusesToGuessAtAnUnrecognisedAnswer(t *testing.T) {
	// A default of FaultTransient would be the failure mode the whole project is built against: an
	// unhandled case quietly resolving into "carry on as though nothing happened".
	for _, status := range []int{400, 418, 451} {
		if got := classify(status, nil); got != FaultUnknown {
			t.Fatalf("classify(%d, nil) = %v, want FaultUnknown", status, got)
		}
	}
}

func TestClassify_PrefersTheTransportErrorOverAStatus(t *testing.T) {
	// A response that both carries a status and failed in transit did not complete. Reading the
	// status would let a truncated 403 look like a revocation and take a healthy stack offline.
	if got := classify(403, errors.New("unexpected EOF")); got != FaultTransient {
		t.Fatalf("classify(403, err) = %v, want FaultTransient", got)
	}
}
