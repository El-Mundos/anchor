// Package store is the secret store anchor reads from, and the rules for what to believe when it
// answers badly.
//
// The interface is deliberately two calls rather than one. Versions is cheap and runs every poll;
// Values transports the actual secrets and runs only when Versions says something moved. In the
// steady state — which is almost always — no secret crosses the wire at all.
//
// Note what that split does NOT do: a version is a hint about whether to FETCH, never about whether
// to RENDER. Rendering is decided by the content hash, because a version can move without the value
// changing, and a value can change while a version is republished unchanged.
package store

import (
	"context"
	"time"
)

// Meta is what a cheap poll learns about one key without transporting it.
type Meta struct {
	Version   int
	UpdatedAt time.Time
}

// Store is a secret store. Implemented by the Infisical client, and by a fake in tests.
type Store interface {
	// Versions reports metadata for the named keys. Cheap; called every poll.
	Versions(ctx context.Context, keys []string) (map[string]Meta, error)
	// Values fetches the secrets themselves. Called only when Versions indicates a change.
	Values(ctx context.Context, keys []string) (map[string]string, error)
}

// Fault is how anchor should react to a failed call. This type exists because "the store did not
// give me what I asked for" hides two opposite situations behind one error value:
//
//   - The store could not answer. Keep the last-good file, stay quiet, try again. This is what
//     removes Infisical from the boot path.
//   - The store answered, and the answer was no. The credential is gone or our identity is
//     rejected. Keeping the last-good file now means keeping a revoked secret working.
//
// Getting this wrong is silent in both directions: treating an outage as a revocation causes an
// avoidable outage of our own, and treating a revocation as an outage leaves a leaked credential
// live for as long as the file survives.
type Fault int

const (
	// FaultTransient — the store could not answer. Ride it out.
	FaultTransient Fault = iota

	// FaultIdentityRevoked — the store refused THIS STACK'S identity. Not "I cannot answer" but
	// "I will not answer you". Someone disowned this identity, and the only reason to do that is to
	// stop what it was reading from being used. This is the one fault that overrides "stale beats
	// absent": the rendered file is purged, and the stack will refuse to start until a working
	// identity is put back. An outage is the correct outcome of a deliberate revocation.
	FaultIdentityRevoked

	// FaultIdentityRejected — the store refused an identity that has NEVER worked in this process.
	//
	// Separate from a revocation because the two look identical on the wire and demand opposite
	// responses. A revocation means credentials that were valid are now refused, and the right
	// answer is to purge and stop. This means credentials that were never accepted at all — a
	// typo'd client id, a secret pasted from the wrong identity, a file filled in against the wrong
	// project — and the right answer is to touch nothing and say so.
	//
	// The rule that separates them: you cannot be revoked from something you were never granted.
	// Treating a first-contact 401 as a revocation would let a misconfigured install purge a working
	// stack's secrets and stop its containers, which is a self-inflicted outage caused by a typo.
	FaultIdentityRejected

	// FaultSecretMissing — our identity is fine; a declared key is not there. Deliberately NOT the
	// same as a revocation. A key vanishing is far more often a rename, a moved folder or a typo'd
	// path than a disownment, and treating a typo as a revocation would take a stack down for a
	// misspelling. All-or-nothing already refuses to render an incomplete set, so the last-good
	// file stands and the gap is alerted.
	FaultSecretMissing

	// FaultUnknown — an answer that fits none of the above. Deliberately separate so it can be
	// alerted on rather than silently folded into whichever behaviour is more convenient.
	FaultUnknown
)

// classify decides which of the above an HTTP response represents.
//
// status is the HTTP status code, or 0 when the request never got an answer at all (DNS failure,
// connection refused, TLS failure, context deadline). err is the transport error, nil if the
// request completed.
//
// The rule behind every line: if this judgement is WRONG, which way does it fail, and would anyone
// find out? Transient is the quiet answer, so it is only given where silence is genuinely correct.
func classify(status int, err error) Fault {
	// No answer arrived at all. Nothing has been said about our access, so nothing has changed.
	if err != nil || status == 0 {
		return FaultTransient
	}
	switch {
	// The store is unwell, or is rationing us. Both pass on their own; both must be ridden out or
	// anchor becomes a second outage on top of the first.
	case status >= 500,
		status == 408, // request timeout
		status == 429: // rate limited — can persist for a long time, but is never an answer about us
		return FaultTransient

	// No token expiry exists in these deployments, so there is no reading of 401 that means "try
	// again in a minute". If the store stops recognising us, someone made that happen.
	case status == 401, // token refused
		status == 403: // identity refused
		return FaultIdentityRevoked

	// Our identity still works; the key is not where the manifest says it is.
	case status == 404:
		return FaultSecretMissing
	}

	// Anything unrecognised is surfaced rather than assumed. A default of "transient" here would be
	// the exact failure this package exists to prevent: an unhandled case that resolves, silently,
	// into carrying on as though nothing happened.
	return FaultUnknown
}
