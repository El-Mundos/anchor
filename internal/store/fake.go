package store

import "context"

// Fake is an in-memory Store for testing the reconcile loop without a network or an Infisical.
//
// It exists so the loop's tests can be about the loop's decisions — rotate, ride out, purge — rather
// than about HTTP. Faults are injectable because the interesting behaviour is almost entirely in
// what happens when the store misbehaves, and those cases are impossible to provoke on demand
// against a real server.
type Fake struct {
	Values_  map[string]string
	Metas    map[string]Meta
	FailWith *Error // returned by both calls when set

	// ValueCalls counts fetches of actual secret values, so a test can assert the version
	// pre-check is doing its job: a steady state that still transports secrets is a silent
	// regression, invisible in behaviour and visible only here.
	ValueCalls   int
	VersionCalls int
}

func (f *Fake) Versions(ctx context.Context, keys []string) (map[string]Meta, error) {
	f.VersionCalls++
	if f.FailWith != nil {
		return nil, f.FailWith
	}
	out := map[string]Meta{}
	for _, k := range keys {
		if m, ok := f.Metas[k]; ok {
			out[k] = m
		}
	}
	return out, nil
}

func (f *Fake) Values(ctx context.Context, keys []string) (map[string]string, error) {
	f.ValueCalls++
	if f.FailWith != nil {
		return nil, f.FailWith
	}
	out := map[string]string{}
	for _, k := range keys {
		if v, ok := f.Values_[k]; ok {
			out[k] = v
		}
	}
	return out, nil
}
