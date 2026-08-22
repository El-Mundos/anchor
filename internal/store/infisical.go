package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Identity is one stack's machine identity, read from the manifest's identity_file.
//
// Per-stack on purpose: a leaked identity should expose one stack's secrets, not the fleet's. The
// file is expected to be 0600 and owned by whoever runs anchor.
type Identity struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// LoadIdentity reads an identity file, refusing the two ways it is usually wrong.
func LoadIdentity(path string) (Identity, error) {
	var id Identity
	b, err := os.ReadFile(path)
	if err != nil {
		return id, fmt.Errorf("identity file: %w", err)
	}
	if err := json.Unmarshal(b, &id); err != nil {
		return id, fmt.Errorf("identity file %s: %w", path, err)
	}
	if id.ClientID == "" || id.ClientSecret == "" {
		return id, fmt.Errorf("identity file %s: client_id and client_secret are both required", path)
	}
	return id, nil
}

// Error carries the Fault alongside the detail, so a caller decides what to do from the Fault and
// logs the detail. Every failure out of this package is one of these: a bare error would force the
// reconcile loop to guess, and guessing here means either an unnecessary outage or a revoked
// credential left working.
type Error struct {
	Fault  Fault
	Op     string
	Status int
	Err    error
}

func (e *Error) Error() string {
	s := e.Op
	if e.Status != 0 {
		s += " (HTTP " + strconv.Itoa(e.Status) + ")"
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

func (e *Error) Unwrap() error { return e.Err }

// Client talks to a self-hosted Infisical.
type Client struct {
	BaseURL string // e.g. https://infisical.example.com — no trailing slash
	Project string // Infisical project (workspace) id
	Env     string // environment slug, e.g. "prod"
	Path    string // secret folder, e.g. "/"

	Identity Identity
	HTTP     *http.Client

	mu      sync.Mutex
	authed  bool // these credentials have logged in successfully at least once
	token   string
	expires time.Time

	// apiVersion is 0 until the first successful listing settles it, then 4 or 3.
	//
	// Discovered rather than configured. v3 is deprecated in Infisical's own source and will
	// eventually be removed; v4 does not exist on older instances. Hard-coding either means a
	// future upgrade breaks anchor at the exact moment nobody is looking at it, and the symptom
	// would be a 404 — which, before this, was reported as "your secrets are missing".
	apiVersion int
}

// endpoint builds the listing URL for a given API version.
//
// The two versions differ in more than a number: v4 renamed workspaceId to projectId and moved the
// list off the /raw suffix. Note that /api/v4/secrets/raw is NOT a v4 endpoint — it matches the
// by-name route with secretName="raw", which is why probing for it returns a misleading 401.
func (c *Client) endpoint(version int, withValues bool) string {
	q := url.Values{
		"environment":     {c.Env},
		"secretPath":      {c.Path},
		"viewSecretValue": {strconv.FormatBool(withValues)},
	}
	if version == 4 {
		q.Set("projectId", c.Project)
		return c.BaseURL + "/api/v4/secrets?" + q.Encode()
	}
	q.Set("workspaceId", c.Project)
	return c.BaseURL + "/api/v3/secrets/raw?" + q.Encode()
}

// tokenSkew renews a little before the token actually dies.
//
// Not cosmetic. A token that expires mid-request produces a 401, and a 401 is how a REVOKED
// identity announces itself — which purges the rendered file and stops the stack. Renewing early
// keeps the routine case away from the destructive one.
const tokenSkew = 5 * time.Minute

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// login exchanges the identity for an access token.
func (c *Client) login(ctx context.Context) (string, error) {
	form := url.Values{
		"clientId":     {c.Identity.ClientID},
		"clientSecret": {c.Identity.ClientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BaseURL+"/api/v1/auth/universal-auth/login", strings.NewReader(form.Encode()))
	if err != nil {
		return "", &Error{Fault: FaultTransient, Op: "login", Err: err}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return "", &Error{Fault: classify(0, err), Op: "login", Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// THIS is where a revocation is established. A 401 on a data request only means the token
		// we were holding is no longer good, which is equally consistent with expiry; a 401 on a
		// FRESH login means the credentials themselves were refused.
		fault := classify(resp.StatusCode, nil)

		// ...but only call it a revocation if these credentials ever worked. On a first run, by far
		// the likeliest reading of "invalid credentials" is that the identity file is wrong — and
		// Infisical returns exactly this for a client id that is not a Universal Auth client id,
		// which is a mistake anyone can make, since an identity's own id is also a UUID sitting one
		// panel away. Calling that a revocation would purge and stop a healthy stack over a typo.
		c.mu.Lock()
		everWorked := c.authed
		c.mu.Unlock()
		if fault == FaultIdentityRevoked && !everWorked {
			fault = FaultIdentityRejected
		}

		return "", &Error{
			Fault:  fault,
			Op:     "login",
			Status: resp.StatusCode,
			Err:    fmt.Errorf("universal auth rejected the identity"),
		}
	}

	var out struct {
		AccessToken string `json:"accessToken"`
		ExpiresIn   int    `json:"expiresIn"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", &Error{Fault: FaultUnknown, Op: "login", Status: resp.StatusCode, Err: err}
	}
	if out.AccessToken == "" {
		return "", &Error{Fault: FaultUnknown, Op: "login", Status: resp.StatusCode,
			Err: fmt.Errorf("login succeeded but returned no access token")}
	}

	c.mu.Lock()
	c.authed = true // these credentials work; a later refusal is now a genuine revocation
	c.token = out.AccessToken
	ttl := time.Duration(out.ExpiresIn) * time.Second
	if ttl > tokenSkew {
		c.expires = time.Now().Add(ttl - tokenSkew)
	} else {
		// A TTL shorter than the skew means every request re-logs in. Correct, if wasteful, and far
		// better than treating an expired token as a revocation.
		c.expires = time.Now()
	}
	c.mu.Unlock()
	return out.AccessToken, nil
}

// bearer returns a usable token, logging in if the cached one is missing or near expiry.
func (c *Client) bearer(ctx context.Context) (string, error) {
	c.mu.Lock()
	tok, exp := c.token, c.expires
	c.mu.Unlock()
	if tok != "" && time.Now().Before(exp) {
		return tok, nil
	}
	return c.login(ctx)
}

// secretEntry is one secret as Infisical returns it. Both API versions have used this shape; the
// pointer on secretsRaw.Secrets is what lets us notice if a version ever stops.
type secretEntry struct {
	Key       string    `json:"secretKey"`
	Value     string    `json:"secretValue"`
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// secretsRaw is one listing from Infisical. viewSecretValue=false masks the values server-side, so
// a poll that only needs versions never transports a secret at all.
//
// Secrets is a POINTER so that "the response had no secrets field at all" is distinguishable from
// "the folder is empty". The first means we are talking to something whose shape we do not
// understand and must not trust; the second is ordinary. Decoded into a plain slice, both would
// arrive as nil and an unrecognised API would silently look like an empty vault — which, under
// all-or-nothing rendering, reads as "every secret is missing".
type secretsRaw struct {
	Secrets *[]secretEntry `json:"secrets"`
}

// errWrongShape marks a 200 whose body we could not recognise, so the caller can try another API
// version rather than trusting it.
var errWrongShape = fmt.Errorf("unrecognised response shape")

// list fetches the folder, with or without values, negotiating the API version on first use.
//
// v4 is tried first because v3 is deprecated at source and will eventually be withdrawn; v3 is the
// fallback because v4 does not exist on older instances. Whichever answers is remembered, so the
// negotiation costs one extra request per process, once.
func (c *Client) list(ctx context.Context, withValues bool) (*secretsRaw, error) {
	c.mu.Lock()
	known := c.apiVersion
	c.mu.Unlock()

	candidates := []int{4, 3}
	if known != 0 {
		candidates = []int{known}
	}

	var lastErr error
	for _, v := range candidates {
		raw, err := c.listVersion(ctx, v, withValues)
		if err == nil {
			c.mu.Lock()
			c.apiVersion = v
			c.mu.Unlock()
			return raw, nil
		}
		lastErr = err
		// Only a missing or unintelligible endpoint justifies trying another version. A revoked
		// identity, an outage or a rate limit say nothing about which API we are speaking, and
		// retrying those against a second URL would just double the load during an incident.
		var se *Error
		if errors.As(err, &se) && se.Fault == FaultUnknown &&
			(se.Status == http.StatusNotFound || errors.Is(se.Err, errWrongShape)) {
			continue
		}
		return nil, err
	}
	return nil, lastErr
}

// listVersion performs one listing against a specific API version.
func (c *Client) listVersion(ctx context.Context, version int, withValues bool) (*secretsRaw, error) {
	op := "versions"
	if withValues {
		op = "values"
	}
	endpoint := c.endpoint(version, withValues)

	// One retry, and only for 401. An expired token and a revoked identity are indistinguishable
	// here, so we ask the question that distinguishes them: log in again. If the login works, it
	// was expiry. If the login is refused, the identity is genuinely gone — and that error, from
	// login, is the one that carries FaultIdentityRevoked.
	for attempt := 0; ; attempt++ {
		tok, err := c.bearer(ctx)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, &Error{Fault: FaultTransient, Op: op, Err: err}
		}
		req.Header.Set("Authorization", "Bearer "+tok)

		resp, err := c.httpClient().Do(req)
		if err != nil {
			return nil, &Error{Fault: classify(0, err), Op: op, Err: err}
		}

		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			resp.Body.Close()
			c.mu.Lock()
			c.token, c.expires = "", time.Time{} // force a real login next time round
			c.mu.Unlock()
			continue
		}

		// A 404 HERE is not a missing secret. classify maps 404 to FaultSecretMissing, which is
		// right for a per-key lookup and wrong for a listing: this URL is either served or it is
		// not. A wrong project id, a proxy answering 404 for an unknown host, or an API version
		// this instance does not have would all arrive here and be reported as "your declared keys
		// are missing" — sending someone to audit secrets that are sitting there intact. Missing
		// keys are established from the response BODY, never from a status code.
		if resp.StatusCode == http.StatusNotFound {
			resp.Body.Close()
			return nil, &Error{
				Fault:  FaultUnknown,
				Op:     op,
				Status: resp.StatusCode,
				Err: fmt.Errorf("no secrets endpoint at %s (API v%d) — check the project id %q and "+
					"the path %q", c.BaseURL, version, c.Project, c.Path),
			}
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, &Error{
				Fault:  classify(resp.StatusCode, nil),
				Op:     op,
				Status: resp.StatusCode,
				Err:    fmt.Errorf("listing %s%s", c.Env, c.Path),
			}
		}

		var out secretsRaw
		err = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		if err != nil {
			return nil, &Error{Fault: FaultUnknown, Op: op, Status: resp.StatusCode, Err: err}
		}
		if out.Secrets == nil {
			// 200, valid JSON, no secrets field. We are talking to something we do not understand.
			// Treating this as an empty vault would render nothing and report every key missing.
			return nil, &Error{Fault: FaultUnknown, Op: op, Status: resp.StatusCode,
				Err: fmt.Errorf("%w from API v%d at %s", errWrongShape, version, c.BaseURL)}
		}
		return &out, nil
	}
}

// Versions reports metadata without transporting any secret value.
func (c *Client) Versions(ctx context.Context, keys []string) (map[string]Meta, error) {
	raw, err := c.list(ctx, false)
	if err != nil {
		return nil, err
	}
	want := make(map[string]bool, len(keys))
	for _, k := range keys {
		want[k] = true
	}
	out := make(map[string]Meta, len(keys))
	for _, s := range *raw.Secrets {
		if want[s.Key] {
			out[s.Key] = Meta{Version: s.Version, UpdatedAt: s.UpdatedAt}
		}
	}
	// A key the manifest declares and the store does not have is reported as missing, NOT as a
	// revocation: it is far more often a rename or a typo'd path, and a revocation is destructive.
	if missing := absent(want, out); len(missing) > 0 {
		return out, &Error{
			Fault: FaultSecretMissing,
			Op:    "versions",
			Err:   fmt.Errorf("declared but not in %s%s: %s", c.Env, c.Path, strings.Join(missing, ", ")),
		}
	}
	return out, nil
}

// Values fetches the secrets themselves. Only called once Versions says something moved.
func (c *Client) Values(ctx context.Context, keys []string) (map[string]string, error) {
	raw, err := c.list(ctx, true)
	if err != nil {
		return nil, err
	}
	want := make(map[string]bool, len(keys))
	for _, k := range keys {
		want[k] = true
	}
	out := make(map[string]string, len(keys))
	for _, s := range *raw.Secrets {
		if want[s.Key] {
			out[s.Key] = s.Value
		}
	}
	if missing := absent(want, out); len(missing) > 0 {
		return out, &Error{
			Fault: FaultSecretMissing,
			Op:    "values",
			Err:   fmt.Errorf("declared but not in %s%s: %s", c.Env, c.Path, strings.Join(missing, ", ")),
		}
	}
	return out, nil
}

// absent names the declared keys the store did not return. Sorted, because this string ends up in
// an alert and an alert that reorders itself between polls looks like a new incident each time.
func absent[V any](want map[string]bool, got map[string]V) []string {
	var missing []string
	for k := range want {
		if _, ok := got[k]; !ok {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	return missing
}
