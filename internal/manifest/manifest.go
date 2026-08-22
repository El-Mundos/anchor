// Package manifest describes what one stack needs from the secret store, and what should happen
// when it changes.
//
// A manifest lives beside the compose file it belongs to, so the declaration travels with the thing
// it configures rather than in a central registry that drifts out of step with reality.
package manifest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Action is what to do to a service once its secrets have changed on disk.
type Action string

const (
	// ActionNone leaves the running container alone. The rendered file moves ahead of what the
	// process is using, so anchor reports the drift rather than pretending they agree.
	ActionNone Action = "none"
	// ActionReload signals the process and trusts it to re-read. Opt-in only: a signal that is
	// delivered but ignored looks exactly like success, so this must be verified per application.
	ActionReload Action = "reload"
	// ActionRecreate replaces the container. Required whenever secrets arrive as environment
	// variables, because a restart reuses the environment baked in at creation.
	ActionRecreate Action = "recreate"
)

// Revoke is what to do to a running service when the store refuses this stack's identity.
//
// This is asked as a separate question from on_change on purpose. on_change is about a secret whose
// VALUE moved; this is about a secret that has been disowned, where the correct outcome may well be
// an outage.
type Revoke string

const (
	// RevokeStop stops the service. The default, and the only choice that makes a revocation real:
	// a running container keeps the environment it was created with, so until it stops, the secret
	// you revoked is still in use.
	RevokeStop Revoke = "stop"
	// RevokeLeave leaves it running and alerts instead. For a service that is useful without the
	// secret, where availability is worth more than promptness. Declared per service because only
	// an operator knows which ones those are — it cannot be discovered at runtime.
	RevokeLeave Revoke = "leave"
)

// Render is how the secrets reach the service.
type Render string

const (
	// RenderFile writes a file the service reads. Rotation can then be a reload, or nothing at all
	// for a service that re-reads on its own.
	RenderFile Render = "file"
	// RenderEnv writes a .env beside the compose file for interpolation. Simple and universal, but
	// it means a rotation can only take effect by recreating the container.
	RenderEnv Render = "env"
)

// Secret is one key this stack needs.
type Secret struct {
	// Key is the name in the secret store.
	Key string `yaml:"key"`

	// As is the name to write into the rendered file, when it differs from Key.
	//
	// Needed because a store is shared and a compose file is not: secrets are commonly namespaced
	// per stack (KALOS_COBRA_SESSION_SECRET) while the compose file wants the bare name
	// (SESSION_SECRET). Without this the two would have to be kept identical, which means either
	// renaming every secret in the store or editing every compose file — and the usual result is a
	// hand-maintained translation step, which is exactly the deploy wrapper anchor exists to delete.
	//
	// Deliberately explicit rather than a stack-wide strip_prefix: a prefix rule is invisible at the
	// point of use, and two keys can silently collapse onto one name.
	As string `yaml:"as"`

	// SharedState marks a secret that is NOT simply owned by the store: a copy of state living in
	// another system, like a database password the database itself only reads at initialisation.
	//
	// Rotating one of these in the store does not rotate it in the system that checks it, so
	// applying the new value would break the very thing the secret protects. anchor renders these
	// but refuses to act on a change, and says so loudly. Coordinated rotation is a per-system
	// procedure, not something a generic controller can be trusted to improvise.
	SharedState bool `yaml:"shared_state"`
}

// Name is what this secret is called in the rendered file.
func (s Secret) Name() string {
	if s.As != "" {
		return s.As
	}
	return s.Key
}

// Service is one compose service and what a secret change should do to it.
type Service struct {
	Name   string `yaml:"name"`
	Action Action `yaml:"on_change"`
	// Signal is the signal name for ActionReload, e.g. "HUP".
	Signal string `yaml:"signal"`
	// Revoke is what happens to this service when the identity is revoked. Defaults to stop.
	Revoke Revoke `yaml:"on_revoke"`
}

// Manifest is one stack's declaration.
type Manifest struct {
	// Project is the Infisical project id, Env its environment ("prod"), Path the secret folder.
	Project string `yaml:"project"`
	Env     string `yaml:"env"`
	Path    string `yaml:"path"`

	// IdentityFile holds the machine identity for THIS stack. Per-stack on purpose: a leaked
	// identity should expose one stack's secrets, not the fleet's.
	IdentityFile string `yaml:"identity_file"`

	Render      Render `yaml:"render"`
	Destination string `yaml:"destination"` // rendered file path

	// Adopt permits anchor to overwrite a destination that already exists and was NOT written by
	// anchor.
	//
	// Off by default, and the default is the whole point. A stack being migrated almost always has
	// a .env already, and it commonly holds more than secrets — ports, hostnames, feature flags.
	// Silently replacing it with only the declared keys deletes the rest, and compose turns the
	// difference into empty strings rather than an error: the container starts healthy with a blank
	// value in it, which is the incident anchor exists to prevent. Requiring this to be set forces
	// someone to open the file first, which is exactly when the undeclared variables get noticed.
	Adopt    bool      `yaml:"adopt"`
	Secrets  []Secret  `yaml:"secrets"`
	Services []Service `yaml:"services"`

	// Dir is where this manifest was found; not part of the file.
	Dir string `yaml:"-"`
}

// Load reads and validates a manifest.
//
// Validation is strict and happens at load, not at rotation time. A typo in an action would
// otherwise sit harmlessly in a file for months and then, on the one day a secret rotates, do
// nothing at all — at the exact moment nobody is watching.
func Load(path string) (*Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true) // an unknown field is a typo, and a typo is a silent misconfiguration
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	m.Dir = filepath.Dir(path)
	if err := m.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &m, nil
}

func (m *Manifest) validate() error {
	if m.Project == "" {
		return fmt.Errorf("project is required")
	}
	if m.Env == "" {
		m.Env = "prod"
	}
	if m.Path == "" {
		m.Path = "/"
	}
	if m.IdentityFile == "" {
		return fmt.Errorf("identity_file is required (this stack's own machine identity)")
	}
	switch m.Render {
	case "":
		m.Render = RenderEnv
	case RenderEnv, RenderFile:
	default:
		return fmt.Errorf("render: %q is not one of %q, %q", m.Render, RenderEnv, RenderFile)
	}
	if m.Destination == "" {
		if m.Render != RenderEnv {
			return fmt.Errorf("destination is required when render is %q", m.Render)
		}
		m.Destination = filepath.Join(m.Dir, ".env")
	}
	if !filepath.IsAbs(m.Destination) {
		m.Destination = filepath.Join(m.Dir, m.Destination)
	}
	if len(m.Secrets) == 0 {
		return fmt.Errorf("no secrets declared — a manifest that asks for nothing does nothing")
	}
	seen := map[string]bool{}
	rendered := map[string]string{}
	for _, s := range m.Secrets {
		if s.Key == "" {
			return fmt.Errorf("a secret has no key")
		}
		if seen[s.Key] {
			return fmt.Errorf("secret %q declared twice", s.Key)
		}
		seen[s.Key] = true
		// Two store keys rendering to one name would silently drop one of them: the map would keep
		// whichever was written last, the file would look complete, and all-or-nothing would be
		// satisfied. Exactly the shape of failure this project exists to refuse, so it is caught at
		// load where it is a typo rather than at rotation where it is an outage.
		name := s.Name()
		if first, dup := rendered[name]; dup {
			return fmt.Errorf("secrets %q and %q both render as %q — one would silently overwrite "+
				"the other", first, s.Key, name)
		}
		rendered[name] = s.Key
	}
	for i := range m.Services {
		sv := &m.Services[i]
		if sv.Name == "" {
			return fmt.Errorf("a service has no name")
		}
		switch sv.Action {
		case "":
			// Recreate is the default because it is the only action that always works. A reload
			// that the application ignores is indistinguishable from one it honoured.
			sv.Action = ActionRecreate
		case ActionNone, ActionRecreate:
		case ActionReload:
			if sv.Signal == "" {
				sv.Signal = "HUP"
			}
		default:
			return fmt.Errorf("service %s: on_change: %q is not one of %q, %q, %q",
				sv.Name, sv.Action, ActionNone, ActionReload, ActionRecreate)
		}
		switch sv.Revoke {
		case "":
			// Stop by default: a revocation that leaves the secret in use has not happened yet.
			sv.Revoke = RevokeStop
		case RevokeStop, RevokeLeave:
		case "restart":
			// Rejected explicitly rather than falling into the generic error, because it is the
			// intuitive choice and it is a trap. A revocation has already purged the rendered file,
			// so a restart either fails against a guarded variable — a crash-loop where a clean
			// stop was available — or, unguarded, interpolates to empty and comes back HEALTHY with
			// no credentials. That is the exact silent failure this project exists to prevent, and
			// a revocation is the worst possible moment to reintroduce it. A service that genuinely
			// works without the secret should say so with %q.
			return fmt.Errorf("service %s: on_revoke: \"restart\" is not offered — the rendered file "+
				"is already purged, so a restart either fails on a guarded variable or silently "+
				"starts with blank secrets; use %q if this service works without them",
				sv.Name, RevokeLeave)
		default:
			return fmt.Errorf("service %s: on_revoke: %q is not one of %q, %q",
				sv.Name, sv.Revoke, RevokeStop, RevokeLeave)
		}
	}
	if m.Render == RenderEnv {
		for _, sv := range m.Services {
			if sv.Action == ActionReload {
				return fmt.Errorf("service %s: on_change: reload cannot work with render: env — "+
					"a restart reuses the environment baked in at creation, so only recreate applies "+
					"a new value", sv.Name)
			}
		}
	}
	return nil
}

// Stack is the stack's name, taken from its directory. Used in logs and alerts, where "kalos-cobra"
// is what someone recognises at 3am and a full path is not.
func (m *Manifest) Stack() string {
	return filepath.Base(m.Dir)
}

// Keys returns the store key names, in manifest order. This is what to ask the store for.
func (m *Manifest) Keys() []string {
	out := make([]string, 0, len(m.Secrets))
	for _, s := range m.Secrets {
		out = append(out, s.Key)
	}
	return out
}

// Names returns the rendered names, in manifest order. This is what the file will contain.
func (m *Manifest) Names() []string {
	out := make([]string, 0, len(m.Secrets))
	for _, s := range m.Secrets {
		out = append(out, s.Name())
	}
	return out
}

// Rename maps fetched values from store keys to rendered names.
//
// A key the store did not return is left absent rather than written as empty, so the completeness
// check downstream still sees it as missing. Translating a gap into an empty string here would
// defeat the one rule everything else depends on.
func (m *Manifest) Rename(values map[string]string) map[string]string {
	out := make(map[string]string, len(values))
	for _, s := range m.Secrets {
		if v, ok := values[s.Key]; ok {
			out[s.Name()] = v
		}
	}
	return out
}

// SharedStateKeys are the keys anchor renders but refuses to act on automatically.
func (m *Manifest) SharedStateKeys() []string {
	var out []string
	for _, s := range m.Secrets {
		if s.SharedState {
			out = append(out, s.Key)
		}
	}
	return out
}
