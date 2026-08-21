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
	// Key is the name in the secret store, and the name written into the rendered file.
	Key string `yaml:"key"`

	// SharedState marks a secret that is NOT simply owned by the store: a copy of state living in
	// another system, like a database password the database itself only reads at initialisation.
	//
	// Rotating one of these in the store does not rotate it in the system that checks it, so
	// applying the new value would break the very thing the secret protects. anchor renders these
	// but refuses to act on a change, and says so loudly. Coordinated rotation is a per-system
	// procedure, not something a generic controller can be trusted to improvise.
	SharedState bool `yaml:"shared_state"`
}

// Service is one compose service and what a secret change should do to it.
type Service struct {
	Name   string `yaml:"name"`
	Action Action `yaml:"on_change"`
	// Signal is the signal name for ActionReload, e.g. "HUP".
	Signal string `yaml:"signal"`
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

	Render      Render    `yaml:"render"`
	Destination string    `yaml:"destination"` // rendered file path
	Secrets     []Secret  `yaml:"secrets"`
	Services    []Service `yaml:"services"`

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
	for _, s := range m.Secrets {
		if s.Key == "" {
			return fmt.Errorf("a secret has no key")
		}
		if seen[s.Key] {
			return fmt.Errorf("secret %q declared twice", s.Key)
		}
		seen[s.Key] = true
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

// Keys returns the declared key names, in manifest order.
func (m *Manifest) Keys() []string {
	out := make([]string, 0, len(m.Secrets))
	for _, s := range m.Secrets {
		out = append(out, s.Key)
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
