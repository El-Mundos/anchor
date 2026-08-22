// Package config is anchor's own settings — the things that are true of the host, not of any one
// stack.
//
// The split matters: anything a stack owns (its keys, its identity, what to do when they change)
// lives in that stack's manifest, beside its compose file. Only what is genuinely host-wide is
// here. A setting in the wrong file is a setting that gets out of step with the thing it describes.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultPath is where anchor looks unless told otherwise.
const DefaultPath = "/etc/anchor/config.yml"

// ManifestName is the file anchor looks for in each stack directory.
const ManifestName = "anchor.yml"

// Config is the daemon's configuration.
type Config struct {
	// InfisicalURL must be an INTERNAL address. The public hostname sits behind a domain-wide
	// forward-auth that would intercept machine-identity API calls, and routing secrets through the
	// edge proxy would put that proxy on the path of the credentials it needs to start.
	InfisicalURL string `yaml:"infisical_url"`

	// StackRoots are the directories searched for manifests, one level down: /srv/infra/<stack>/.
	StackRoots []string `yaml:"stack_roots"`

	// PollInterval is how often each stack is reconciled. Polling is the guarantee — a missed
	// webhook is silent staleness forever, a missed poll corrects itself on the next one.
	PollInterval time.Duration `yaml:"poll_interval"`

	// AlertmanagerURL is optional. Empty means alerts are logged only, which is a legitimate way to
	// start: a controller that cannot alert is still better than one that also cannot render.
	AlertmanagerURL string `yaml:"alertmanager_url"`

	// BelayURL is optional. When set, recreates are routed through Belay so a rotation inherits its
	// health gate and rollback. When empty, anchor recreates directly and says so — the difference
	// matters enough that it should never be silent.
	BelayURL string `yaml:"belay_url"`
}

// Load reads the config, applying defaults that are safe rather than convenient.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true) // an unknown field is a typo, and a typo is a silent misconfiguration
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func (c *Config) validate() error {
	if c.InfisicalURL == "" {
		return fmt.Errorf("infisical_url is required")
	}
	c.InfisicalURL = strings.TrimRight(c.InfisicalURL, "/")
	if len(c.StackRoots) == 0 {
		return fmt.Errorf("stack_roots is required — anchor would otherwise manage nothing")
	}
	if c.PollInterval == 0 {
		c.PollInterval = time.Minute
	}
	if c.PollInterval < 5*time.Second {
		// Not arbitrary: below this the version pre-check stops being a saving and starts being a
		// denial-of-service against your own secret store.
		return fmt.Errorf("poll_interval %s is too aggressive; 5s is the floor", c.PollInterval)
	}
	return nil
}

// Discover finds every manifest under the configured roots.
//
// It looks exactly one level down (<root>/<stack>/anchor.yml) rather than walking the tree. A
// recursive search would eventually find a manifest inside a backup directory, a .bak copy or an
// old checkout, and start rendering secrets into places nobody remembers.
func (c *Config) Discover() ([]string, error) {
	var found []string
	for _, root := range c.StackRoots {
		entries, err := os.ReadDir(root)
		if err != nil {
			return nil, fmt.Errorf("stack root %s: %w", root, err)
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			p := filepath.Join(root, e.Name(), ManifestName)
			if _, err := os.Stat(p); err == nil {
				found = append(found, p)
			}
		}
	}
	return found, nil
}
