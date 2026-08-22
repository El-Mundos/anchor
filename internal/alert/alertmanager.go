// Package alert delivers anchor's alerts to Alertmanager.
//
// Alertmanager rather than Karma: Karma is only a UI over Alertmanager's API, so anything posted
// here appears there with no further integration.
package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/El-Mundos/anchor/internal/reconcile"
)

// Alertmanager posts to the v2 alerts endpoint.
type Alertmanager struct {
	URL  string // e.g. http://localhost:9093/api/v2/alerts
	HTTP *http.Client
}

type amAlert struct {
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	StartsAt     time.Time         `json:"startsAt"`
	GeneratorURL string            `json:"generatorURL,omitempty"`
}

// Alert delivers one alert.
//
// The labelling mirrors what Belay learned the hard way: a per-stack alertname, plus a source
// label. Alertmanager groups by label set, so a single shared alertname would collapse every
// stack's problems into one Karma group — and a second stack failing would silently join an
// existing group rather than appearing as news.
func (a *Alertmanager) Alert(ctx context.Context, in reconcile.Alert) error {
	if a.URL == "" {
		return nil
	}
	severity := in.Severity
	if severity == "" {
		severity = "warning"
	}

	body, err := json.Marshal([]amAlert{{
		Labels: map[string]string{
			"alertname": fmt.Sprintf("(anchor) %s", in.Stack),
			"stack":     in.Stack,
			"severity":  severity,
			"source":    "anchor",
		},
		Annotations: map[string]string{
			"summary":     in.Summary,
			"description": in.Detail,
		},
		// Alertmanager expires an alert that stops being re-sent, so a resolved problem clears
		// itself once anchor stops reporting it. No explicit resolve is needed, and none is sent:
		// an explicit resolve that got lost would leave a stale alert forever.
		StartsAt: time.Now(),
	}})
	if err != nil {
		return err
	}

	client := a.HTTP
	if client == nil {
		// Short: alerting is best-effort and must never become the slow path. reconcile logs and
		// swallows the error, so a hung Alertmanager delays a pass rather than stopping it.
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("alertmanager returned %d", resp.StatusCode)
	}
	return nil
}
