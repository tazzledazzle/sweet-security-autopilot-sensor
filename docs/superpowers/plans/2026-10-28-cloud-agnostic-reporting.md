# Cloud-Agnostic Architecture and Grafana Reporting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the hardcoded Sweet Security coupling in the controller with a pluggable `AlertBus` fan-out dispatcher; add a Grafana annotation sink and enriched Prometheus metrics; introduce a Kubernetes-native audit webhook handler; and remove all hardcoded GCP defaults from config and Helm.

**Architecture:** New packages `pkg/reporting/sink` (interface), `pkg/reporting/bus` (dispatcher), `pkg/reporting/grafana` (annotation sink + metrics), and `internal/audit` (K8s webhook handler). The controller publishes alerts to the bus instead of calling Sweet Security directly. Sweet Security becomes a registered `AlertSink` via a thin adapter in `pkg/sweetsecurity/sink.go`. All GCP-specific defaults are removed from `internal/config` and `deploy/helm/values.yaml`.

**Tech Stack:** Go 1.22, `prometheus/client_golang`, standard `net/http`, `k8s.io/apimachinery` (already in go.mod), Helm 3.

## Global Constraints

- All existing tests must continue to pass after each task
- No new external dependencies — use only packages already in `go.mod`
- `default_visibility = ["//visibility:private"]` — run `bazel run //:gazelle` after each new package
- `CLUSTER_NAME`, `CLUSTER_PROVIDER`, `CLUSTER_REGION`, `GRAFANA_ENDPOINT`, `GRAFANA_API_KEY` are injected via environment variables
- The bus is non-blocking per sink — a failing Grafana sink must never delay Sweet Security delivery
- After this spec, `config.DefaultWebhookConfig().SidecarImage` returns `""` — callers must set `SIDECAR_IMAGE` env var

---

### Task 1: `pkg/reporting/sink` — AlertSink interface

**Files:**
- Create: `pkg/reporting/sink/sink.go`
- Create: `pkg/reporting/sink/sink_test.go`

**Interfaces:**
- Produces:
  - `sink.AlertSink` interface with `Name() string` and `Send(ctx context.Context, alert *types.Alert) error`
  - `sink.Filter` type: `func(alert *types.Alert) bool`
  - `sink.Registration` struct with `Sink AlertSink` and `Filter Filter`

- [ ] **Step 1: Write the failing test**

Create `pkg/reporting/sink/sink_test.go`:

```go
package sink_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/invisible-tech/autopilot-security-sensor/internal/types"
	"github.com/invisible-tech/autopilot-security-sensor/pkg/reporting/sink"
)

// mockSink implements AlertSink for testing.
type mockSink struct {
	name   string
	sendFn func(context.Context, *types.Alert) error
}

func (m *mockSink) Name() string { return m.name }
func (m *mockSink) Send(ctx context.Context, alert *types.Alert) error {
	return m.sendFn(ctx, alert)
}

func TestAlertSink_Interface(t *testing.T) {
	var s sink.AlertSink = &mockSink{
		name:   "test",
		sendFn: func(_ context.Context, _ *types.Alert) error { return nil },
	}
	if s.Name() != "test" {
		t.Errorf("Name() = %q, want %q", s.Name(), "test")
	}
	alert := &types.Alert{ID: "a1", Severity: "HIGH"}
	if err := s.Send(context.Background(), alert); err != nil {
		t.Errorf("Send() unexpected error: %v", err)
	}
}

func TestFilter_NilAcceptsAll(t *testing.T) {
	alert := &types.Alert{ID: "a1", Severity: "LOW"}
	reg := sink.Registration{
		Sink:   &mockSink{name: "s", sendFn: func(_ context.Context, _ *types.Alert) error { return nil }},
		Filter: nil,
	}
	// nil filter means accept all — calling it would panic, so check for nil before calling
	if reg.Filter != nil && !reg.Filter(alert) {
		t.Error("non-nil filter unexpectedly rejected alert")
	}
}

func TestFilter_BySeverity(t *testing.T) {
	criticalOnly := sink.Filter(func(a *types.Alert) bool {
		return a.Severity == "CRITICAL"
	})
	high := &types.Alert{Severity: "HIGH"}
	critical := &types.Alert{Severity: "CRITICAL"}
	if criticalOnly(high) {
		t.Error("filter should reject HIGH")
	}
	if !criticalOnly(critical) {
		t.Error("filter should accept CRITICAL")
	}
}

func TestSendError(t *testing.T) {
	want := errors.New("downstream unavailable")
	s := &mockSink{
		name:   "failing",
		sendFn: func(_ context.Context, _ *types.Alert) error { return want },
	}
	alert := &types.Alert{ID: "a1", Timestamp: time.Now()}
	err := s.Send(context.Background(), alert)
	if !errors.Is(err, want) {
		t.Errorf("Send() = %v, want %v", err, want)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./pkg/reporting/sink/...
```

Expected: `cannot find package "github.com/invisible-tech/autopilot-security-sensor/pkg/reporting/sink"`

- [ ] **Step 3: Create `pkg/reporting/sink/sink.go`**

```go
package sink

import (
	"context"
	"time"

	"github.com/invisible-tech/autopilot-security-sensor/internal/types"
)

// AlertSink receives security alerts for processing or forwarding.
type AlertSink interface {
	Name() string
	Send(ctx context.Context, alert *types.Alert) error
}

// Filter is a predicate on an alert. Return true to allow, false to skip.
// A nil Filter means accept all (fan-out behavior).
type Filter func(alert *types.Alert) bool

// Registration pairs a sink with its optional filter.
// Per-sink timeouts are not supported — the bus default applies to all sinks.
type Registration struct {
	Sink   AlertSink
	Filter Filter // nil = accept all
}

// Severity constants mirror types.Alert.Severity for use in Filter predicates.
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

// _ ensures the unused time import compiles (Registration may be extended later).
var _ = time.Second
```

Wait — the `time` import is unused. Remove it:

```go
package sink

import (
	"context"

	"github.com/invisible-tech/autopilot-security-sensor/internal/types"
)

// AlertSink receives security alerts for processing or forwarding.
type AlertSink interface {
	Name() string
	Send(ctx context.Context, alert *types.Alert) error
}

// Filter is a predicate on an alert. Return true to allow, false to skip.
// A nil Filter means accept all (fan-out behavior).
type Filter func(alert *types.Alert) bool

// Registration pairs a sink with its optional filter.
type Registration struct {
	Sink   AlertSink
	Filter Filter // nil = accept all
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./pkg/reporting/sink/... -v
```

Expected: All 4 tests pass.

- [ ] **Step 5: Update Gazelle BUILD files**

```bash
bazel run //:gazelle
```

- [ ] **Step 6: Commit**

```bash
git add pkg/reporting/sink/
git commit -m "feat: add AlertSink interface and Registration type"
```

---

### Task 2: `pkg/reporting/bus` — AlertBus dispatcher

**Files:**
- Create: `pkg/reporting/bus/bus.go`
- Create: `pkg/reporting/bus/metrics.go`
- Create: `pkg/reporting/bus/bus_test.go`

**Interfaces:**
- Consumes: `sink.AlertSink`, `sink.Filter`, `sink.Registration` from Task 1
- Produces:
  - `bus.New(defaultTimeout time.Duration, log *logrus.Logger) *Bus`
  - `(*Bus).Register(s sink.AlertSink, f sink.Filter)`
  - `(*Bus).Publish(ctx context.Context, alert *types.Alert) error` — fans out concurrently; returns error only if ALL sinks fail
  - Prometheus metrics: `apss_sink_send_duration_seconds{sink}`, `apss_sink_errors_total{sink}`

- [ ] **Step 1: Write the failing tests**

Create `pkg/reporting/bus/bus_test.go`:

```go
package bus_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/invisible-tech/autopilot-security-sensor/internal/types"
	"github.com/invisible-tech/autopilot-security-sensor/pkg/reporting/bus"
	"github.com/invisible-tech/autopilot-security-sensor/pkg/reporting/sink"
)

type countSink struct {
	name  string
	calls atomic.Int64
	err   error
}

func (s *countSink) Name() string { return s.name }
func (s *countSink) Send(_ context.Context, _ *types.Alert) error {
	s.calls.Add(1)
	return s.err
}

func newLog() *logrus.Logger {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	return l
}

func alert() *types.Alert {
	return &types.Alert{ID: "a1", Severity: "HIGH", Timestamp: time.Now()}
}

func TestBus_Publish_FanOut(t *testing.T) {
	b := bus.New(5*time.Second, newLog())
	s1 := &countSink{name: "s1"}
	s2 := &countSink{name: "s2"}
	b.Register(s1, nil)
	b.Register(s2, nil)

	if err := b.Publish(context.Background(), alert()); err != nil {
		t.Errorf("Publish() unexpected error: %v", err)
	}
	if s1.calls.Load() != 1 {
		t.Errorf("s1 calls = %d, want 1", s1.calls.Load())
	}
	if s2.calls.Load() != 1 {
		t.Errorf("s2 calls = %d, want 1", s2.calls.Load())
	}
}

func TestBus_Publish_FilterBlocks(t *testing.T) {
	b := bus.New(5*time.Second, newLog())
	s := &countSink{name: "critical-only"}
	b.Register(s, func(a *types.Alert) bool { return a.Severity == "CRITICAL" })

	_ = b.Publish(context.Background(), &types.Alert{Severity: "HIGH"})
	if s.calls.Load() != 0 {
		t.Errorf("filtered sink called %d times, want 0", s.calls.Load())
	}

	_ = b.Publish(context.Background(), &types.Alert{Severity: "CRITICAL"})
	if s.calls.Load() != 1 {
		t.Errorf("sink calls after CRITICAL = %d, want 1", s.calls.Load())
	}
}

func TestBus_Publish_OneSinkFails_OthersStillCalled(t *testing.T) {
	b := bus.New(5*time.Second, newLog())
	failing := &countSink{name: "fail", err: errors.New("down")}
	working := &countSink{name: "ok"}
	b.Register(failing, nil)
	b.Register(working, nil)

	err := b.Publish(context.Background(), alert())
	// Not all sinks failed (working succeeded) — should return nil
	if err != nil {
		t.Errorf("Publish() = %v, want nil when at least one sink succeeds", err)
	}
	if working.calls.Load() != 1 {
		t.Errorf("working sink calls = %d, want 1", working.calls.Load())
	}
}

func TestBus_Publish_AllSinksFail_ReturnsError(t *testing.T) {
	b := bus.New(5*time.Second, newLog())
	b.Register(&countSink{name: "f1", err: errors.New("err1")}, nil)
	b.Register(&countSink{name: "f2", err: errors.New("err2")}, nil)

	err := b.Publish(context.Background(), alert())
	if err == nil {
		t.Error("Publish() = nil, want error when all sinks fail")
	}
}

func TestBus_Publish_NoSinks(t *testing.T) {
	b := bus.New(5*time.Second, newLog())
	if err := b.Publish(context.Background(), alert()); err != nil {
		t.Errorf("Publish() with no sinks = %v, want nil", err)
	}
}

func TestBus_Publish_RespectsTimeout(t *testing.T) {
	b := bus.New(50*time.Millisecond, newLog())
	slow := &slowSink{delay: 500 * time.Millisecond}
	b.Register(slow, nil)

	start := time.Now()
	_ = b.Publish(context.Background(), alert())
	elapsed := time.Since(start)

	if elapsed > 200*time.Millisecond {
		t.Errorf("Publish took %v, timeout should have fired at ~50ms", elapsed)
	}
}

type slowSink struct{ delay time.Duration }

func (s *slowSink) Name() string { return "slow" }
func (s *slowSink) Send(ctx context.Context, _ *types.Alert) error {
	select {
	case <-time.After(s.delay):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./pkg/reporting/bus/... 2>&1 | head -5
```

Expected: `cannot find package ".../pkg/reporting/bus"`

- [ ] **Step 3: Create `pkg/reporting/bus/metrics.go`**

```go
package bus

import "github.com/prometheus/client_golang/prometheus"

var (
	sinkSendDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "apss_sink_send_duration_seconds",
			Help:    "Duration of alert sink send operations in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"sink"},
	)
	sinkErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "apss_sink_errors_total",
			Help: "Total number of alert sink errors.",
		},
		[]string{"sink"},
	)
)

func init() {
	prometheus.MustRegister(sinkSendDuration, sinkErrors)
}
```

- [ ] **Step 4: Create `pkg/reporting/bus/bus.go`**

```go
package bus

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/invisible-tech/autopilot-security-sensor/internal/types"
	"github.com/invisible-tech/autopilot-security-sensor/pkg/reporting/sink"
)

// Bus fans out alerts to all registered sinks concurrently.
type Bus struct {
	mu      sync.RWMutex
	sinks   []sink.Registration
	timeout time.Duration
	log     *logrus.Logger
}

// New creates a Bus with the given per-sink timeout and logger.
func New(defaultTimeout time.Duration, log *logrus.Logger) *Bus {
	return &Bus{timeout: defaultTimeout, log: log}
}

// Register adds a sink. Pass nil for f to receive all alerts (fan-out).
func (b *Bus) Register(s sink.AlertSink, f sink.Filter) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sinks = append(b.sinks, sink.Registration{Sink: s, Filter: f})
}

// Publish fans out alert to all sinks whose filter accepts it.
// Each sink runs concurrently with its own timeout context.
// Errors are logged but never block other sinks.
// Returns non-nil only when ALL sinks fail (or there are no sinks, returns nil).
func (b *Bus) Publish(ctx context.Context, alert *types.Alert) error {
	b.mu.RLock()
	regs := make([]sink.Registration, len(b.sinks))
	copy(regs, b.sinks)
	b.mu.RUnlock()

	if len(regs) == 0 {
		return nil
	}

	type result struct{ err error }
	results := make(chan result, len(regs))

	for _, reg := range regs {
		if reg.Filter != nil && !reg.Filter(alert) {
			results <- result{}
			continue
		}
		go func(r sink.Registration) {
			sinkCtx, cancel := context.WithTimeout(ctx, b.timeout)
			defer cancel()

			start := time.Now()
			err := r.Sink.Send(sinkCtx, alert)
			sinkSendDuration.WithLabelValues(r.Sink.Name()).Observe(time.Since(start).Seconds())

			if err != nil {
				sinkErrors.WithLabelValues(r.Sink.Name()).Inc()
				b.log.WithError(err).WithField("sink", r.Sink.Name()).Error("alert sink failed")
			}
			results <- result{err: err}
		}(reg)
	}

	var failCount int
	for range regs {
		if r := <-results; r.err != nil {
			failCount++
		}
	}
	if failCount > 0 && failCount == len(regs) {
		return fmt.Errorf("all %d alert sinks failed", failCount)
	}
	return nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
go test ./pkg/reporting/bus/... -v
```

Expected: 6 tests pass, including the timeout test.

- [ ] **Step 6: Update Gazelle and commit**

```bash
bazel run //:gazelle
git add pkg/reporting/bus/
git commit -m "feat: add AlertBus fan-out dispatcher with Prometheus observability"
```

---

### Task 3: `pkg/sweetsecurity/sink.go` — AlertSink adapter

**Files:**
- Create: `pkg/sweetsecurity/sink.go`
- Create: `pkg/sweetsecurity/sink_test.go`

**Interfaces:**
- Consumes: `sink.AlertSink` (Task 1), existing `sweetsecurity.Client`, `config.ControllerConfig`
- Produces:
  - `sweetsecurity.NewSink(cfg config.ControllerConfig, log *logrus.Logger) *Sink`
  - `(*Sink).Name() string` → `"sweet-security"`
  - `(*Sink).Send(ctx context.Context, alert *types.Alert) error`

- [ ] **Step 1: Write the failing test**

Create `pkg/sweetsecurity/sink_test.go`:

```go
package sweetsecurity_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/invisible-tech/autopilot-security-sensor/internal/config"
	"github.com/invisible-tech/autopilot-security-sensor/internal/types"
	"github.com/invisible-tech/autopilot-security-sensor/pkg/sweetsecurity"
)

func TestSink_Name(t *testing.T) {
	log := logrus.New()
	s := sweetsecurity.NewSink(config.ControllerConfig{}, log)
	if s.Name() != "sweet-security" {
		t.Errorf("Name() = %q, want %q", s.Name(), "sweet-security")
	}
}

func TestSink_Send_PostsAlert(t *testing.T) {
	var received Alert
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	log := logrus.New()
	cfg := config.ControllerConfig{
		SweetSecurityEnabled:  true,
		SweetSecurityEndpoint: srv.URL,
		SweetSecurityAPIKey:   "test-key",
		SweetSecurityTimeout:  5 * time.Second,
	}
	s := sweetsecurity.NewSink(cfg, log)

	alert := &types.Alert{
		ID: "a1", Severity: "CRITICAL", RuleID: "APSS-001",
		RuleName: "Reverse Shell", Description: "desc",
		PodName: "pod", PodNS: "ns",
		Timestamp: time.Now(),
		Metadata:  map[string]interface{}{"cluster": "test-cluster"},
	}
	if err := s.Send(context.Background(), alert); err != nil {
		t.Fatalf("Send() error: %v", err)
	}
	if received.ID != "a1" {
		t.Errorf("received.ID = %q, want %q", received.ID, "a1")
	}
}

func TestSink_Send_NotConfigured_ReturnsError(t *testing.T) {
	log := logrus.New()
	s := sweetsecurity.NewSink(config.ControllerConfig{SweetSecurityEnabled: false}, log)
	err := s.Send(context.Background(), &types.Alert{ID: "a1"})
	if err == nil {
		t.Error("expected error when sink not configured, got nil")
	}
}

// Alert mirrors the JSON shape sent to Sweet Security for test assertions.
type Alert struct {
	ID string `json:"id"`
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./pkg/sweetsecurity/... -run TestSink 2>&1 | head -5
```

Expected: `undefined: sweetsecurity.NewSink`

- [ ] **Step 3: Add `Metadata` field to `types.Alert`**

Edit `internal/types/alerts.go` — add `Metadata` field to `Alert`:

```go
// Alert is a generated security alert from the detection engine.
type Alert struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Severity    string                 `json:"severity"`
	RuleID      string                 `json:"rule_id"`
	RuleName    string                 `json:"rule_name"`
	Description string                 `json:"description"`
	EventIDs    []string               `json:"event_ids"`
	PodName     string                 `json:"pod_name"`
	PodNS       string                 `json:"pod_namespace"`
	MitreTactic string                 `json:"mitre_tactic,omitempty"`
	MitreID     string                 `json:"mitre_id,omitempty"`
	Actions     []string               `json:"recommended_actions"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}
```

Run existing tests to confirm nothing breaks:

```bash
go test ./internal/types/... ./internal/controller/... -v
```

Expected: all pass.

- [ ] **Step 4: Create `pkg/sweetsecurity/sink.go`**

```go
package sweetsecurity

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/invisible-tech/autopilot-security-sensor/internal/config"
	"github.com/invisible-tech/autopilot-security-sensor/internal/types"
)

// Sink adapts Client to the sink.AlertSink interface.
type Sink struct {
	client *Client
	log    *logrus.Logger
}

// NewSink creates an AlertSink backed by a Sweet Security client.
// Returns a Sink that errors on Send() when SweetSecurityEnabled is false.
func NewSink(cfg config.ControllerConfig, log *logrus.Logger) *Sink {
	var client *Client
	if cfg.SweetSecurityEnabled {
		client = NewClient(Config{
			APIEndpoint: cfg.SweetSecurityEndpoint,
			APIKey:      cfg.SweetSecurityAPIKey,
			Timeout:     cfg.SweetSecurityTimeout,
		}, log)
	}
	return &Sink{client: client, log: log}
}

// Name returns the sink identifier used in metrics labels.
func (s *Sink) Name() string { return "sweet-security" }

// Send forwards an alert to the Sweet Security API.
func (s *Sink) Send(ctx context.Context, alert *types.Alert) error {
	if s.client == nil {
		return fmt.Errorf("sweet-security sink not configured")
	}
	sweetAlert := &Alert{
		ID:           alert.ID,
		Timestamp:    alert.Timestamp,
		Severity:     alert.Severity,
		RuleID:       alert.RuleID,
		RuleName:     alert.RuleName,
		Description:  alert.Description,
		PodName:      alert.PodName,
		PodNamespace: alert.PodNS,
		MitreTactic:  alert.MitreTactic,
		MitreID:      alert.MitreID,
		EventIDs:     alert.EventIDs,
		Metadata: map[string]interface{}{
			"source":              "apss-autopilot-security-sensor",
			"recommended_actions": alert.Actions,
		},
	}
	for k, v := range alert.Metadata {
		sweetAlert.Metadata[k] = v
	}
	return s.client.SendAlert(ctx, sweetAlert)
}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
go test ./pkg/sweetsecurity/... -v
```

Expected: all tests pass including the new `TestSink_*` tests.

- [ ] **Step 6: Update Gazelle and commit**

```bash
bazel run //:gazelle
git add internal/types/alerts.go pkg/sweetsecurity/sink.go pkg/sweetsecurity/sink_test.go
git commit -m "feat: add Metadata to Alert, add Sweet Security AlertSink adapter"
```

---

### Task 4: `pkg/reporting/grafana/annotations.go` — Grafana annotation sink

**Files:**
- Create: `pkg/reporting/grafana/annotations.go`
- Create: `pkg/reporting/grafana/annotations_test.go`

**Interfaces:**
- Consumes: `sink.AlertSink` (Task 1), `config.GrafanaConfig` (Task 7 — write config first, or use raw fields here)
- Produces:
  - `grafana.NewAnnotationSink(endpoint, apiKey string, log *logrus.Logger) *AnnotationSink`
  - `(*AnnotationSink).Name() string` → `"grafana-annotations"`
  - `(*AnnotationSink).Send(ctx context.Context, alert *types.Alert) error` — POSTs to `/api/annotations`

**Note:** `config.GrafanaConfig` is added in Task 7. This task uses `endpoint string, apiKey string` directly to avoid a dependency cycle. The wiring in `cmd/controller/main.go` (Task 10) passes values from `GrafanaConfig`.

- [ ] **Step 1: Write the failing test**

Create `pkg/reporting/grafana/annotations_test.go`:

```go
package grafana_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/invisible-tech/autopilot-security-sensor/internal/types"
	"github.com/invisible-tech/autopilot-security-sensor/pkg/reporting/grafana"
)

func newTestLog() *logrus.Logger {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	return l
}

func TestAnnotationSink_Name(t *testing.T) {
	s := grafana.NewAnnotationSink("http://grafana:3000", "key", newTestLog())
	if s.Name() != "grafana-annotations" {
		t.Errorf("Name() = %q, want %q", s.Name(), "grafana-annotations")
	}
}

func TestAnnotationSink_Send_PostsAnnotation(t *testing.T) {
	type annotation struct {
		Time     int64    `json:"time"`
		Text     string   `json:"text"`
		Tags     []string `json:"tags"`
		IsRegion bool     `json:"isRegion"`
	}
	var got annotation
	var gotAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/annotations" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := grafana.NewAnnotationSink(srv.URL, "mykey", newTestLog())
	alert := &types.Alert{
		ID:          "a1",
		Severity:    "CRITICAL",
		Description: "Reverse shell detected",
		RuleID:      "APSS-001",
		MitreTactic: "Command and Control",
		PodName:     "pod-1",
		PodNS:       "default",
		Timestamp:   time.Unix(1700000000, 0),
	}

	if err := s.Send(context.Background(), alert); err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	if got.Time != alert.Timestamp.UnixMilli() {
		t.Errorf("annotation.Time = %d, want %d", got.Time, alert.Timestamp.UnixMilli())
	}
	if got.IsRegion {
		t.Error("IsRegion should be false")
	}
	if gotAuth != "Bearer mykey" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer mykey")
	}

	foundSeverity := false
	for _, tag := range got.Tags {
		if tag == "CRITICAL" {
			foundSeverity = true
		}
	}
	if !foundSeverity {
		t.Errorf("Tags %v should contain severity CRITICAL", got.Tags)
	}
}

func TestAnnotationSink_Send_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	s := grafana.NewAnnotationSink(srv.URL, "key", newTestLog())
	err := s.Send(context.Background(), &types.Alert{ID: "a1", Timestamp: time.Now()})
	if err == nil {
		t.Error("expected error on HTTP 500, got nil")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./pkg/reporting/grafana/... 2>&1 | head -5
```

Expected: `cannot find package ".../pkg/reporting/grafana"`

- [ ] **Step 3: Create `pkg/reporting/grafana/annotations.go`**

```go
package grafana

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/invisible-tech/autopilot-security-sensor/internal/types"
)

// AnnotationSink sends Grafana annotations when alerts fire.
type AnnotationSink struct {
	endpoint string
	apiKey   string
	client   *http.Client
	log      *logrus.Logger
}

// NewAnnotationSink creates a sink that POSTs to Grafana's /api/annotations endpoint.
func NewAnnotationSink(endpoint, apiKey string, log *logrus.Logger) *AnnotationSink {
	return &AnnotationSink{
		endpoint: endpoint,
		apiKey:   apiKey,
		client:   &http.Client{Timeout: 10 * time.Second},
		log:      log,
	}
}

// Name returns the sink identifier used in metrics labels.
func (s *AnnotationSink) Name() string { return "grafana-annotations" }

// Send posts an annotation to Grafana for the given alert.
func (s *AnnotationSink) Send(ctx context.Context, alert *types.Alert) error {
	payload := grafanaAnnotation{
		Time:     alert.Timestamp.UnixMilli(),
		Text:     fmt.Sprintf("[%s] %s — %s/%s", alert.Severity, alert.Description, alert.PodNS, alert.PodName),
		Tags:     []string{"apss", alert.Severity, alert.RuleID, alert.MitreTactic},
		IsRegion: false,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal annotation: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint+"/api/annotations", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.apiKey)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("send annotation: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("grafana returned status %d", resp.StatusCode)
	}
	return nil
}

type grafanaAnnotation struct {
	Time     int64    `json:"time"`
	Text     string   `json:"text"`
	Tags     []string `json:"tags"`
	IsRegion bool     `json:"isRegion"`
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./pkg/reporting/grafana/... -v
```

Expected: 3 tests pass.

- [ ] **Step 5: Update Gazelle and commit**

```bash
bazel run //:gazelle
git add pkg/reporting/grafana/
git commit -m "feat: add Grafana annotation sink"
```

---

### Task 5: `pkg/reporting/grafana/metrics.go` — enriched alert metrics

**Files:**
- Create: `pkg/reporting/grafana/metrics.go`
- Create: `pkg/reporting/grafana/metrics_test.go`

**Interfaces:**
- Consumes: `sink.AlertSink` (Task 1), `types.Alert`
- Produces:
  - `grafana.NewMetricsSink() *MetricsSink` — an `AlertSink` that records MITRE/severity metrics
  - `(*MetricsSink).Name() string` → `"grafana-metrics"`
  - `(*MetricsSink).Send(ctx context.Context, alert *types.Alert) error`
  - Prometheus metrics: `apss_alerts_by_mitre_total{tactic,technique_id,severity}`, `apss_alert_severity_gauge{severity}`

- [ ] **Step 1: Write the failing test**

Create `pkg/reporting/grafana/metrics_test.go`:

```go
package grafana_test

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/invisible-tech/autopilot-security-sensor/internal/types"
	"github.com/invisible-tech/autopilot-security-sensor/pkg/reporting/grafana"
)

func TestMetricsSink_Name(t *testing.T) {
	s := grafana.NewMetricsSink()
	if s.Name() != "grafana-metrics" {
		t.Errorf("Name() = %q, want %q", s.Name(), "grafana-metrics")
	}
}

func TestMetricsSink_Send_RecordsMetrics(t *testing.T) {
	s := grafana.NewMetricsSink()
	alert := &types.Alert{
		ID:          "a1",
		Severity:    "HIGH",
		RuleID:      "APSS-001",
		MitreTactic: "Command and Control",
		MitreID:     "T1059.004",
		Timestamp:   time.Now(),
	}
	if err := s.Send(context.Background(), alert); err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	// Verify apss_alerts_by_mitre_total incremented
	count := testutil.ToFloat64(grafana.AlertsByMitre.WithLabelValues("Command and Control", "T1059.004", "HIGH"))
	if count != 1 {
		t.Errorf("apss_alerts_by_mitre_total = %v, want 1", count)
	}
}

func TestMetricsSink_Send_NoError(t *testing.T) {
	s := grafana.NewMetricsSink()
	err := s.Send(context.Background(), &types.Alert{Severity: "LOW", Timestamp: time.Now()})
	if err != nil {
		t.Errorf("Send() = %v, want nil", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./pkg/reporting/grafana/... -run TestMetrics 2>&1 | head -5
```

Expected: `undefined: grafana.NewMetricsSink`

- [ ] **Step 3: Create `pkg/reporting/grafana/metrics.go`**

```go
package grafana

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/invisible-tech/autopilot-security-sensor/internal/types"
)

// Exported so tests can read label values via testutil.ToFloat64.
var (
	AlertsByMitre = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "apss_alerts_by_mitre_total",
			Help: "Total alerts by MITRE tactic, technique, and severity.",
		},
		[]string{"tactic", "technique_id", "severity"},
	)
	alertSeverityGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "apss_alert_severity_gauge",
			Help: "Current number of open alerts by severity.",
		},
		[]string{"severity"},
	)
)

func init() {
	prometheus.MustRegister(AlertsByMitre, alertSeverityGauge)
}

// MetricsSink is an AlertSink that records enriched Prometheus metrics.
type MetricsSink struct{}

// NewMetricsSink creates a sink that records MITRE and severity metrics.
func NewMetricsSink() *MetricsSink { return &MetricsSink{} }

// Name returns the sink identifier.
func (s *MetricsSink) Name() string { return "grafana-metrics" }

// Send records the alert in Prometheus metrics. Never returns an error.
func (s *MetricsSink) Send(_ context.Context, alert *types.Alert) error {
	AlertsByMitre.WithLabelValues(alert.MitreTactic, alert.MitreID, alert.Severity).Inc()
	alertSeverityGauge.WithLabelValues(alert.Severity).Inc()
	return nil
}
```

- [ ] **Step 4: Run all grafana tests**

```bash
go test ./pkg/reporting/grafana/... -v
```

Expected: all tests pass (annotations + metrics).

- [ ] **Step 5: Update Gazelle and commit**

```bash
bazel run //:gazelle
git add pkg/reporting/grafana/metrics.go pkg/reporting/grafana/metrics_test.go
git commit -m "feat: add Grafana MetricsSink with MITRE and severity Prometheus metrics"
```

---

### Task 6: `internal/audit` — Kubernetes audit webhook handler

**Files:**
- Create: `internal/audit/handler.go`
- Create: `internal/audit/handler_test.go`

**Interfaces:**
- Consumes: `controller.IngestEvent` function signature: `func(context.Context, *types.SecurityEvent) error`
- Produces:
  - `audit.New(ingestFn func(context.Context, *types.SecurityEvent) error, log *logrus.Logger) *Handler`
  - `(*Handler).Handle(w http.ResponseWriter, r *http.Request)` — responds HTTP 200 immediately, processes filtered audit events asynchronously

- [ ] **Step 1: Write the failing test**

Create `internal/audit/handler_test.go`:

```go
package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/invisible-tech/autopilot-security-sensor/internal/audit"
	"github.com/invisible-tech/autopilot-security-sensor/internal/types"
)

func newLog() *logrus.Logger {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	return l
}

// auditEventList matches the JSON shape of audit.k8s.io/v1.EventList.
type auditEventList struct {
	Items []auditItem `json:"items"`
}

type auditItem struct {
	AuditID   string     `json:"auditID"`
	Stage     string     `json:"stage"`
	Verb      string     `json:"verb"`
	User      auditUser  `json:"user"`
	ObjectRef *objectRef `json:"objectRef,omitempty"`
	RequestReceivedTimestamp time.Time `json:"requestReceivedTimestamp"`
}

type auditUser struct {
	Username string `json:"username"`
}

type objectRef struct {
	Resource  string `json:"resource"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

func makeBody(items []auditItem) []byte {
	b, _ := json.Marshal(auditEventList{Items: items})
	return b
}

func TestHandler_Responds200Immediately(t *testing.T) {
	var calls atomic.Int64
	h := audit.New(func(_ context.Context, _ *types.SecurityEvent) error {
		calls.Add(1)
		return nil
	}, newLog())

	body := makeBody([]auditItem{{
		AuditID: "id1", Stage: "ResponseComplete", Verb: "create",
		User:      auditUser{Username: "alice"},
		ObjectRef: &objectRef{Resource: "secrets", Namespace: "default", Name: "my-secret"},
		RequestReceivedTimestamp: time.Now(),
	}})
	req := httptest.NewRequest(http.MethodPost, "/audit/webhook", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestHandler_FiltersSensitiveResources(t *testing.T) {
	var ingested []*types.SecurityEvent
	h := audit.New(func(_ context.Context, ev *types.SecurityEvent) error {
		ingested = append(ingested, ev)
		return nil
	}, newLog())

	items := []auditItem{
		{AuditID: "1", Stage: "ResponseComplete", Verb: "create",
			ObjectRef: &objectRef{Resource: "secrets"}, RequestReceivedTimestamp: time.Now()},
		{AuditID: "2", Stage: "ResponseComplete", Verb: "get",
			ObjectRef: &objectRef{Resource: "pods"}, RequestReceivedTimestamp: time.Now()},
		{AuditID: "3", Stage: "ResponseComplete", Verb: "create",
			ObjectRef: &objectRef{Resource: "pods/exec"}, RequestReceivedTimestamp: time.Now()},
		{AuditID: "4", Stage: "RequestReceived", Verb: "create",
			ObjectRef: &objectRef{Resource: "secrets"}, RequestReceivedTimestamp: time.Now()},
	}

	body := makeBody(items)
	req := httptest.NewRequest(http.MethodPost, "/audit/webhook", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.Handle(w, req)

	// Wait briefly for async processing
	time.Sleep(50 * time.Millisecond)

	// Only item 1 (secrets/create/ResponseComplete) and item 3 (pods/exec/create/ResponseComplete) pass
	if len(ingested) != 2 {
		t.Errorf("ingested %d events, want 2", len(ingested))
	}
}

func TestHandler_InvalidBody_Returns400(t *testing.T) {
	h := audit.New(func(_ context.Context, _ *types.SecurityEvent) error { return nil }, newLog())
	req := httptest.NewRequest(http.MethodPost, "/audit/webhook", bytes.NewReader([]byte("not-json")))
	w := httptest.NewRecorder()
	h.Handle(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/audit/... 2>&1 | head -5
```

Expected: `cannot find package ".../internal/audit"`

- [ ] **Step 3: Create `internal/audit/handler.go`**

```go
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/invisible-tech/autopilot-security-sensor/internal/types"
)

// Handler receives Kubernetes audit EventList batches and converts
// filtered events into SecurityEvents for the controller.
type Handler struct {
	ingestFn func(context.Context, *types.SecurityEvent) error
	log      *logrus.Logger
}

// New creates an audit webhook handler that calls ingestFn for each matching event.
func New(ingestFn func(context.Context, *types.SecurityEvent) error, log *logrus.Logger) *Handler {
	return &Handler{ingestFn: ingestFn, log: log}
}

// Handle processes a Kubernetes audit webhook POST.
// Responds HTTP 200 immediately, then processes matching events asynchronously.
func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) {
	var list auditEventList
	if err := json.NewDecoder(r.Body).Decode(&list); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

	// Respond immediately — prevents API server audit backend from queuing.
	w.WriteHeader(http.StatusOK)

	go h.process(r.Context(), list.Items)
}

func (h *Handler) process(ctx context.Context, items []auditItem) {
	for _, item := range items {
		if !isSensitive(item) {
			continue
		}
		ref := ""
		ns := ""
		name := ""
		if item.ObjectRef != nil {
			ref = item.ObjectRef.Resource
			ns = item.ObjectRef.Namespace
			name = item.ObjectRef.Name
		}
		ev := &types.SecurityEvent{
			ID:           fmt.Sprintf("audit-%s", item.AuditID),
			Type:         "k8s_audit",
			Severity:     "MEDIUM",
			Timestamp:    item.RequestReceivedTimestamp,
			PodNamespace: ns,
			Metadata: map[string]interface{}{
				"verb":     item.Verb,
				"resource": ref,
				"name":     name,
				"user":     item.User.Username,
			},
		}
		if err := h.ingestFn(ctx, ev); err != nil {
			h.log.WithError(err).WithField("audit_id", item.AuditID).Warn("failed to ingest audit event")
		}
	}
}

// isSensitive returns true for audit events targeting sensitive resources
// at the ResponseComplete stage only.
func isSensitive(item auditItem) bool {
	if item.Stage != "ResponseComplete" {
		return false
	}
	if item.ObjectRef == nil {
		return false
	}
	resource := item.ObjectRef.Resource
	verb := item.Verb

	switch resource {
	case "secrets", "serviceaccounts":
		return verb == "create" || verb == "update" || verb == "patch" || verb == "delete"
	case "clusterrolebindings", "rolebindings":
		return verb == "create" || verb == "delete"
	case "pods/exec", "pods/portforward":
		return verb == "create"
	}
	return false
}

// auditEventList matches the JSON shape of audit.k8s.io/v1.EventList.
// Defined here to avoid importing k8s.io/apiserver (heavy dependency).
type auditEventList struct {
	Items []auditItem `json:"items"`
}

type auditItem struct {
	AuditID                  string     `json:"auditID"`
	Stage                    string     `json:"stage"`
	Verb                     string     `json:"verb"`
	User                     auditUser  `json:"user"`
	ObjectRef                *objectRef `json:"objectRef,omitempty"`
	RequestReceivedTimestamp time.Time  `json:"requestReceivedTimestamp"`
}

type auditUser struct {
	Username string   `json:"username"`
	Groups   []string `json:"groups"`
}

type objectRef struct {
	Resource   string `json:"resource"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	APIGroup   string `json:"apiGroup"`
	APIVersion string `json:"apiVersion"`
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/audit/... -v
```

Expected: 3 tests pass.

- [ ] **Step 5: Update Gazelle and commit**

```bash
bazel run //:gazelle
git add internal/audit/
git commit -m "feat: add Kubernetes audit webhook handler"
```

---

### Task 7: `internal/config` — GrafanaConfig, ClusterConfig, remove gcr.io default

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`

**Interfaces:**
- Produces:
  - `config.GrafanaConfig` struct
  - `config.ClusterConfig` struct
  - `config.DefaultGrafanaConfig() GrafanaConfig`
  - `config.DefaultClusterConfig() ClusterConfig`
  - `config.DefaultWebhookConfig().SidecarImage` returns `""` when `SIDECAR_IMAGE` env var is unset

- [ ] **Step 1: Write the failing tests**

Add to `internal/config/config_test.go`:

```go
func TestDefaultGrafanaConfig_Disabled(t *testing.T) {
	os.Unsetenv("GRAFANA_ENDPOINT")
	cfg := config.DefaultGrafanaConfig()
	if cfg.Enabled {
		t.Error("GrafanaConfig.Enabled should be false when GRAFANA_ENDPOINT unset")
	}
	if cfg.AnnotationsEnabled {
		t.Error("AnnotationsEnabled should be false when Grafana not enabled")
	}
}

func TestDefaultGrafanaConfig_Enabled(t *testing.T) {
	os.Setenv("GRAFANA_ENDPOINT", "http://grafana:3000")
	os.Setenv("GRAFANA_API_KEY", "mykey")
	defer os.Unsetenv("GRAFANA_ENDPOINT")
	defer os.Unsetenv("GRAFANA_API_KEY")

	cfg := config.DefaultGrafanaConfig()
	if !cfg.Enabled {
		t.Error("GrafanaConfig.Enabled should be true when GRAFANA_ENDPOINT set")
	}
	if cfg.Endpoint != "http://grafana:3000" {
		t.Errorf("Endpoint = %q, want %q", cfg.Endpoint, "http://grafana:3000")
	}
	if cfg.APIKey != "mykey" {
		t.Errorf("APIKey = %q, want %q", cfg.APIKey, "mykey")
	}
	if cfg.SinkTimeout != 10*time.Second {
		t.Errorf("SinkTimeout = %v, want 10s", cfg.SinkTimeout)
	}
}

func TestDefaultClusterConfig_Defaults(t *testing.T) {
	os.Unsetenv("CLUSTER_NAME")
	os.Unsetenv("CLUSTER_PROVIDER")
	os.Unsetenv("CLUSTER_REGION")
	cfg := config.DefaultClusterConfig()
	if cfg.Name != "unknown" {
		t.Errorf("Name = %q, want %q", cfg.Name, "unknown")
	}
	if cfg.Provider != "generic" {
		t.Errorf("Provider = %q, want %q", cfg.Provider, "generic")
	}
}

func TestDefaultWebhookConfig_NoSidecarImageDefault(t *testing.T) {
	os.Unsetenv("SIDECAR_IMAGE")
	cfg := config.DefaultWebhookConfig()
	if cfg.SidecarImage != "" {
		t.Errorf("SidecarImage should be empty string when SIDECAR_IMAGE unset, got %q", cfg.SidecarImage)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/config/... -run "TestDefaultGrafana|TestDefaultCluster|TestDefaultWebhookConfig_NoSidecar" 2>&1
```

Expected: failures for undefined `DefaultGrafanaConfig`, `DefaultClusterConfig`, and the SidecarImage test may pass or fail depending on env.

- [ ] **Step 3: Update `internal/config/config.go`**

Replace the `DefaultWebhookConfig` `SidecarImage` line and add the new types and constructors. The full additions:

```go
// In WebhookConfig's DefaultWebhookConfig():
// Change:
SidecarImage: GetEnv("SIDECAR_IMAGE", "gcr.io/invisible-sre-sandbox/apss-agent:latest"),
// To:
SidecarImage: GetEnv("SIDECAR_IMAGE", ""),

// Add new types after the existing config types:

// GrafanaConfig holds configuration for the Grafana reporting sink.
type GrafanaConfig struct {
	Enabled            bool
	Endpoint           string
	APIKey             string
	AnnotationsEnabled bool
	SinkTimeout        time.Duration
}

// ClusterConfig holds provider-neutral cluster identity metadata.
type ClusterConfig struct {
	Name     string // CLUSTER_NAME
	Provider string // CLUSTER_PROVIDER: gcp | aws | azure | generic
	Region   string // CLUSTER_REGION
}

// DefaultGrafanaConfig returns Grafana config from environment.
func DefaultGrafanaConfig() GrafanaConfig {
	endpoint := GetEnv("GRAFANA_ENDPOINT", "")
	enabled := endpoint != ""
	annotationsEnabled := enabled && GetEnv("GRAFANA_ANNOTATIONS_ENABLED", "true") == "true"
	return GrafanaConfig{
		Enabled:            enabled,
		Endpoint:           endpoint,
		APIKey:             GetEnv("GRAFANA_API_KEY", ""),
		AnnotationsEnabled: annotationsEnabled,
		SinkTimeout:        GetEnvDuration("GRAFANA_SINK_TIMEOUT", 10*time.Second),
	}
}

// DefaultClusterConfig returns cluster identity config from environment.
func DefaultClusterConfig() ClusterConfig {
	return ClusterConfig{
		Name:     GetEnv("CLUSTER_NAME", "unknown"),
		Provider: GetEnv("CLUSTER_PROVIDER", "generic"),
		Region:   GetEnv("CLUSTER_REGION", ""),
	}
}
```

- [ ] **Step 4: Update the existing `TestDefaultWebhookConfig` test**

The test currently asserts `cfg.SidecarImage != ""` which will now fail since the default is `""`. Replace that assertion:

```go
// Old (remove this):
if cfg.SidecarImage == "" {
    t.Error("SidecarImage should be set")
}

// New (replace with):
// SidecarImage has no default — callers must set SIDECAR_IMAGE env var
if cfg.SidecarImage != "" {
    t.Errorf("SidecarImage default should be empty, got %q", cfg.SidecarImage)
}
```

- [ ] **Step 5: Run all config tests**

```bash
go test ./internal/config/... -v
```

Expected: all pass including the new and updated tests.

- [ ] **Step 6: Update Gazelle and commit**

```bash
bazel run //:gazelle
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat: add GrafanaConfig, ClusterConfig; remove hardcoded gcr.io default"
```

---

### Task 8: Refactor `internal/controller` to use AlertBus

**Files:**
- Modify: `internal/controller/controller.go`
- Modify: `internal/controller/controller_test.go`

**Interfaces:**
- Consumes: `bus.Bus` (Task 2), `config.ClusterConfig` (Task 7)
- Produces:
  - `(*Controller).SetAlertBus(b *bus.Bus)` — wires the bus; if nil, alerts are still stored and logged but not published
  - `(*Controller).SetClusterConfig(cfg config.ClusterConfig)` — injects cluster metadata into outgoing alerts

- [ ] **Step 1: Write the failing test**

Add to `internal/controller/controller_test.go`:

```go
func TestController_SetAlertBus_PublishesAlerts(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.PanicLevel)
	cfg := config.ControllerConfig{EventBufferSize: 100, AlertBufferSize: 100}
	c := New(cfg, log)

	var published []*types.Alert
	var mu sync.Mutex

	b := bus.New(5*time.Second, log)
	b.Register(&captureSink{fn: func(a *types.Alert) {
		mu.Lock()
		published = append(published, a)
		mu.Unlock()
	}}, nil)
	c.SetAlertBus(b)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Start(ctx)

	ev := &types.SecurityEvent{
		ID: "ev-1", AgentID: "a", Type: "process_start", Severity: "CRITICAL",
		Timestamp: time.Now(), PodName: "pod", PodNamespace: "ns",
		Process: &types.ProcessEventData{SuspiciousIndicators: []string{"possible_cryptominer"}},
	}
	if err := c.IngestEvent(ctx, ev); err != nil {
		t.Fatalf("IngestEvent: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	n := len(published)
	mu.Unlock()
	if n < 1 {
		t.Errorf("want at least 1 alert published to bus, got %d", n)
	}
}

func TestController_SetClusterConfig_InjectsMetadata(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.PanicLevel)
	cfg := config.ControllerConfig{EventBufferSize: 100, AlertBufferSize: 100}
	c := New(cfg, log)

	var published []*types.Alert
	var mu sync.Mutex

	b := bus.New(5*time.Second, log)
	b.Register(&captureSink{fn: func(a *types.Alert) {
		mu.Lock()
		published = append(published, a)
		mu.Unlock()
	}}, nil)
	c.SetAlertBus(b)
	c.SetClusterConfig(config.ClusterConfig{Name: "my-cluster", Provider: "gcp"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Start(ctx)

	_ = c.IngestEvent(ctx, &types.SecurityEvent{
		ID: "ev-1", AgentID: "a", Severity: "CRITICAL", Timestamp: time.Now(),
		Process: &types.ProcessEventData{SuspiciousIndicators: []string{"possible_cryptominer"}},
	})
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(published) == 0 {
		t.Fatal("no alerts published")
	}
	clusterName, ok := published[0].Metadata["cluster_name"]
	if !ok || clusterName != "my-cluster" {
		t.Errorf("Metadata[cluster_name] = %v, want %q", clusterName, "my-cluster")
	}
}

// captureSink captures published alerts for testing.
type captureSink struct{ fn func(*types.Alert) }

func (s *captureSink) Name() string { return "capture" }
func (s *captureSink) Send(_ context.Context, a *types.Alert) error {
	s.fn(a)
	return nil
}
```

Also add these imports to the test file: `"sync"`, `"github.com/invisible-tech/autopilot-security-sensor/pkg/reporting/bus"`.

- [ ] **Step 2: Run the new tests to verify they fail**

```bash
go test ./internal/controller/... -run "TestController_SetAlertBus|TestController_SetClusterConfig" 2>&1 | head -10
```

Expected: `undefined: c.SetAlertBus`

- [ ] **Step 3: Update `internal/controller/controller.go`**

Remove `sweetSecurity` and `sweetSecurityMu` fields and all Sweet Security methods. Add `bus` and `clusterCfg` fields. Update `processAlerts` to publish to the bus.

```go
package controller

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	"github.com/invisible-tech/autopilot-security-sensor/internal/config"
	"github.com/invisible-tech/autopilot-security-sensor/internal/detection"
	"github.com/invisible-tech/autopilot-security-sensor/internal/types"
	"github.com/invisible-tech/autopilot-security-sensor/pkg/reporting/bus"
)

var (
	eventsReceived = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "apss_events_received_total",
			Help: "Total security events received",
		},
		[]string{"type", "severity", "namespace"},
	)
	alertsGenerated = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "apss_alerts_generated_total",
			Help: "Total security alerts generated",
		},
		[]string{"rule", "severity"},
	)
	activeAgents = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "apss_active_agents",
			Help: "Number of active APSS agents",
		},
	)
)

func init() {
	prometheus.MustRegister(eventsReceived, alertsGenerated, activeAgents)
}

// Controller orchestrates event processing, detection, and alert handling.
type Controller struct {
	cfg      config.ControllerConfig
	log      *logrus.Logger
	engine   *detection.Engine
	agents   map[string]*types.AgentInfo
	agentsMu sync.RWMutex
	alerts   []*types.Alert
	alertsMu sync.RWMutex

	eventBuffer chan *types.SecurityEvent
	alertChan   chan *types.Alert

	busMu      sync.RWMutex
	alertBus   *bus.Bus
	clusterCfg config.ClusterConfig
}

// New creates a new Controller with the given config and logger.
func New(cfg config.ControllerConfig, log *logrus.Logger) *Controller {
	return &Controller{
		cfg:         cfg,
		log:         log,
		engine:      detection.NewEngine(),
		agents:      make(map[string]*types.AgentInfo),
		eventBuffer: make(chan *types.SecurityEvent, cfg.EventBufferSize),
		alertChan:   make(chan *types.Alert, cfg.AlertBufferSize),
	}
}

// SetAlertBus wires the alert bus. Call before Start.
func (c *Controller) SetAlertBus(b *bus.Bus) {
	c.busMu.Lock()
	c.alertBus = b
	c.busMu.Unlock()
}

// SetClusterConfig injects cluster identity into outgoing alerts. Call before Start.
func (c *Controller) SetClusterConfig(cfg config.ClusterConfig) {
	c.busMu.Lock()
	c.clusterCfg = cfg
	c.busMu.Unlock()
}

// Start begins event processing and agent health check goroutines.
func (c *Controller) Start(ctx context.Context) {
	go c.processEvents(ctx)
	go c.processAlerts(ctx)
	go c.checkAgentHealth(ctx)
}

// IngestEvent accepts an event from the HTTP API and queues it for processing.
func (c *Controller) IngestEvent(ctx context.Context, event *types.SecurityEvent) error {
	c.agentsMu.Lock()
	if agent, ok := c.agents[event.AgentID]; ok {
		agent.LastSeen = time.Now()
		agent.EventCount++
	} else {
		c.agents[event.AgentID] = &types.AgentInfo{
			ID:           event.AgentID,
			PodName:      event.PodName,
			PodNamespace: event.PodNamespace,
			ConnectedAt:  time.Now(),
			LastSeen:     time.Now(),
			EventCount:   1,
		}
	}
	c.agentsMu.Unlock()

	select {
	case c.eventBuffer <- event:
		return nil
	default:
		return fmt.Errorf("event buffer full")
	}
}

// GetAgents returns a copy of connected agents.
func (c *Controller) GetAgents() []*types.AgentInfo {
	c.agentsMu.RLock()
	defer c.agentsMu.RUnlock()
	out := make([]*types.AgentInfo, 0, len(c.agents))
	for _, a := range c.agents {
		out = append(out, a)
	}
	return out
}

// GetAlerts returns the most recent alerts, up to limit.
func (c *Controller) GetAlerts(limit int) []*types.Alert {
	c.alertsMu.RLock()
	defer c.alertsMu.RUnlock()
	n := len(c.alerts)
	if limit <= 0 || limit > n {
		limit = n
	}
	start := n - limit
	if start < 0 {
		start = 0
	}
	out := make([]*types.Alert, limit)
	copy(out, c.alerts[start:])
	return out
}

func (c *Controller) processEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-c.eventBuffer:
			c.evaluateEvent(event)
		}
	}
}

func (c *Controller) evaluateEvent(event *types.SecurityEvent) {
	eventsReceived.WithLabelValues(event.Type, event.Severity, event.PodNamespace).Inc()
	for _, alert := range c.engine.Evaluate(event) {
		select {
		case c.alertChan <- alert:
		default:
			c.log.Warn("Alert channel full, dropping alert")
		}
	}
}

func (c *Controller) processAlerts(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case alert := <-c.alertChan:
			c.alertsMu.Lock()
			c.alerts = append(c.alerts, alert)
			if len(c.alerts) > c.cfg.AlertRetentionCount {
				c.alerts = c.alerts[len(c.alerts)-c.cfg.AlertRetentionCount:]
			}
			c.alertsMu.Unlock()

			alertsGenerated.WithLabelValues(alert.RuleID, alert.Severity).Inc()
			c.log.WithFields(logrus.Fields{
				"alert_id": alert.ID, "rule_id": alert.RuleID, "rule_name": alert.RuleName,
				"severity": alert.Severity, "pod": alert.PodName, "namespace": alert.PodNS,
				"mitre": alert.MitreID, "description": alert.Description,
			}).Warn("SECURITY ALERT")

			c.publishAlert(ctx, alert)
		}
	}
}

func (c *Controller) publishAlert(ctx context.Context, alert *types.Alert) {
	c.busMu.RLock()
	b := c.alertBus
	clusterCfg := c.clusterCfg
	c.busMu.RUnlock()

	if alert.Metadata == nil {
		alert.Metadata = make(map[string]interface{})
	}
	if clusterCfg.Name != "" {
		alert.Metadata["cluster_name"] = clusterCfg.Name
		alert.Metadata["cluster_provider"] = clusterCfg.Provider
		alert.Metadata["cluster_region"] = clusterCfg.Region
	}

	if b == nil {
		return
	}
	if err := b.Publish(ctx, alert); err != nil {
		c.log.WithError(err).WithField("alert_id", alert.ID).Error("alert bus publish failed")
	}
}

func (c *Controller) checkAgentHealth(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.agentsMu.Lock()
			now := time.Now()
			for id, agent := range c.agents {
				if now.Sub(agent.LastSeen) > c.cfg.AgentStaleThreshold {
					c.log.WithField("agent_id", id).Warn("Agent appears offline")
					delete(c.agents, id)
				}
			}
			activeAgents.Set(float64(len(c.agents)))
			c.agentsMu.Unlock()
		}
	}
}
```

- [ ] **Step 4: Remove stale tests from `controller_test.go`**

Delete these two test functions — they test methods that no longer exist:
- `TestController_SendHighSeverityEvent_NoClient`
- `TestController_SweetSecurity`

Also add imports `"sync"` and `"github.com/invisible-tech/autopilot-security-sensor/pkg/reporting/bus"` to the test file.

- [ ] **Step 5: Run all controller tests**

```bash
go test ./internal/controller/... -v
```

Expected: all existing tests pass plus the two new bus tests.

- [ ] **Step 6: Update Gazelle and commit**

```bash
bazel run //:gazelle
git add internal/controller/controller.go internal/controller/controller_test.go
git commit -m "feat: wire AlertBus into controller, inject cluster metadata into alerts"
```

---

### Task 9: Wire `internal/server` + `cmd/controller/main.go`

**Files:**
- Modify: `internal/server/server.go`
- Modify: `cmd/controller/main.go`

**Interfaces:**
- Consumes: `audit.Handler` (Task 6), `bus.Bus` (Task 2), `sweetsecurity.NewSink` (Task 3), `grafana.NewAnnotationSink` (Task 4), `grafana.NewMetricsSink` (Task 5), `config.GrafanaConfig` + `config.ClusterConfig` (Task 7)
- Produces: `/audit/webhook` HTTP route; full sink-registered main.go that replaces previous `initSweetSecurity` wiring

- [ ] **Step 1: Update `internal/server/server.go`**

Add an `auditHandler` field and update `New` to accept an optional audit handler. If the handler is nil, the route is not registered.

Replace the `New` function and `Server` struct:

```go
// Server is the HTTP server for the controller API.
type Server struct {
	cfg          config.ControllerConfig
	controller   *controller.Controller
	log          *logrus.Logger
	httpServer   *http.Server
	auditHandler http.Handler
}

// New creates a new HTTP server. Pass a non-nil auditHandler to enable /audit/webhook.
func New(cfg config.ControllerConfig, ctrl *controller.Controller, log *logrus.Logger, auditHandler http.Handler) *Server {
	mux := http.NewServeMux()
	s := &Server{cfg: cfg, controller: ctrl, log: log, auditHandler: auditHandler}
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/api/v1/events", s.handleEvents)
	mux.HandleFunc("/api/v1/agents", s.handleAgents)
	mux.HandleFunc("/api/v1/alerts", s.handleAlerts)
	mux.Handle("/metrics", promhttp.Handler())
	if auditHandler != nil {
		mux.Handle("/audit/webhook", auditHandler)
	}

	s.httpServer = &http.Server{
		Addr:         cfg.HTTPAddr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	return s
}
```

Also remove the `SendHighSeverityEvent` call from `handleEvents` — the controller no longer has this method:

```go
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var event types.SecurityEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if err := s.controller.IngestEvent(r.Context(), &event); err != nil {
		http.Error(w, "Event buffer full", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}
```

- [ ] **Step 2: Update server tests**

In `internal/server/server_test.go`, find all calls to `server.New(cfg, ctrl, log)` and update them to `server.New(cfg, ctrl, log, nil)`. Run tests to confirm:

```bash
go test ./internal/server/... -v
```

Expected: all pass.

- [ ] **Step 3: Replace `cmd/controller/main.go`**

```go
package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/invisible-tech/autopilot-security-sensor/internal/audit"
	"github.com/invisible-tech/autopilot-security-sensor/internal/config"
	"github.com/invisible-tech/autopilot-security-sensor/internal/controller"
	"github.com/invisible-tech/autopilot-security-sensor/internal/server"
	"github.com/invisible-tech/autopilot-security-sensor/pkg/reporting/bus"
	"github.com/invisible-tech/autopilot-security-sensor/pkg/reporting/grafana"
	"github.com/invisible-tech/autopilot-security-sensor/pkg/sweetsecurity"
)

func main() {
	log := logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{})
	log.SetLevel(logrus.InfoLevel)

	cfg := config.DefaultControllerConfig()
	grafanaCfg := config.DefaultGrafanaConfig()
	clusterCfg := config.DefaultClusterConfig()

	ctrl := controller.New(cfg, log)

	alertBus := bus.New(grafanaCfg.SinkTimeout, log)

	// Sweet Security sink — registered only when configured
	if cfg.SweetSecurityEnabled {
		alertBus.Register(sweetsecurity.NewSink(cfg, log), nil)
	}

	// Grafana annotation sink — registered only when Grafana is configured
	if grafanaCfg.Enabled && grafanaCfg.AnnotationsEnabled {
		alertBus.Register(grafana.NewAnnotationSink(grafanaCfg.Endpoint, grafanaCfg.APIKey, log), nil)
	}

	// Metrics sink — always registered (records MITRE and severity metrics)
	alertBus.Register(grafana.NewMetricsSink(), nil)

	ctrl.SetAlertBus(alertBus)
	ctrl.SetClusterConfig(clusterCfg)
	ctrl.Start(context.Background())

	// Audit webhook handler — enabled when AUDIT_WEBHOOK_ENABLED=true
	var auditHandler http.Handler
	if os.Getenv("AUDIT_WEBHOOK_ENABLED") == "true" {
		auditHandler = audit.New(ctrl.IngestEvent, log)
	}

	srv := server.New(cfg, ctrl, log, auditHandler)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.WithError(err).Fatal("Controller server failed")
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Info("Shutting down controller")
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	_ = srv.Shutdown(ctx)
}
```

- [ ] **Step 4: Build the controller to confirm it compiles**

```bash
go build ./cmd/controller/...
```

Expected: no errors.

- [ ] **Step 5: Run all tests**

```bash
go test ./... 2>&1 | grep -E "^(ok|FAIL|---)"
```

Expected: all packages `ok`.

- [ ] **Step 6: Update Gazelle and commit**

```bash
bazel run //:gazelle
git add internal/server/server.go internal/server/server_test.go cmd/controller/main.go
git commit -m "feat: wire audit handler and alert bus into server and main"
```

---

### Task 10: Helm values, deploy scripts, dashboard ConfigMap, audit docs

**Files:**
- Modify: `deploy/helm/values.yaml`
- Create: `deploy/helm/templates/grafana-dashboard.yaml`
- Modify: `deploy.sh` (add `--registry` and `--cluster-name` flags)
- Modify: `deploy-batch.sh` (same)
- Create: `docs/audit-webhook-setup.md`

- [ ] **Step 1: Update `deploy/helm/values.yaml`**

Replace the hardcoded image repository values and add new sections. Key changes:

```yaml
# Add at top of file under existing namespace line:
global:
  registry: ""   # Required: gcr.io/my-project | 123456789.dkr.ecr.us-east-1.amazonaws.com | myacr.azurecr.io
  imagePullSecrets: []
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  nodeSelector: {}
  tolerations: []
  affinity:
    podAntiAffinity:
      preferredDuringSchedulingIgnoredDuringExecution:
        - weight: 100
          podAffinityTerm:
            labelSelector:
              matchLabels:
                app.kubernetes.io/name: apss-controller
            topologyKey: kubernetes.io/hostname

# Change controller.image.repository:
controller:
  image:
    repository: "{{ .Values.global.registry }}/apss-controller"

# Change webhook.image.repository:
webhook:
  image:
    repository: "{{ .Values.global.registry }}/apss-webhook"
  excludeNamespaces:
    - kube-system
    - kube-public
    - apss-system
    - cert-manager
    - istio-system
    # gke-managed-system removed — add back via values override on GKE

# Change agent.image.repository:
agent:
  image:
    repository: "{{ .Values.global.registry }}/apss-agent"

# Add after sweetSecurity section:
grafana:
  enabled: false
  endpoint: ""
  apiKeySecret:
    name: ""
    key: "api-key"
  annotationsEnabled: true
  dashboardProvisioning: true
  sinkTimeoutSeconds: 10

cluster:
  name: ""
  provider: "generic"   # gcp | aws | azure | generic
  region: ""

# Update auditLogProcessor:
auditLogProcessor:
  enabled: false
  source: "webhook"   # pubsub removed
```

- [ ] **Step 2: Create `deploy/helm/templates/grafana-dashboard.yaml`**

```yaml
{{- if and .Values.grafana.enabled .Values.grafana.dashboardProvisioning }}
apiVersion: v1
kind: ConfigMap
metadata:
  name: apss-grafana-dashboard
  namespace: {{ .Values.namespace }}
  labels:
    grafana_dashboard: "1"
data:
  apss-dashboard.json: |
    {
      "title": "APSS Security Dashboard",
      "uid": "apss-security",
      "panels": [
        {
          "id": 1,
          "title": "Alert Rate by Severity",
          "type": "timeseries",
          "targets": [{"expr": "rate(apss_alerts_generated_total[5m])", "legendFormat": "{{severity}}"}]
        },
        {
          "id": 2,
          "title": "Active Agents",
          "type": "stat",
          "targets": [{"expr": "apss_active_agents"}]
        },
        {
          "id": 3,
          "title": "MITRE Tactic Distribution",
          "type": "barchart",
          "targets": [{"expr": "sum by (tactic) (apss_alerts_by_mitre_total)", "legendFormat": "{{tactic}}"}]
        },
        {
          "id": 4,
          "title": "Sink Error Rate",
          "type": "timeseries",
          "targets": [{"expr": "rate(apss_sink_errors_total[5m])", "legendFormat": "{{sink}}"}]
        },
        {
          "id": 5,
          "title": "Sink Send Latency (p95)",
          "type": "timeseries",
          "targets": [{"expr": "histogram_quantile(0.95, rate(apss_sink_send_duration_seconds_bucket[5m]))", "legendFormat": "{{sink}}"}]
        }
      ],
      "annotations": {
        "list": [
          {
            "name": "APSS Alerts",
            "datasource": "-- Grafana --",
            "enable": true,
            "tags": ["apss"]
          }
        ]
      }
    }
{{- end }}
```

- [ ] **Step 3: Add `--registry` and `--cluster-name` flags to `deploy.sh`**

At the top of `deploy.sh`, after the existing variable declarations, add:

```bash
REGISTRY=""
CLUSTER_NAME_FLAG=""

# Parse flags
while [[ $# -gt 0 ]]; do
  case $1 in
    --registry) REGISTRY="$2"; shift 2 ;;
    --cluster-name) CLUSTER_NAME_FLAG="$2"; shift 2 ;;
    *) shift ;;
  esac
done

if [[ -z "$REGISTRY" ]]; then
  echo "ERROR: --registry is required (e.g. --registry gcr.io/my-project)"
  exit 1
fi
if [[ -z "$CLUSTER_NAME_FLAG" ]]; then
  echo "ERROR: --cluster-name is required"
  exit 1
fi
```

Then update the `helm upgrade` call in `deploy.sh` to pass:
```bash
  --set global.registry="${REGISTRY}" \
  --set cluster.name="${CLUSTER_NAME_FLAG}" \
```

Apply the same changes to `deploy-batch.sh`.

- [ ] **Step 4: Create `docs/audit-webhook-setup.md`**

```markdown
# Kubernetes Audit Webhook Setup

APSS receives Kubernetes audit events via a standard audit webhook.
Configure your cluster to POST audit events to the APSS controller at:
`http://apss-controller.apss-system.svc.cluster.local:8080/audit/webhook`

## Audit Policy

Save as `audit-policy.yaml` and mount into the API server:

\`\`\`yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["secrets", "serviceaccounts"]
      - group: "rbac.authorization.k8s.io"
        resources: ["clusterrolebindings", "rolebindings"]
    verbs: ["create", "update", "patch", "delete"]
  - level: Request
    resources:
      - group: ""
        resources: ["pods/exec", "pods/portforward"]
    verbs: ["create"]
  - level: None
\`\`\`

## GKE

In GKE, configure via the cluster's `--audit-policy-file` flag through GKE audit logging.
Add to your cluster creation flags:
`--audit-policy-file=audit-policy.yaml --audit-webhook-config-file=audit-webhook.yaml`

## EKS

In EKS, use the `--audit-log-path` and `--audit-webhook-config-file` flags
in the API server configuration. See AWS documentation for managed node groups.

## AKS

In AKS, use the Diagnostic Settings to forward audit logs to APSS via a webhook adapter.

## Self-hosted (kubeadm)

Add to `/etc/kubernetes/manifests/kube-apiserver.yaml`:
\`\`\`yaml
- --audit-policy-file=/etc/kubernetes/audit-policy.yaml
- --audit-webhook-config-file=/etc/kubernetes/audit-webhook.yaml
\`\`\`
```

- [ ] **Step 5: Enable audit webhook in Helm values**

In `deploy/helm/values.yaml`, update `auditLogProcessor`:
```yaml
auditLogProcessor:
  enabled: false   # set to true after audit-webhook-setup.md steps are complete
  source: "webhook"
```

And add the `AUDIT_WEBHOOK_ENABLED` env var to the controller Deployment template in `deploy/helm/templates/` (if applicable).

- [ ] **Step 6: Run a full test suite to confirm everything still passes**

```bash
go test ./... 2>&1 | grep -E "^(ok|FAIL)"
bazel test //...
```

Expected: all packages `ok`.

- [ ] **Step 7: Commit**

```bash
git add deploy/helm/values.yaml deploy/helm/templates/grafana-dashboard.yaml \
        deploy.sh deploy-batch.sh docs/audit-webhook-setup.md
git commit -m "feat: cloud-agnostic Helm config, Grafana dashboard ConfigMap, audit webhook docs"
```
