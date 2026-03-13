package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/FrankFMY/burrow/internal/server/store"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
)

func TestMetricsEndpoint(t *testing.T) {
	api, _, _ := setupTestAPI(t)
	router := api.Router()

	doRequest(t, router, "GET", "/health", nil, "")

	rec := doRequest(t, router, "GET", "/metrics", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") && !strings.Contains(ct, "text/openmetrics") && !strings.Contains(ct, "application/openmetrics-text") {
		t.Errorf("content-type: got %q, want prometheus text format", ct)
	}

	body := rec.Body.String()
	expectedMetrics := []string{
		"burrow_clients_total",
		"burrow_connections_active",
		"burrow_connections_total",
		"burrow_bytes_transferred_total",
		"burrow_server_uptime_seconds",
		"burrow_goroutines",
		"burrow_memory_alloc_bytes",
		"burrow_http_request_duration_seconds",
	}
	for _, name := range expectedMetrics {
		if !strings.Contains(body, name) {
			t.Errorf("response body missing metric %q", name)
		}
	}
}

func TestMetricsEndpointNoAuth(t *testing.T) {
	api, _, _ := setupTestAPI(t)
	router := api.Router()

	rec := doRequest(t, router, "GET", "/metrics", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics should not require auth, got status %d", rec.Code)
	}
}

func TestMetricsUpdate(t *testing.T) {
	dir := t.TempDir()
	db, err := store.NewSQLite(dir + "/test.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	ctx := context.Background()
	db.CreateClient(ctx, &store.Client{
		ID: "m1", Name: "Active", Token: "mt1", CreatedAt: time.Now().UTC(),
	})
	db.CreateClient(ctx, &store.Client{
		ID: "m2", Name: "Revoked", Token: "mt2", CreatedAt: time.Now().UTC(),
	})
	db.RevokeClient(ctx, "m2")

	db.RecordTraffic(ctx, "mt1", 1024, 2048)

	startedAt := time.Now().Add(-30 * time.Second)
	m.Update(db, startedAt, 3)

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}

	findGauge := func(name string, labels map[string]string) *float64 {
		for _, f := range families {
			if f.GetName() != name {
				continue
			}
			for _, metric := range f.GetMetric() {
				if labels == nil {
					v := metric.GetGauge().GetValue()
					return &v
				}
				match := true
				for k, v := range labels {
					found := false
					for _, lp := range metric.GetLabel() {
						if lp.GetName() == k && lp.GetValue() == v {
							found = true
							break
						}
					}
					if !found {
						match = false
						break
					}
				}
				if match {
					v := metric.GetGauge().GetValue()
					return &v
				}
			}
		}
		return nil
	}

	findCounter := func(name string, labels map[string]string) *float64 {
		for _, f := range families {
			if f.GetName() != name {
				continue
			}
			for _, metric := range f.GetMetric() {
				if labels == nil {
					v := metric.GetCounter().GetValue()
					return &v
				}
				match := true
				for k, v := range labels {
					found := false
					for _, lp := range metric.GetLabel() {
						if lp.GetName() == k && lp.GetValue() == v {
							found = true
							break
						}
					}
					if !found {
						match = false
						break
					}
				}
				if match {
					v := metric.GetCounter().GetValue()
					return &v
				}
			}
		}
		return nil
	}

	active := findGauge("burrow_clients_total", map[string]string{"status": "active"})
	if active == nil || *active != 1 {
		t.Errorf("burrow_clients_total{status=active}: got %v, want 1", active)
	}

	revoked := findGauge("burrow_clients_total", map[string]string{"status": "revoked"})
	if revoked == nil || *revoked != 1 {
		t.Errorf("burrow_clients_total{status=revoked}: got %v, want 1", revoked)
	}

	connActive := findGauge("burrow_connections_active", nil)
	if connActive == nil || *connActive != 3 {
		t.Errorf("burrow_connections_active: got %v, want 3", connActive)
	}

	uptime := findGauge("burrow_server_uptime_seconds", nil)
	if uptime == nil || *uptime < 29 {
		t.Errorf("burrow_server_uptime_seconds: got %v, want >= 29", uptime)
	}

	goroutines := findGauge("burrow_goroutines", nil)
	if goroutines == nil || *goroutines < 1 {
		t.Errorf("burrow_goroutines: got %v, want >= 1", goroutines)
	}

	memAlloc := findGauge("burrow_memory_alloc_bytes", nil)
	if memAlloc == nil || *memAlloc < 1 {
		t.Errorf("burrow_memory_alloc_bytes: got %v, want > 0", memAlloc)
	}

	bytesUp := findCounter("burrow_bytes_transferred_total", map[string]string{"direction": "up"})
	if bytesUp == nil || *bytesUp != 1024 {
		t.Errorf("burrow_bytes_transferred_total{direction=up}: got %v, want 1024", bytesUp)
	}

	bytesDown := findCounter("burrow_bytes_transferred_total", map[string]string{"direction": "down"})
	if bytesDown == nil || *bytesDown != 2048 {
		t.Errorf("burrow_bytes_transferred_total{direction=down}: got %v, want 2048", bytesDown)
	}
}

func TestMetricsHTTPDuration(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	handler := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}

	var found *dto.MetricFamily
	for _, f := range families {
		if f.GetName() == "burrow_http_request_duration_seconds" {
			found = f
			break
		}
	}
	if found == nil {
		t.Fatal("burrow_http_request_duration_seconds metric not found")
	}

	if len(found.GetMetric()) == 0 {
		t.Fatal("no histogram observations recorded")
	}

	metric := found.GetMetric()[0]
	if metric.GetHistogram().GetSampleCount() != 1 {
		t.Errorf("sample count: got %d, want 1", metric.GetHistogram().GetSampleCount())
	}
}

func TestMetricsUpdateDeltaAccumulation(t *testing.T) {
	dir := t.TempDir()
	db, err := store.NewSQLite(dir + "/test.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	ctx := context.Background()
	db.CreateClient(ctx, &store.Client{
		ID: "d1", Name: "Delta", Token: "dt1", CreatedAt: time.Now().UTC(),
	})

	startedAt := time.Now()

	db.RecordTraffic(ctx, "dt1", 100, 200)
	m.Update(db, startedAt, 0)

	db.RecordTraffic(ctx, "dt1", 50, 75)
	m.Update(db, startedAt, 0)

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	for _, f := range families {
		if f.GetName() != "burrow_bytes_transferred_total" {
			continue
		}
		for _, metric := range f.GetMetric() {
			for _, lp := range metric.GetLabel() {
				if lp.GetName() == "direction" && lp.GetValue() == "up" {
					got := metric.GetCounter().GetValue()
					if got != 150 {
						t.Errorf("bytes_up after two updates: got %v, want 150", got)
					}
				}
				if lp.GetName() == "direction" && lp.GetValue() == "down" {
					got := metric.GetCounter().GetValue()
					if got != 275 {
						t.Errorf("bytes_down after two updates: got %v, want 275", got)
					}
				}
			}
		}
	}
}

func TestMetricsViaPromHandler(t *testing.T) {
	dir := t.TempDir()
	db, err := store.NewSQLite(dir + "/test.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	ctx := context.Background()
	db.CreateClient(ctx, &store.Client{
		ID: "p1", Name: "Prom", Token: "pt1", CreatedAt: time.Now().UTC(),
	})
	m.Update(db, time.Now().Add(-60*time.Second), 0)

	handler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusOK)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "burrow_clients_total") {
		t.Error("missing burrow_clients_total in prometheus output")
	}
	if !strings.Contains(body, "burrow_server_uptime_seconds") {
		t.Error("missing burrow_server_uptime_seconds in prometheus output")
	}
}
