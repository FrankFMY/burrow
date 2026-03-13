package server

import (
	"context"
	"net/http"
	"runtime"
	"strconv"
	"time"

	"github.com/FrankFMY/burrow/internal/server/store"
	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Metrics struct {
	clientsTotal        *prometheus.GaugeVec
	connectionsActive   prometheus.Gauge
	connectionsTotal    prometheus.Counter
	bytesTransferred    *prometheus.CounterVec
	serverUptime        prometheus.Gauge
	goroutines          prometheus.Gauge
	memoryAlloc         prometheus.Gauge
	httpRequestDuration *prometheus.HistogramVec

	lastBytesUp   int64
	lastBytesDown int64
}

func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		clientsTotal: promauto.With(reg).NewGaugeVec(prometheus.GaugeOpts{
			Name: "burrow_clients_total",
			Help: "Number of clients by status.",
		}, []string{"status"}),

		connectionsActive: promauto.With(reg).NewGauge(prometheus.GaugeOpts{
			Name: "burrow_connections_active",
			Help: "Number of currently active connections.",
		}),

		connectionsTotal: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "burrow_connections_total",
			Help: "Total number of connections since server start.",
		}),

		bytesTransferred: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "burrow_bytes_transferred_total",
			Help: "Total bytes transferred.",
		}, []string{"direction"}),

		serverUptime: promauto.With(reg).NewGauge(prometheus.GaugeOpts{
			Name: "burrow_server_uptime_seconds",
			Help: "Server uptime in seconds.",
		}),

		goroutines: promauto.With(reg).NewGauge(prometheus.GaugeOpts{
			Name: "burrow_goroutines",
			Help: "Number of goroutines.",
		}),

		memoryAlloc: promauto.With(reg).NewGauge(prometheus.GaugeOpts{
			Name: "burrow_memory_alloc_bytes",
			Help: "Allocated heap memory in bytes.",
		}),

		httpRequestDuration: promauto.With(reg).NewHistogramVec(prometheus.HistogramOpts{
			Name:    "burrow_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "path", "status"}),
	}

	m.bytesTransferred.WithLabelValues("up")
	m.bytesTransferred.WithLabelValues("down")
	m.clientsTotal.WithLabelValues("active")
	m.clientsTotal.WithLabelValues("revoked")

	return m
}

func (m *Metrics) Update(s store.Store, startedAt time.Time, activeSessions int) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stats, err := s.GetStats(ctx)
	if err != nil {
		return
	}

	m.clientsTotal.WithLabelValues("active").Set(float64(stats.ActiveClients))
	m.clientsTotal.WithLabelValues("revoked").Set(float64(stats.RevokedClients))

	m.connectionsActive.Set(float64(activeSessions))

	deltaUp := stats.TotalBytesUp - m.lastBytesUp
	if deltaUp > 0 {
		m.bytesTransferred.WithLabelValues("up").Add(float64(deltaUp))
	}
	deltaDown := stats.TotalBytesDown - m.lastBytesDown
	if deltaDown > 0 {
		m.bytesTransferred.WithLabelValues("down").Add(float64(deltaDown))
	}
	m.lastBytesUp = stats.TotalBytesUp
	m.lastBytesDown = stats.TotalBytesDown

	m.serverUptime.Set(time.Since(startedAt).Seconds())
	m.goroutines.Set(float64(runtime.NumGoroutine()))

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	m.memoryAlloc.Set(float64(mem.Alloc))
}

func (m *Metrics) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)
		duration := time.Since(start).Seconds()

		path := r.URL.Path
		if rctx := chi.RouteContext(r.Context()); rctx != nil {
			if pattern := rctx.RoutePattern(); pattern != "" {
				path = pattern
			}
		}

		m.httpRequestDuration.WithLabelValues(
			r.Method,
			path,
			strconv.Itoa(wrapped.statusCode),
		).Observe(duration)
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.written {
		rw.statusCode = code
		rw.written = true
	}
	rw.ResponseWriter.WriteHeader(code)
}
