// Package reqmetrics counts and times the requests an HTTP surface of this
// service answers, by bounded labels the surface names and the status.
package reqmetrics

import (
	"net/http"
	"strconv"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Recorder is one surface's request counter and latency histogram.
type Recorder struct {
	requests metric.Int64Counter
	latency  metric.Float64Histogram
}

// New is the recorder of the surface prefix (prefix.requests,
// prefix.duration) on meter.
func New(meter metric.Meter, prefix, what string) Recorder {
	// Instrument creation fails only on an invalid name, fixed by callers.
	requests, _ := meter.Int64Counter(prefix+".requests", metric.WithDescription(what))
	latency, _ := meter.Float64Histogram(prefix+".duration", metric.WithUnit("s"), metric.WithDescription(what))

	return Recorder{requests: requests, latency: latency}
}

// Wrap records next's requests with labels (bounded: never an identifier
// from the request) and the response's status.
func (r Recorder) Wrap(next http.Handler, labels func(*http.Request) []attribute.KeyValue) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()
		sw := &status{ResponseWriter: w, code: http.StatusOK}

		next.ServeHTTP(sw, req)

		attrs := append(labels(req), attribute.String("status", strconv.Itoa(sw.code)))
		set := metric.WithAttributes(attrs...)
		r.requests.Add(req.Context(), 1, set)
		r.latency.Record(req.Context(), time.Since(start).Seconds(), set)
	})
}

// status remembers the code a handler wrote.
type status struct {
	http.ResponseWriter

	code int
}

func (s *status) WriteHeader(code int) {
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the writer.
func (s *status) Unwrap() http.ResponseWriter { return s.ResponseWriter }
