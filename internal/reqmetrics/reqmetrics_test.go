package reqmetrics_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/backplane-labs/backplane-kratos/internal/reqmetrics"
)

// A request is counted and timed with the surface's labels and its status.
func TestWrap(t *testing.T) {
	t.Parallel()

	reader := sdkmetric.NewManualReader()
	meter := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test")
	rec := reqmetrics.New(meter, "kratos.test", "test requests")

	h := rec.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }),
		func(*http.Request) []attribute.KeyValue { return []attribute.KeyValue{attribute.String("op", "brew")} })

	for _, path := range []string{"/a", "/b"} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, http.NoBody))
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}

	got := map[string]int64{}

	for _, m := range rm.ScopeMetrics[0].Metrics {
		switch data := m.Data.(type) {
		case metricdata.Sum[int64]:
			for _, p := range data.DataPoints {
				got[m.Name+"{"+p.Attributes.Encoded(attribute.DefaultEncoder())+"}"] = p.Value
			}
		case metricdata.Histogram[float64]:
			for _, p := range data.DataPoints {
				got[m.Name+"{"+p.Attributes.Encoded(attribute.DefaultEncoder())+"}"] = int64(p.Count)
			}
		}
	}

	if got["kratos.test.requests{op=brew,status=418}"] != 2 || got["kratos.test.duration{op=brew,status=418}"] != 2 {
		t.Fatalf("metrics %v", got)
	}
}
