package flows

import (
	"net/http/httputil"
	"net/url"
)

// kratosProxy passes requests on to Kratos's public API at public as the
// edge sent them: the client's host and forwarding headers kept, headers
// added (a proxy's authorization).
func kratosProxy(public *url.URL, headers map[string]string) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) {
		r.SetURL(public)
		r.Out.Host = r.In.Host

		// Kratos sees the client as the edge saw it.
		for _, h := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
			if v, ok := r.In.Header[h]; ok {
				r.Out.Header[h] = v
			}
		}

		for k, v := range headers {
			r.Out.Header.Set(k, v)
		}
	}}
}
