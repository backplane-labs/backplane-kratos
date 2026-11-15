package scim

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gopherex/xlog"

	"github.com/backplane-labs/backplane-kratos/internal/ory"
)

// Path is the prefix of every directory's SCIM base URL, /scim/v2/<id>/.
const Path = "/scim/v2/"

const (
	contentType = "application/scim+json"
	listSchema  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	errorSchema = "urn:ietf:params:scim:api:messages:2.0:Error"
	// maxBody bounds a request body.
	maxBody = 1 << 20
	// maxResults bounds a page (the service provider config says so).
	maxResults = 100
	// timeout bounds one request's work against Kratos and the broker.
	timeout = 20 * time.Second
)

//go:embed static/*.json
var static embed.FS

// Handler serves every directory under Path.
func (e *Directories) Handler() http.Handler {
	mux := http.NewServeMux()
	base := Path + "{dir}/"

	for _, doc := range []string{"ServiceProviderConfig", "ResourceTypes", "Schemas"} {
		mux.Handle("GET "+base+doc, e.authed(func(w http.ResponseWriter, _ *http.Request, _ Directory) {
			body, _ := static.ReadFile("static/" + doc + ".json")
			write(w, http.StatusOK, body)
		}))
	}

	mux.Handle("GET "+base+"Groups", e.authed(func(w http.ResponseWriter, _ *http.Request, _ Directory) {
		writeJSON(w, http.StatusOK, list(nil, 1))
	}))
	mux.Handle("GET "+base+"Users", e.authed(e.find))
	mux.Handle("POST "+base+"Users", e.authed(e.create))
	mux.Handle("GET "+base+"Users/{id}", e.authed(e.get))
	mux.Handle("PUT "+base+"Users/{id}", e.authed(e.replace))
	mux.Handle("PATCH "+base+"Users/{id}", e.authed(e.patch))
	mux.Handle("DELETE "+base+"Users/{id}", e.authed(e.remove))
	mux.Handle(base, e.authed(func(w http.ResponseWriter, r *http.Request, _ Directory) {
		e.fail(w, r, notFound())
	}))

	return mux
}

type handler func(w http.ResponseWriter, r *http.Request, d Directory)

// authed resolves the directory and checks its token: Bearer or bare (Okta
// sends either), compared in constant time.
func (e *Directories) authed(next handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d, ok := find(e.dirs.Get(), r.PathValue("dir"))
		if !ok {
			e.fail(w, r, notFound())

			return
		}

		want := e.tokens.Get()[d.ID].Reveal()
		got := strings.TrimSpace(r.Header.Get("Authorization"))

		if len(got) > len("bearer ") && strings.EqualFold(got[:len("bearer ")], "bearer ") {
			got = strings.TrimSpace(got[len("bearer "):])
		}

		if want == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			e.fail(w, r, refuse(http.StatusUnauthorized, "", "authentication required"))

			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()

		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		next(w, r.WithContext(ctx), d)
	})
}

func (e *Directories) find(w http.ResponseWriter, r *http.Request, d Directory) {
	f, err := ParseFilter(r.URL.Query().Get("filter"))
	if err != nil {
		e.fail(w, r, err)

		return
	}

	ids, err := e.svc.Find(r.Context(), d, f)
	if err != nil {
		e.fail(w, r, err)

		return
	}

	start := max(atoi(r.URL.Query().Get("startIndex"), 1), 1)
	count := min(max(atoi(r.URL.Query().Get("count"), maxResults), 0), maxResults)

	page := []map[string]any{}

	for i := range ids {
		if i+1 >= start && len(page) < count {
			page = append(page, resource(ids[i], d.ID))
		}
	}

	out := list(page, start)
	out["totalResults"] = len(ids)
	writeJSON(w, http.StatusOK, out)
}

func (e *Directories) create(w http.ResponseWriter, r *http.Request, d Directory) {
	u, err := readUser(r)
	if err == nil {
		var id ory.Identity

		id, err = e.svc.Create(r.Context(), d, u)
		if err == nil {
			writeJSON(w, http.StatusCreated, resource(id, d.ID))

			return
		}
	}

	e.fail(w, r, err)
}

func (e *Directories) get(w http.ResponseWriter, r *http.Request, d Directory) {
	e.answer(w, r, d)(e.svc.Get(r.Context(), d, r.PathValue("id")))
}

func (e *Directories) replace(w http.ResponseWriter, r *http.Request, d Directory) {
	u, err := readUser(r)
	if err != nil {
		e.fail(w, r, err)

		return
	}

	e.answer(w, r, d)(e.svc.Replace(r.Context(), d, r.PathValue("id"), u))
}

func (e *Directories) patch(w http.ResponseWriter, r *http.Request, d Directory) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		e.fail(w, r, refuse(http.StatusRequestEntityTooLarge, "", "the body is too large"))

		return
	}

	ops, err := ParsePatch(body)
	if err != nil {
		e.fail(w, r, err)

		return
	}

	e.answer(w, r, d)(e.svc.Patch(r.Context(), d, r.PathValue("id"), ops))
}

func (e *Directories) remove(w http.ResponseWriter, r *http.Request, d Directory) {
	if err := e.svc.Delete(r.Context(), d, r.PathValue("id")); err != nil {
		e.fail(w, r, err)

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// answer writes the user id or the failure.
func (e *Directories) answer(w http.ResponseWriter, r *http.Request, d Directory) func(ory.Identity, error) {
	return func(id ory.Identity, err error) {
		if err != nil {
			e.fail(w, r, err)

			return
		}

		writeJSON(w, http.StatusOK, resource(id, d.ID))
	}
}

func readUser(r *http.Request) (User, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, refuse(http.StatusRequestEntityTooLarge, "", "the body is too large")
	}

	return ParseUser(body)
}

// fail writes err as a SCIM error: a refusal as it is, an event not yet out
// as 503 (the IdP retries), anything else as 500, logged once here.
func (e *Directories) fail(w http.ResponseWriter, r *http.Request, err error) {
	ref, ok := asError(err)

	switch {
	case ok:
	case errors.Is(err, errUnavailable):
		e.Log().Ctx().Warn(r.Context(), "scim: change kept, event pending", xlog.Err(err))

		ref = refuse(http.StatusServiceUnavailable, "", "try again")
	default:
		e.Log().Ctx().Error(r.Context(), "scim: request failed", xlog.Err(err))

		ref = refuse(http.StatusInternalServerError, "", "internal error")
	}

	out := map[string]any{"schemas": []string{errorSchema}, "status": strconv.Itoa(ref.Status), "detail": ref.Detail}
	if ref.Type != "" {
		out["scimType"] = ref.Type
	}

	writeJSON(w, ref.Status, out)
}

// resource is the SCIM user of an identity: what the directory last wrote,
// with the service's id, Kratos's state as active, and meta.
func resource(id ory.Identity, dir string) map[string]any {
	r, _ := stored(id)
	out := map[string]any{}

	for k, v := range r.User {
		out[k] = v
	}

	out["schemas"] = []string{UserSchema}
	out["id"] = id.ID
	out["active"] = id.State != inactive

	meta := map[string]any{"resourceType": "User", "location": Path + dir + "/Users/" + id.ID}
	if id.CreatedAt != nil {
		meta["created"] = id.CreatedAt.UTC().Format(time.RFC3339)
	}

	if id.UpdatedAt != nil {
		meta["lastModified"] = id.UpdatedAt.UTC().Format(time.RFC3339)
	}

	out["meta"] = meta

	return out
}

func list(page []map[string]any, start int) map[string]any {
	if page == nil {
		page = []map[string]any{}
	}

	return map[string]any{
		"schemas": []string{listSchema}, "totalResults": len(page), "startIndex": start,
		"itemsPerPage": len(page), "Resources": page,
	}
}

func atoi(s string, fallback int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}

	return n
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		status, body = http.StatusInternalServerError, []byte(`{"detail":"internal error"}`)
	}

	write(w, status, body)
}

func write(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
