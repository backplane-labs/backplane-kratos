package overlay

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

// SchemaVersion is the Kratos release whose configuration schema
// validates the overlay.
const SchemaVersion = "v26.2.0"

//go:embed kratos.schema.json
var kratosSchema []byte

// stubBase stands in for the deployment's file: the keys Kratos requires,
// so the overlay is checked as Kratos will see it merged.
func stubBase() map[string]any {
	return map[string]any{
		"dsn": "memory",
		"identity": map[string]any{
			"default_schema_id": "default",
			"schemas":           []any{map[string]any{"id": "default", "url": "base64://e30="}},
		},
		"selfservice": map[string]any{"default_browser_return_url": "http://127.0.0.1/"},
		"courier":     map[string]any{"smtp": map[string]any{"connection_uri": "smtp://127.0.0.1:25/"}},
	}
}

//nolint:gochecknoglobals // compiled once per process
var compiled = sync.OnceValues(func() (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(kratosSchema))
	if err != nil {
		return nil, fmt.Errorf("kratos schema: %w", err)
	}

	c := jsonschema.NewCompiler()
	c.AssertFormat()

	if err := c.AddResource("https://kratos.local/config.schema.json", doc); err != nil {
		return nil, fmt.Errorf("kratos schema: %w", err)
	}

	// The tracing block lives in ory/x; the overlay never sets it.
	if err := c.AddResource("ory://tracing-config", map[string]any{}); err != nil {
		return nil, fmt.Errorf("kratos schema: %w", err)
	}

	s, err := c.Compile("https://kratos.local/config.schema.json")
	if err != nil {
		return nil, fmt.Errorf("kratos schema: %w", err)
	}

	return s, nil
})

// ErrInvalid: Kratos would refuse the overlay.
var ErrInvalid = errors.New("kratos would refuse the configuration")

// Validate checks doc against Kratos's configuration schema, merged over
// a stand-in base file.
func Validate(doc map[string]any) error {
	schema, err := compiled()
	if err != nil {
		return err
	}

	merged := stubBase()
	overlayOnto(merged, doc)

	// Round-trip through JSON: the validator wants JSON types.
	raw, err := json.Marshal(merged)
	if err != nil {
		return fmt.Errorf("overlay: %w", err)
	}

	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("overlay: %w", err)
	}

	if err := schema.Validate(value); err != nil {
		var verr *jsonschema.ValidationError
		if errors.As(err, &verr) {
			return fmt.Errorf("%w: %s", ErrInvalid, describe(verr))
		}

		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}

	return nil
}

// maxCauses bounds the causes an error lists.
const maxCauses = 5

// describe flattens a validation error to its leaf causes.
func describe(e *jsonschema.ValidationError) string {
	printer := message.NewPrinter(language.English)

	var out []string

	var walk func(*jsonschema.ValidationError)

	walk = func(e *jsonschema.ValidationError) {
		if len(e.Causes) == 0 {
			loc := "/" + strings.Join(e.InstanceLocation, "/")
			out = append(out, loc+": "+e.ErrorKind.LocalizedString(printer))

			return
		}

		for _, c := range e.Causes {
			walk(c)
		}
	}

	walk(e)

	if len(out) > maxCauses {
		out = append(out[:maxCauses], fmt.Sprintf("and %d more", len(out)-maxCauses))
	}

	return strings.Join(out, "; ")
}

// overlayOnto merges src into dst as Kratos merges files: maps deeply,
// anything else replaced.
func overlayOnto(dst, src map[string]any) {
	for k, sv := range src {
		if srcMap, isMap := sv.(map[string]any); isMap {
			if dstMap, ok := dst[k].(map[string]any); ok {
				overlayOnto(dstMap, srcMap)

				continue
			}
		}

		dst[k] = sv
	}
}
