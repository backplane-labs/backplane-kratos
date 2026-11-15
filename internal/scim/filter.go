package scim

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
)

// Filter is a GET /Users filter: the attributes compared, joined by and; a
// zero Filter lists without one.
type Filter struct {
	UserName   string
	ExternalID string
	Email      string
}

// IsZero reports whether f compares nothing.
func (f Filter) IsZero() bool { return f == Filter{} }

// comparison is one `attr eq value` at the start of a filter folded to lower
// case outside quotes: the value quoted (with JSON escapes) or bare, as
// Entra ID sends either.
var comparison = regexp.MustCompile(
	`^\s*(username|externalid|emails\[\s*type\s+eq\s+"work"\s*\]\.value|emails\.value|emails)\s+eq\s+` +
		`("(?:[^"\\]|\\.)*"|[^\s"]+)\s*`)

// conjunction joins comparisons (in a folded filter).
var conjunction = regexp.MustCompile(`^and\s+`)

func invalidFilter(detail string) *Error {
	return refuse(http.StatusBadRequest, "invalidFilter", detail)
}

// ParseFilter reads the filters IdPs send: eq comparisons of userName,
// externalId or the work e-mail, joined by and. Attribute names and the
// operators are case-insensitive; values are compared as written.
func ParseFilter(s string) (Filter, error) {
	var f Filter

	rest := strings.TrimSpace(s)
	for rest != "" {
		// Folding changes ASCII letters only, so its offsets index rest too.
		m := comparison.FindStringSubmatchIndex(caseFold(rest))
		if m == nil {
			return Filter{}, invalidFilter("unsupported filter " + s)
		}

		value, err := filterValue(rest[m[4]:m[5]])
		if err != nil {
			return Filter{}, err
		}

		switch caseFold(rest[m[2]:m[3]]) {
		case "username":
			f.UserName = value
		case "externalid":
			f.ExternalID = value
		default:
			f.Email = value
		}

		rest = rest[m[1]:]
		if rest == "" {
			break
		}

		next := conjunction.FindString(caseFold(rest))
		if next == "" {
			return Filter{}, invalidFilter("unsupported filter " + s)
		}

		rest = rest[len(next):]
	}

	return f, nil
}

// filterValue is a comparison's value: a JSON string unquoted, a bare word
// as it is.
func filterValue(raw string) (string, error) {
	if !strings.HasPrefix(raw, `"`) {
		return raw, nil
	}

	var v string
	if json.Unmarshal([]byte(raw), &v) != nil {
		return "", invalidFilter("bad string " + raw)
	}

	return v, nil
}

// caseFold lowercases s outside double quotes, so the attribute names and
// operators match whatever case the IdP wrote them in.
func caseFold(s string) string {
	var b strings.Builder

	quoted, escaped := false, false

	for _, r := range s {
		switch {
		case escaped:
			escaped = false
		case quoted && r == '\\':
			escaped = true
		case r == '"':
			quoted = !quoted
		case !quoted:
			r = toLowerASCII(r)
		}

		b.WriteRune(r)
	}

	return b.String()
}

func toLowerASCII(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + ('a' - 'A')
	}

	return r
}
