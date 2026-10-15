// Package insight finds settings that Kratos's schema accepts but that do
// not work together: a flow without its UI, links without the link method,
// codes with nowhere to go, nobody able to sign in.
package insight

import (
	"strings"

	"github.com/backplane-labs/backplane-kratos/internal/overlay"
)

// Levels of a finding.
const (
	Error   = "error"   // the flow breaks
	Warning = "warning" // it works only under a condition the console cannot see
	Info    = "info"    // worth knowing
)

// Finding is one problem of the settings.
type Finding struct {
	// Flow it is about; empty: the whole installation.
	Flow  string
	Level string
	Text  string
	// Field is the settings field to change (e.g. "recovery.ui_url").
	Field string
}

// State is what the findings look at.
type State struct {
	Settings overlay.Settings
	// Bound reports whether a hook (short name) is bound.
	Bound func(hook string) bool
}

func (s State) bound(hook string) bool { return s.Bound != nil && s.Bound(hook) }

// findings collects the findings of one State.
type findings struct {
	State

	out []Finding
}

func (f *findings) add(flow, level, field, text string) {
	f.out = append(f.out, Finding{Flow: flow, Level: level, Field: field, Text: text})
}

// Check lists the findings of st, the installation's first.
func Check(st State) []Finding {
	f := &findings{State: st}
	f.installation()
	f.uiPages()
	f.delivering()
	f.features()
	f.offFlows()

	return f.out
}

func (f *findings) installation() {
	s := f.Settings

	if !canSignIn(s.Methods) {
		f.add("", Error, "methods",
			"No method signs anyone in: enable passwords, passwordless codes, passkeys or social sign-in.")
	}

	if usesSMS(s) && !f.bound(overlay.DeliverHook) {
		f.add("", Error, "",
			"An identity schema sends codes by SMS, but SMS reaches nowhere until kratos.Deliver is bound.")
	}

	if s.Registration.Enabled && !canRegister(s.Methods) {
		f.add(overlay.FlowRegistration, Error, "methods", "Registration is open but no method can register an identity.")
	}

	if s.Login.RequireVerifiedAddress && !s.Verification.Enabled {
		f.add(overlay.FlowLogin, Error, "verification.enabled",
			"Login requires a verified address but verification is off: nobody new can verify and sign in.")
	}
}

// canSignIn reports whether a method signs someone in on its own.
func canSignIn(m overlay.Methods) bool {
	return m.Password.Enabled || m.Code.Passwordless || m.Passkey.Enabled ||
		(m.WebAuthn.Enabled && m.WebAuthn.Passwordless) || social(m)
}

// canRegister reports whether a method registers an identity.
func canRegister(m overlay.Methods) bool {
	return m.Password.Enabled || m.Code.Passwordless || m.Passkey.Enabled || m.WebAuthn.Enabled || social(m)
}

func social(m overlay.Methods) bool { return m.OIDC.Enabled && len(m.OIDC.Providers) > 0 }

func (f *findings) uiPages() {
	s := f.Settings

	pages := []struct{ flow, ui string }{
		{overlay.FlowRegistration, s.Registration.UIURL},
		{overlay.FlowLogin, s.Login.UIURL},
		{overlay.FlowSettings, s.Settings.UIURL},
	}

	for _, p := range pages {
		if p.ui == "" {
			f.add(p.flow, Warning, p.flow+".ui_url",
				"No UI page here: unless Kratos's own file sets one, browsers land on Ory's fallback page.")
		}
	}
}

// delivering checks the flows that deliver codes or links.
func (f *findings) delivering() {
	s := f.Settings

	flows := []struct {
		flow    string
		enabled bool
		ui, use string
	}{
		{overlay.FlowRecovery, s.Recovery.Enabled, s.Recovery.UIURL, s.Recovery.Use},
		{overlay.FlowVerification, s.Verification.Enabled, s.Verification.UIURL, s.Verification.Use},
	}

	for _, r := range flows {
		if !r.enabled {
			continue
		}

		if r.ui == "" {
			f.add(r.flow, Warning, r.flow+".ui_url",
				"No UI page here: unless Kratos's own file sets one, the codes and links lead to Ory's fallback page.")
		}

		if r.use == "link" && !s.Methods.Link.Enabled {
			f.add(r.flow, Error, "methods.link.enabled",
				"It delivers links but the link method is off: enable it or deliver codes.")
		}

		if r.use == "code" && !s.Methods.Code.Enabled {
			f.add(r.flow, Error, "methods.code.enabled", "It delivers codes but the code method is off.")
		}
	}
}

func (f *findings) features() {
	s := f.Settings

	if s.Recovery.Enabled && !s.Features.ContinueWith {
		f.add(overlay.FlowRecovery, Info, "features.continue_with",
			"Native apps cannot finish a recovery: it ends with a browser redirect to the settings page "+
				"unless native app flows are on.")
	}

	if s.Recovery.Enabled && usesSMS(s) && !s.Features.ChooseRecoveryAddress {
		f.add(overlay.FlowRecovery, Warning, "features.choose_recovery_address",
			"Recovery by SMS needs the recovery with a chosen address.")
	}
}

func (f *findings) offFlows() {
	for _, flow := range overlay.Flows() {
		hooked := f.bound(overlay.HookName("before", flow)) || f.bound(overlay.HookName("after", flow))
		if hooked && !flowOn(f.Settings, flow) {
			f.add(flow, Info, "", "Its hooks are bound but the flow is off: they never run.")
		}
	}
}

// flowOn reports whether users can run a flow.
func flowOn(s overlay.Settings, flow string) bool {
	switch flow {
	case overlay.FlowRegistration:
		return s.Registration.Enabled
	case overlay.FlowRecovery:
		return s.Recovery.Enabled
	case overlay.FlowVerification:
		return s.Verification.Enabled
	default:
		return true
	}
}

// usesSMS reports whether an identity schema of the settings sends by SMS.
func usesSMS(s overlay.Settings) bool {
	for _, doc := range s.Identity.Schemas {
		compact := strings.Join(strings.Fields(doc), "")
		if strings.Contains(compact, `"via":"sms"`) {
			return true
		}
	}

	return false
}
