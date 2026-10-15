// Package admin is the console module's API: the Kratos installation,
// its identities, sessions and courier, and the overlay. Every mutation
// is application audit.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane"
	"github.com/backplane-labs/backplane/pkg/backplane/config"
	"github.com/backplane-labs/backplane/pkg/backplane/deps"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/gopherex/xlog"

	"github.com/backplane-labs/backplane-kratos/internal/activities"
	"github.com/backplane-labs/backplane-kratos/internal/apply"
	"github.com/backplane-labs/backplane-kratos/internal/flows"
	"github.com/backplane-labs/backplane-kratos/internal/ory"
	"github.com/backplane-labs/backplane-kratos/internal/overlay"
	v1 "github.com/backplane-labs/backplane-kratos/proto/kratos/console/v1"
)

// cardSessions is how many sessions an identity card lists.
const cardSessions = 100

// Admin serves AdminService.
type Admin struct {
	v1.UnimplementedAdminServiceServer
	deps.Component

	kratos   ory.Client
	flows    *flows.Flows
	applier  *apply.Applier
	failOpen config.Live[[]string]
	settings config.Live[overlay.Settings]
	events   bool
}

// New creates the component under parent.
func New(
	parent deps.Scope,
	k ory.Client,
	f *flows.Flows,
	a *apply.Applier,
	failOpen config.Live[[]string],
	settings config.Live[overlay.Settings],
	events bool,
) *Admin {
	return &Admin{
		Component: deps.NewComponent(
			parent,
			"admin",
		), kratos: k, flows: f, applier: a, failOpen: failOpen, settings: settings, events: events,
	}
}

// grpcErr maps a Kratos error to a status the console shows.
func grpcErr(err error) error {
	if err == nil {
		return nil
	}

	var e *ory.Error
	if errors.As(err, &e) {
		switch {
		case e.Status == http.StatusNotFound:
			return status.Error(codes.NotFound, e.Error())
		case e.Status == http.StatusConflict:
			return status.Error(codes.AlreadyExists, e.Error())
		case e.Status == http.StatusBadRequest:
			return status.Error(codes.InvalidArgument, e.Error())
		case e.Status >= http.StatusInternalServerError:
			return status.Error(codes.Unavailable, e.Error())
		}

		return status.Error(codes.FailedPrecondition, e.Error())
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return status.Error(codes.DeadlineExceeded, err.Error())
	}

	return status.Error(codes.Unavailable, err.Error())
}

// audit records an operator action.
func (a *Admin) audit(ctx context.Context, action, subject string, err error, fields ...xlog.Field) {
	outcome := "succeeded"
	if err != nil {
		outcome = "failed"
	}

	fields = append(fields, backplane.Audit(), xlog.String("event.name", action),
		xlog.String(backplane.AuditID, uuid.NewString()), xlog.String(backplane.AuditSubject, subject),
		xlog.String(backplane.AuditActor, "console"), xlog.String(backplane.AuditOutcome, outcome))
	if err != nil {
		fields = append(fields, xlog.Err(err))
	}

	a.Log().Ctx().Info(ctx, action, fields...)
}

func ts(t *time.Time) *timestamppb.Timestamp {
	if t == nil || t.IsZero() {
		return nil
	}

	return timestamppb.New(*t)
}

// GetStatus implements AdminService.
func (a *Admin) GetStatus(ctx context.Context, _ *v1.GetStatusRequest) (*v1.GetStatusResponse, error) {
	out := &v1.GetStatusResponse{
		AdminUrl: a.kratos.AdminURL(), PublicUrl: a.kratos.PublicURL(), Events: a.events,
	}

	if err := a.kratos.Ready(ctx); err != nil {
		out.Problem = err.Error()
	}

	if v, err := a.kratos.Version(ctx); err == nil {
		out.Version = v
	}

	st := a.applier.State()
	out.Overlay = &v1.Overlay{Path: st.Path, Hash: st.Hash}

	if !st.WrittenAt.IsZero() {
		out.Overlay.WrittenAt = timestamppb.New(st.WrittenAt)
	}

	if st.Err != nil {
		out.Overlay.Error = st.Err.Error()
	}

	open := a.failOpen.Get()
	for _, name := range a.flows.Hooks() {
		out.Hooks = append(out.Hooks, &v1.HookPoint{
			Name: name, Bound: a.flows.Bound(name), FailOpen: slices.Contains(open, name), Description: describe(name),
		})
	}

	for _, s := range a.flows.Stats() {
		c := &v1.CallbackStat{
			Point: s.Point, Calls: s.Calls, Failures: s.Failures, LastOutcome: s.LastOutcome, LastError: s.LastError,
			LastLatencyMs: float64(s.LastLatency.Microseconds()) / 1000, //nolint:mnd // ms
		}
		if !s.LastAt.IsZero() {
			c.LastAt = timestamppb.New(s.LastAt)
		}

		out.Callbacks = append(out.Callbacks, c)
	}

	return out, nil
}

func describe(name string) string {
	if name == overlay.DeliverHook {
		return "Kratos's courier messages: codes and links by email or SMS"
	}

	for _, flow := range overlay.Flows() {
		switch name {
		case overlay.HookName("before", flow):
			return "Before a " + flow + " flow starts"
		case overlay.HookName("after", flow):
			return "When a " + flow + " flow completes"
		}
	}

	return ""
}

// GetOverlay implements AdminService.
func (a *Admin) GetOverlay(context.Context, *v1.GetOverlayRequest) (*v1.GetOverlayResponse, error) {
	content, err := a.applier.Masked()
	if err != nil {
		// Settings that do not render are the answer, not a failure of the call.
		return &v1.GetOverlayResponse{Error: err.Error()}, nil //nolint:nilerr // reported in the response
	}

	return &v1.GetOverlayResponse{Content: string(content)}, nil
}

// identity converts Kratos's identity; credentials keep types and
// identifiers only.
func identity(ident ory.Identity) *v1.Identity {
	out := &v1.Identity{
		Id: ident.ID, SchemaId: ident.SchemaID, State: ident.State, TraitsJson: string(ident.Traits),
		MetadataPublicJson: jsonText(ident.MetadataPublic), MetadataAdminJson: jsonText(ident.MetadataAdmin),
		ExternalId: ident.ExternalID, CreatedAt: ts(ident.CreatedAt), UpdatedAt: ts(ident.UpdatedAt), Label: label(ident),
	}

	for _, v := range ident.VerifiableAddresses {
		out.VerifiableAddresses = append(
			out.VerifiableAddresses,
			&v1.Address{Value: v.Value, Via: v.Via, Verified: v.Verified, Status: v.Status},
		)
	}

	for _, r := range ident.RecoveryAddresses {
		out.RecoveryAddresses = append(out.RecoveryAddresses, &v1.Address{Value: r.Value, Via: r.Via})
	}

	types := make([]string, 0, len(ident.Credentials))
	for t := range ident.Credentials {
		types = append(types, t)
	}

	slices.Sort(types)

	for _, t := range types {
		c := ident.Credentials[t]
		out.Credentials = append(
			out.Credentials,
			&v1.Credential{Type: t, Identifiers: c.Identifiers, CreatedAt: ts(c.CreatedAt)},
		)
	}

	return out
}

func jsonText(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}

	return string(raw)
}

// label is the best human handle of an identity.
func label(ident ory.Identity) string {
	for _, t := range []string{"password", "code", "webauthn", "passkey"} {
		if c, ok := ident.Credentials[t]; ok && len(c.Identifiers) > 0 {
			return c.Identifiers[0]
		}
	}

	var traits map[string]any
	if json.Unmarshal(ident.Traits, &traits) == nil {
		for _, k := range []string{"email", "username", "phone", "name"} {
			if s, ok := traits[k].(string); ok && s != "" {
				return s
			}
		}
	}

	if len(ident.VerifiableAddresses) > 0 {
		return ident.VerifiableAddresses[0].Value
	}

	return ident.ID
}

// ListIdentities implements AdminService.
func (a *Admin) ListIdentities(ctx context.Context, r *v1.ListIdentitiesRequest) (*v1.ListIdentitiesResponse, error) {
	f := ory.IdentityFilter{PageSize: int(r.GetPageSize()), PageToken: r.GetPageToken()}

	q := strings.TrimSpace(r.GetQuery())
	if q != "" {
		if _, err := uuid.Parse(q); err == nil {
			f.IDs = []string{q}
		} else {
			f.CredentialsIdentifier = q
		}
	}

	page, err := a.kratos.ListIdentities(ctx, f)
	if err != nil {
		return nil, grpcErr(err)
	}

	// Neither an identifier nor an id: maybe an external id.
	if len(page.Items) == 0 && f.CredentialsIdentifier != "" && f.PageToken == "" {
		if ident, err := a.kratos.GetIdentityByExternalID(ctx, q); err == nil {
			page.Items = []ory.Identity{ident}
		}
	}

	out := &v1.ListIdentitiesResponse{NextPageToken: page.Next}
	for i := range page.Items {
		out.Identities = append(out.Identities, identity(page.Items[i]))
	}

	return out, nil
}

// GetIdentity implements AdminService.
func (a *Admin) GetIdentity(ctx context.Context, r *v1.GetIdentityRequest) (*v1.GetIdentityResponse, error) {
	ident, err := a.kratos.GetIdentity(ctx, r.GetId())
	if err != nil {
		return nil, grpcErr(err)
	}

	out := &v1.GetIdentityResponse{Identity: identity(ident)}

	page, err := a.kratos.ListIdentitySessions(ctx, r.GetId(), ory.SessionFilter{PageSize: cardSessions})
	if err != nil {
		return nil, grpcErr(err)
	}

	for _, s := range page.Items {
		out.Sessions = append(out.Sessions, session(s, ident))
	}

	return out, nil
}

func session(s ory.Session, owner ory.Identity) *v1.Session {
	if s.Identity != nil {
		owner = *s.Identity
	}

	out := &v1.Session{
		Id: s.ID, Active: s.Active, IdentityId: owner.ID, Aal: s.AuthenticatorAssuranceLevel,
		AuthenticatedAt: ts(s.AuthenticatedAt), ExpiresAt: ts(s.ExpiresAt),
	}
	if owner.ID != "" {
		out.IdentityLabel = label(owner)
	}

	for _, m := range s.AuthenticationMethods {
		out.Methods = append(out.Methods, m.Method)
	}

	for _, d := range s.Devices {
		out.Devices = append(
			out.Devices,
			&v1.Device{IpAddress: d.IPAddress, UserAgent: d.UserAgent, Location: d.Location},
		)
	}

	return out
}

func rawOrNil(s string) json.RawMessage {
	if strings.TrimSpace(s) == "" {
		return nil
	}

	return json.RawMessage(s)
}

// errJSON: a JSON field is not JSON.
func checkJSON(fields map[string]string) error {
	for name, v := range fields {
		if strings.TrimSpace(v) != "" && !json.Valid([]byte(v)) {
			return status.Errorf(codes.InvalidArgument, "%s is not valid JSON", name)
		}
	}

	return nil
}

// CreateIdentity implements AdminService.
func (a *Admin) CreateIdentity(ctx context.Context, r *v1.CreateIdentityRequest) (*v1.CreateIdentityResponse, error) {
	if err := checkJSON(map[string]string{
		"traits": r.GetTraitsJson(), "metadata_public": r.GetMetadataPublicJson(), "metadata_admin": r.GetMetadataAdminJson(),
	}); err != nil {
		return nil, err
	}

	ident, err := activities.CreateIdentity(ctx, a.kratos, activities.IdentityIn{
		SchemaID: r.GetSchemaId(), Traits: rawOrNil(r.GetTraitsJson()), State: r.GetState(), Password: r.GetPassword(),
		ExternalID:     r.GetExternalId(),
		MetadataPublic: rawOrNil(r.GetMetadataPublicJson()), MetadataAdmin: rawOrNil(r.GetMetadataAdminJson()),
	})
	a.audit(ctx, "kratos.identity.created", "identity/"+ident.ID, err)

	if err != nil {
		return nil, grpcErr(err)
	}

	return &v1.CreateIdentityResponse{Identity: identity(ident)}, nil
}

// UpdateIdentity implements AdminService.
func (a *Admin) UpdateIdentity(ctx context.Context, r *v1.UpdateIdentityRequest) (*v1.UpdateIdentityResponse, error) {
	if err := checkJSON(map[string]string{
		"traits": r.GetTraitsJson(), "metadata_public": r.GetMetadataPublicJson(), "metadata_admin": r.GetMetadataAdminJson(),
	}); err != nil {
		return nil, err
	}

	ident, err := activities.UpdateIdentity(ctx, a.kratos, activities.IdentityIn{
		ID: r.GetId(), SchemaID: r.GetSchemaId(), Traits: rawOrNil(r.GetTraitsJson()), State: r.GetState(),
		MetadataPublic: rawOrNil(r.GetMetadataPublicJson()), MetadataAdmin: rawOrNil(r.GetMetadataAdminJson()),
	})
	a.audit(ctx, "kratos.identity.updated", "identity/"+r.GetId(), err, xlog.String("state", r.GetState()))

	if err != nil {
		return nil, grpcErr(err)
	}

	return &v1.UpdateIdentityResponse{Identity: identity(ident)}, nil
}

// DeleteIdentity implements AdminService.
func (a *Admin) DeleteIdentity(ctx context.Context, r *v1.DeleteIdentityRequest) (*v1.DeleteIdentityResponse, error) {
	err := a.kratos.DeleteIdentity(ctx, r.GetId())
	a.audit(ctx, "kratos.identity.deleted", "identity/"+r.GetId(), err)

	return &v1.DeleteIdentityResponse{}, grpcErr(err)
}

// DeleteCredentials implements AdminService.
func (a *Admin) DeleteCredentials(
	ctx context.Context,
	r *v1.DeleteCredentialsRequest,
) (*v1.DeleteCredentialsResponse, error) {
	err := a.kratos.DeleteCredentials(ctx, r.GetId(), r.GetType(), r.GetIdentifier())
	a.audit(ctx, "kratos.credentials.deleted", "identity/"+r.GetId(), err, xlog.String("type", r.GetType()))

	return &v1.DeleteCredentialsResponse{}, grpcErr(err)
}

// CreateRecoveryCode implements AdminService.
func (a *Admin) CreateRecoveryCode(
	ctx context.Context,
	r *v1.CreateRecoveryCodeRequest,
) (*v1.CreateRecoveryCodeResponse, error) {
	var (
		recovery ory.RecoveryCode
		err      error
	)

	if r.GetLink() {
		recovery, err = a.kratos.CreateRecoveryLink(ctx, r.GetId(), r.GetExpiresIn())
	} else {
		recovery, err = a.kratos.CreateRecoveryCode(ctx, r.GetId(), r.GetExpiresIn(), r.GetFlowType())
	}

	a.audit(ctx, "kratos.recovery.created", "identity/"+r.GetId(), err)

	if err != nil {
		return nil, grpcErr(err)
	}

	return &v1.CreateRecoveryCodeResponse{
		Code:      recovery.Code,
		Link:      recovery.Link,
		ExpiresAt: ts(recovery.ExpiresAt),
	}, nil
}

// ListSessions implements AdminService.
func (a *Admin) ListSessions(ctx context.Context, r *v1.ListSessionsRequest) (*v1.ListSessionsResponse, error) {
	f := ory.SessionFilter{
		PageSize:  int(r.GetPageSize()),
		PageToken: r.GetPageToken(),
		Expand:    []string{"identity", "devices"},
	}
	if r.GetActiveOnly() {
		active := true
		f.Active = &active
	}

	page, err := a.kratos.ListSessions(ctx, f)
	if err != nil {
		return nil, grpcErr(err)
	}

	out := &v1.ListSessionsResponse{NextPageToken: page.Next}
	for _, s := range page.Items {
		out.Sessions = append(out.Sessions, session(s, ory.Identity{}))
	}

	return out, nil
}

// RevokeSessions implements AdminService.
func (a *Admin) RevokeSessions(ctx context.Context, r *v1.RevokeSessionsRequest) (*v1.RevokeSessionsResponse, error) {
	var err error

	switch {
	case r.GetSessionId() != "":
		err = a.kratos.DisableSession(ctx, r.GetSessionId())
		a.audit(ctx, "kratos.session.revoked", "session/"+r.GetSessionId(), err)
	case r.GetIdentityId() != "":
		err = a.kratos.DeleteIdentitySessions(ctx, r.GetIdentityId())
		a.audit(ctx, "kratos.sessions.revoked", "identity/"+r.GetIdentityId(), err)
	default:
		return nil, status.Error(codes.InvalidArgument, "session_id or identity_id is required")
	}

	return &v1.RevokeSessionsResponse{}, grpcErr(err)
}

func message(m ory.Message) *v1.Message {
	out := &v1.Message{
		Id: m.ID, Status: m.Status, Channel: m.Channel, Recipient: m.Recipient, TemplateType: m.TemplateType,
		SendCount: int32(min(m.SendCount, math.MaxInt32)), //nolint:gosec // bounded
		CreatedAt: ts(m.CreatedAt), UpdatedAt: ts(m.UpdatedAt),
	}
	if out.GetChannel() == "" {
		out.Channel = m.Type
	}

	for _, d := range m.Dispatches {
		out.Dispatches = append(
			out.Dispatches,
			&v1.Dispatch{Status: d.Status, Error: jsonText(d.Error), CreatedAt: ts(d.CreatedAt)},
		)
	}

	return out
}

// ListMessages implements AdminService.
func (a *Admin) ListMessages(ctx context.Context, r *v1.ListMessagesRequest) (*v1.ListMessagesResponse, error) {
	page, err := a.kratos.ListMessages(ctx, ory.MessageFilter{
		Status: r.GetStatus(), Recipient: r.GetRecipient(), PageSize: int(r.GetPageSize()), PageToken: r.GetPageToken(),
	})
	if err != nil {
		return nil, grpcErr(err)
	}

	out := &v1.ListMessagesResponse{NextPageToken: page.Next}
	for i := range page.Items {
		out.Messages = append(out.Messages, message(page.Items[i]))
	}

	return out, nil
}

// GetMessage implements AdminService.
func (a *Admin) GetMessage(ctx context.Context, r *v1.GetMessageRequest) (*v1.GetMessageResponse, error) {
	m, err := a.kratos.GetMessage(ctx, r.GetId())
	if err != nil {
		return nil, grpcErr(err)
	}

	out := &v1.GetMessageResponse{Message: message(m)}

	if r.GetReveal() {
		out.Subject, out.Body = m.Subject, m.Body
		a.audit(ctx, "kratos.message.revealed", "message/"+m.ID, nil, xlog.String("recipient", m.Recipient))
	}

	return out, nil
}

// ListSchemas implements AdminService.
func (a *Admin) ListSchemas(ctx context.Context, _ *v1.ListSchemasRequest) (*v1.ListSchemasResponse, error) {
	schemas, err := a.kratos.ListSchemas(ctx)
	if err != nil {
		return nil, grpcErr(err)
	}

	out := &v1.ListSchemasResponse{}
	for _, s := range schemas {
		out.Schemas = append(out.Schemas, &v1.Schema{Id: s.ID, SchemaJson: string(s.Schema)})
	}

	return out, nil
}

// SetAddressVerified implements AdminService.
func (a *Admin) SetAddressVerified(
	ctx context.Context,
	r *v1.SetAddressVerifiedRequest,
) (*v1.SetAddressVerifiedResponse, error) {
	ident, err := a.kratos.GetIdentity(ctx, r.GetId())
	if err != nil {
		return nil, grpcErr(err)
	}

	index := slices.IndexFunc(
		ident.VerifiableAddresses,
		func(v ory.VerifiableAddress) bool { return v.Value == r.GetValue() },
	)
	if index < 0 {
		return nil, status.Errorf(codes.NotFound, "the identity has no address %q", r.GetValue())
	}

	state := "pending"
	if r.GetVerified() {
		state = "completed"
	}

	type op struct {
		Op    string `json:"op"`
		Path  string `json:"path"`
		Value any    `json:"value"`
	}

	base := "/verifiable_addresses/" + strconv.Itoa(index)

	patch, err := json.Marshal([]op{
		{Op: "replace", Path: base + "/verified", Value: r.GetVerified()},
		{Op: "replace", Path: base + "/status", Value: state},
	})
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	ident, err = a.kratos.PatchIdentity(ctx, r.GetId(), patch)
	a.audit(ctx, "kratos.address.verified", "identity/"+r.GetId(), err,
		xlog.String("address", r.GetValue()), xlog.Bool("verified", r.GetVerified()))

	if err != nil {
		return nil, grpcErr(err)
	}

	return &v1.SetAddressVerifiedResponse{Identity: identity(ident)}, nil
}

// ImportIdentities implements AdminService.
func (a *Admin) ImportIdentities(
	ctx context.Context,
	r *v1.ImportIdentitiesRequest,
) (*v1.ImportIdentitiesResponse, error) {
	var bodies []json.RawMessage
	if err := json.Unmarshal([]byte(r.GetIdentitiesJson()), &bodies); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "identities must be a JSON array: %v", err)
	}

	results, err := a.kratos.ImportIdentities(ctx, bodies)
	a.audit(ctx, "kratos.identities.imported", "identities", err, xlog.Int("count", len(bodies)))

	if err != nil {
		return nil, grpcErr(err)
	}

	out := &v1.ImportIdentitiesResponse{}
	for _, res := range results {
		out.Results = append(
			out.Results,
			&v1.ImportResult{Action: res.Action, IdentityId: res.Identity, Error: jsonText(res.Error)},
		)
	}

	return out, nil
}

// ExtendSession implements AdminService.
func (a *Admin) ExtendSession(ctx context.Context, r *v1.ExtendSessionRequest) (*v1.ExtendSessionResponse, error) {
	s, err := a.kratos.ExtendSession(ctx, r.GetId())
	a.audit(ctx, "kratos.session.extended", "session/"+r.GetId(), err)

	if err != nil {
		return nil, grpcErr(err)
	}

	return &v1.ExtendSessionResponse{Session: session(s, ory.Identity{})}, nil
}
