package admin

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/backplane-labs/backplane-kratos/internal/insight"
	"github.com/backplane-labs/backplane-kratos/internal/ory"
	"github.com/backplane-labs/backplane-kratos/internal/overlay"
	v1 "github.com/backplane-labs/backplane-kratos/proto/kratos/console/v1"
)

// events of completed flows, as flows declares them.
func eventOf(flow string) string {
	switch flow {
	case overlay.FlowRegistration:
		return "kratos.Registered"
	case overlay.FlowLogin:
		return "kratos.LoggedIn"
	case overlay.FlowSettings:
		return "kratos.SettingsChanged"
	case overlay.FlowRecovery:
		return "kratos.Recovered"
	default:
		return "kratos.Verified"
	}
}

func finding(f insight.Finding) *v1.Finding {
	return &v1.Finding{Level: f.Level, Text: f.Text, Field: f.Field}
}

// GetFlows implements AdminService.
func (a *Admin) GetFlows(context.Context, *v1.GetFlowsRequest) (*v1.GetFlowsResponse, error) {
	findings := insight.Check(insight.State{Settings: a.settings.Get(), Bound: a.flows.Bound})
	stats := map[string]*v1.FlowHook{}

	for _, s := range a.flows.Stats() {
		h := &v1.FlowHook{Calls: s.Calls, Failures: s.Failures, LastOutcome: s.LastOutcome}
		if !s.LastAt.IsZero() {
			h.LastAt = timestamppb.New(s.LastAt)
		}

		stats[s.Point] = h // hooks/<when>/<flow>
	}

	open := a.failOpen.Get()
	out := &v1.GetFlowsResponse{}

	for _, flow := range overlay.Flows() {
		card := &v1.FlowCard{Flow: flow, Event: eventOf(flow)}

		for _, when := range []string{"before", "after"} {
			name := overlay.HookName(when, flow)
			h := &v1.FlowHook{}

			if s, ok := stats["hooks/"+when+"/"+flow]; ok {
				h = s
			}

			h.Name, h.When, h.Bound, h.FailOpen = name, when, a.flows.Bound(name), slices.Contains(open, name)
			card.Hooks = append(card.Hooks, h)
		}

		out.Flows = append(out.Flows, card)
	}

	for _, f := range findings {
		if f.Flow == "" {
			out.Findings = append(out.Findings, finding(f))

			continue
		}

		for _, card := range out.GetFlows() {
			if card.GetFlow() == f.Flow {
				card.Findings = append(card.Findings, finding(f))
			}
		}
	}

	return out, nil
}

// kratosFlow is the part of a flow TryFlow reads.
type kratosFlow struct {
	UI struct {
		Nodes []struct {
			Group      string `json:"group"`
			Attributes struct {
				Name     string          `json:"name"`
				Type     string          `json:"type"`
				NodeType string          `json:"node_type"`
				Required bool            `json:"required"`
				Value    json.RawMessage `json:"value"`
			} `json:"attributes"`
			Messages []struct {
				Text string `json:"text"`
			} `json:"messages"`
			Meta struct {
				Label *struct {
					Text string `json:"text"`
				} `json:"label"`
			} `json:"meta"`
		} `json:"nodes"`
		Messages []struct {
			Text string `json:"text"`
		} `json:"messages"`
	} `json:"ui"`
}

// TryFlow implements AdminService.
func (a *Admin) TryFlow(ctx context.Context, r *v1.TryFlowRequest) (*v1.TryFlowResponse, error) {
	if !slices.Contains(overlay.Flows(), r.GetFlow()) {
		return &v1.TryFlowResponse{Error: "unknown flow " + r.GetFlow()}, nil
	}

	if r.GetFlow() == overlay.FlowSettings {
		return &v1.TryFlowResponse{Error: "the settings flow belongs to a signed-in user: sign in from the UI to see it"}, nil
	}

	raw, err := a.kratos.InitFlow(ctx, r.GetFlow())
	if err != nil {
		var e *ory.Error
		if errors.As(err, &e) {
			return &v1.TryFlowResponse{Error: e.Error()}, nil
		}

		return nil, grpcErr(err)
	}

	var f kratosFlow
	if err := json.Unmarshal(raw, &f); err != nil {
		// The answer is the problem, not a failure of the call.
		out := &v1.TryFlowResponse{FlowJson: string(raw), Error: "not a flow: " + err.Error()}

		return out, nil //nolint:nilerr // see above
	}

	out := &v1.TryFlowResponse{FlowJson: string(raw)}

	for _, m := range f.UI.Messages {
		out.Messages = append(out.Messages, m.Text)
	}

	for i := range f.UI.Nodes {
		n := &f.UI.Nodes[i]

		node := &v1.FormNode{
			Group: n.Group, Name: n.Attributes.Name, Type: n.Attributes.Type, Required: n.Attributes.Required,
			Value: strings.Trim(string(n.Attributes.Value), `"`),
		}
		if node.GetType() == "" {
			node.Type = n.Attributes.NodeType
		}

		if n.Meta.Label != nil {
			node.Label = n.Meta.Label.Text
		}

		for _, m := range n.Messages {
			node.Messages = append(node.Messages, m.Text)
		}

		out.Nodes = append(out.Nodes, node)
	}

	return out, nil
}
