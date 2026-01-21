package reliability

import (
	"github.com/supabase/sdaudit/internal/rules"
	"github.com/supabase/sdaudit/pkg/types"
)

func init() {
	rules.Register(&REL001{})
}

type REL001 struct{}

func (r *REL001) ID() string   { return "REL001" }
func (r *REL001) Name() string { return "Restart policy not configured" }

func (r *REL001) Description() string {
	return "Long-running services should have a Restart= policy to recover from crashes."
}

func (r *REL001) Category() types.Category { return types.CategoryReliability }
func (r *REL001) Severity() types.Severity { return types.SeverityHigh }
func (r *REL001) Tags() []string           { return []string{"availability", "resilience", "recovery"} }

func (r *REL001) Suggestion() string {
	return "Add 'Restart=on-failure' or 'Restart=always' to the [Service] section."
}

func (r *REL001) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.service.html#Restart="}
}

func (r *REL001) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil || !unit.IsService() {
		return nil
	}

	// Oneshot services typically don't need restart
	if unit.GetDirective("Service", "Type") == "oneshot" {
		return nil
	}

	restart := unit.GetDirective("Service", "Restart")
	if restart == "" || restart == "no" {
		return []types.Issue{{
			RuleID:      r.ID(),
			RuleName:    r.Name(),
			Severity:    r.Severity(),
			Category:    r.Category(),
			Tags:        r.Tags(),
			Unit:        unit.Name,
			File:        unit.Path,
			Description: "Service has no restart policy. It will not recover from crashes.",
			Suggestion:  r.Suggestion(),
			References:  r.References(),
		}}
	}
	return nil
}
