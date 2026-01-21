package rules

import (
	"sort"
	"sync"

	"github.com/supabase/sdaudit/pkg/types"
)

var (
	registry     = make(map[string]Rule)
	registryLock sync.RWMutex
)

// Register adds a rule to the global registry
func Register(rule Rule) {
	registryLock.Lock()
	defer registryLock.Unlock()

	if _, exists := registry[rule.ID()]; exists {
		panic("rule already registered: " + rule.ID())
	}
	registry[rule.ID()] = rule
}

// Get returns a rule by ID, or nil if not found
func Get(id string) Rule {
	registryLock.RLock()
	defer registryLock.RUnlock()
	return registry[id]
}

// All returns all registered rules
func All() []Rule {
	registryLock.RLock()
	defer registryLock.RUnlock()

	rules := make([]Rule, 0, len(registry))
	for _, rule := range registry {
		rules = append(rules, rule)
	}

	sort.Slice(rules, func(i, j int) bool {
		return rules[i].ID() < rules[j].ID()
	})

	return rules
}

// Count returns the total number of registered rules
func Count() int {
	registryLock.RLock()
	defer registryLock.RUnlock()
	return len(registry)
}

// RunAll executes all rules against the given context and returns all issues
func RunAll(ctx *Context) []types.Issue {
	var allIssues []types.Issue

	for _, rule := range All() {
		if ctx.IsRuleDisabled(rule.ID()) {
			continue
		}

		issues := rule.Check(ctx)

		for i := range issues {
			if override, ok := ctx.GetSeverityOverride(rule.ID()); ok {
				issues[i].Severity = override
			}
		}

		allIssues = append(allIssues, issues...)
	}

	return allIssues
}

// RunFiltered executes rules matching the filter criteria
func RunFiltered(ctx *Context, category *types.Category, minSeverity *types.Severity, tags []string) []types.Issue {
	var allIssues []types.Issue

	for _, rule := range All() {
		if ctx.IsRuleDisabled(rule.ID()) {
			continue
		}

		if category != nil && rule.Category() != *category {
			continue
		}

		if minSeverity != nil && rule.Severity() < *minSeverity {
			continue
		}

		if len(tags) > 0 {
			hasTag := false
			tagSet := make(map[string]bool)
			for _, t := range tags {
				tagSet[t] = true
			}
			for _, t := range rule.Tags() {
				if tagSet[t] {
					hasTag = true
					break
				}
			}
			if !hasTag {
				continue
			}
		}

		issues := rule.Check(ctx)

		for i := range issues {
			if override, ok := ctx.GetSeverityOverride(rule.ID()); ok {
				issues[i].Severity = override
			}
		}

		allIssues = append(allIssues, issues...)
	}

	return allIssues
}
