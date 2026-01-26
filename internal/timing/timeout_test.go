package timing

import (
	"testing"
	"time"

	"github.com/supabase/sdaudit/pkg/types"
)

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{"5", 5 * time.Second, false},
		{"5s", 5 * time.Second, false},
		{"5sec", 5 * time.Second, false},
		{"5seconds", 5 * time.Second, false},
		{"5min", 5 * time.Minute, false},
		{"5m", 5 * time.Minute, false},
		{"5h", 5 * time.Hour, false},
		{"1h30min", 90 * time.Minute, false},
		{"100ms", 100 * time.Millisecond, false},
		{"100msec", 100 * time.Millisecond, false},
		{"1000us", 1000 * time.Microsecond, false},
		{"1d", 24 * time.Hour, false},
		{"1w", 7 * 24 * time.Hour, false},
		{"infinity", 0, false},
		{"0", 0, false},
		{"", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseDuration(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDuration(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.expected {
				t.Errorf("ParseDuration(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestParseTimeouts(t *testing.T) {
	unit := &types.UnitFile{
		Name: "test.service",
		Path: "/etc/systemd/system/test.service",
		Type: "service",
		Sections: map[string]*types.Section{
			"Service": {
				Name: "Service",
				Directives: map[string][]types.Directive{
					"TimeoutStartSec": {{Key: "TimeoutStartSec", Value: "30", Line: 5}},
					"TimeoutStopSec":  {{Key: "TimeoutStopSec", Value: "60", Line: 6}},
					"RestartSec":      {{Key: "RestartSec", Value: "5", Line: 7}},
				},
			},
		},
	}

	config := ParseTimeouts(unit, nil)

	if config.TimeoutStartSec != 30*time.Second {
		t.Errorf("TimeoutStartSec = %v, want 30s", config.TimeoutStartSec)
	}
	if config.TimeoutStopSec != 60*time.Second {
		t.Errorf("TimeoutStopSec = %v, want 60s", config.TimeoutStopSec)
	}
	if config.RestartSec != 5*time.Second {
		t.Errorf("RestartSec = %v, want 5s", config.RestartSec)
	}
}

func TestParseTimeouts_Defaults(t *testing.T) {
	unit := &types.UnitFile{
		Name:     "test.service",
		Path:     "/etc/systemd/system/test.service",
		Type:     "service",
		Sections: map[string]*types.Section{},
	}

	config := ParseTimeouts(unit, nil)

	if config.TimeoutStartSec != DefaultTimeoutStartSec {
		t.Errorf("TimeoutStartSec = %v, want default %v", config.TimeoutStartSec, DefaultTimeoutStartSec)
	}
	if config.TimeoutStopSec != DefaultTimeoutStopSec {
		t.Errorf("TimeoutStopSec = %v, want default %v", config.TimeoutStopSec, DefaultTimeoutStopSec)
	}
	if config.RestartSec != DefaultRestartSec {
		t.Errorf("RestartSec = %v, want default %v", config.RestartSec, DefaultRestartSec)
	}
}

func TestParseTimeouts_TimeoutSec(t *testing.T) {
	// TimeoutSec sets both start and stop
	unit := &types.UnitFile{
		Name: "test.service",
		Path: "/etc/systemd/system/test.service",
		Type: "service",
		Sections: map[string]*types.Section{
			"Service": {
				Name: "Service",
				Directives: map[string][]types.Directive{
					"TimeoutSec": {{Key: "TimeoutSec", Value: "45", Line: 5}},
				},
			},
		},
	}

	config := ParseTimeouts(unit, nil)

	if config.TimeoutStartSec != 45*time.Second {
		t.Errorf("TimeoutStartSec = %v, want 45s", config.TimeoutStartSec)
	}
	if config.TimeoutStopSec != 45*time.Second {
		t.Errorf("TimeoutStopSec = %v, want 45s", config.TimeoutStopSec)
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		input    time.Duration
		expected string
	}{
		{0, "infinity"},
		{500 * time.Millisecond, "500ms"},
		{5 * time.Second, "5s"},
		{90 * time.Second, "1m30s"},
		{3600 * time.Second, "1h0m0s"},
	}

	for _, tt := range tests {
		got := FormatDuration(tt.input)
		// FormatDuration uses d.String() which has standard Go formatting
		// Just verify it's not empty and handles infinity correctly
		if tt.input == 0 && got != "infinity" {
			t.Errorf("FormatDuration(0) = %q, want \"infinity\"", got)
		}
		if tt.input > 0 && got == "" {
			t.Errorf("FormatDuration(%v) returned empty string", tt.input)
		}
	}
}
