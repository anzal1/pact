package pact

import (
	"testing"
)

func TestParseCapability(t *testing.T) {
	tests := []struct {
		input    string
		resource string
		action   string
		wantErr  bool
	}{
		{"github:pr:create", "github:pr", "create", false},
		{"github:*", "github", "*", false},
		{"*", "*", "*", false},
		{"flights:search", "flights", "search", false},
		{"flights:book", "flights", "book", false},
		{"email:send,to=*@mycompany.com", "email", "send", false},
		{"github:pr:create,repo=myorg/*", "github:pr", "create", false},
		{"", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			cap, err := ParseCapability(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cap.Resource != tt.resource {
				t.Errorf("resource: got %q, want %q", cap.Resource, tt.resource)
			}
			if cap.Action != tt.action {
				t.Errorf("action: got %q, want %q", cap.Action, tt.action)
			}
		})
	}
}

func TestParseCapabilityWithConstraints(t *testing.T) {
	cap, err := ParseCapability("email:send,to=*@mycompany.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cap.Constraints["to"] != "*@mycompany.com" {
		t.Errorf("constraint 'to': got %q, want %q", cap.Constraints["to"], "*@mycompany.com")
	}
}

func TestParseCapabilityLessThan(t *testing.T) {
	cap, err := ParseCapability("flights:book<500USD")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cap.Resource != "flights" {
		t.Errorf("resource: got %q, want 'flights'", cap.Resource)
	}
	if cap.Action != "book" {
		t.Errorf("action: got %q, want 'book'", cap.Action)
	}
	if cap.Constraints["max"] != "500USD" {
		t.Errorf("constraint 'max': got %q, want '500USD'", cap.Constraints["max"])
	}
}

func TestCapabilityCovers(t *testing.T) {
	tests := []struct {
		parent string
		child  string
		covers bool
	}{
		// Wildcard covers everything
		{"*", "github:pr:create", true},
		{"*", "flights:book<500USD", true},

		// Resource wildcard
		{"github:*", "github:pr:create", true},
		{"github:*", "github:issue:list", true},
		{"github:*", "slack:send", false},

		// Exact match
		{"github:pr:create", "github:pr:create", true},
		{"github:pr:create", "github:pr:merge", false},

		// Hierarchical resource matching
		{"github:pr:create,repo=myorg/*", "github:pr:create,repo=myorg/app", true},
		{"github:pr:create,repo=myorg/*", "github:pr:create,repo=other/app", false},

		// Numeric constraints
		{"flights:book,max=500USD", "flights:book,max=300USD", true},
		{"flights:book,max=500USD", "flights:book,max=600USD", false},
		{"flights:book,max=500USD", "flights:book,max=500USD", true},
	}

	for _, tt := range tests {
		t.Run(tt.parent+" covers "+tt.child, func(t *testing.T) {
			parent, err := ParseCapability(tt.parent)
			if err != nil {
				t.Fatalf("failed to parse parent: %v", err)
			}
			child, err := ParseCapability(tt.child)
			if err != nil {
				t.Fatalf("failed to parse child: %v", err)
			}

			got := parent.Covers(child)
			if got != tt.covers {
				t.Errorf("Covers: got %v, want %v", got, tt.covers)
			}
		})
	}
}

func TestCapabilitySetCovers(t *testing.T) {
	parent, _ := ParseCapabilitySet([]string{
		"github:pr:create,repo=myorg/*",
		"github:pr:merge,repo=myorg/*",
		"slack:send,channel=#eng",
	})

	// All capabilities covered
	child, _ := ParseCapabilitySet([]string{
		"github:pr:create,repo=myorg/app",
		"slack:send,channel=#eng",
	})
	if !parent.Covers(child) {
		t.Error("parent should cover child")
	}

	// One capability not covered
	childBad, _ := ParseCapabilitySet([]string{
		"github:pr:create,repo=myorg/app",
		"github:issue:create,repo=myorg/app", // not in parent
	})
	if parent.Covers(childBad) {
		t.Error("parent should NOT cover child with extra capability")
	}
}

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		match   bool
	}{
		{"*", "anything", true},
		{"myorg/*", "myorg/app", true},
		{"myorg/*", "other/app", false},
		{"*@mycompany.com", "alice@mycompany.com", true},
		{"*@mycompany.com", "alice@other.com", false},
		{"my*app", "mygreatapp", true},
		{"my*app", "myapp", true},
		{"my*app", "mygreat", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+" vs "+tt.value, func(t *testing.T) {
			got := globMatch(tt.pattern, tt.value)
			if got != tt.match {
				t.Errorf("globMatch(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.match)
			}
		})
	}
}
