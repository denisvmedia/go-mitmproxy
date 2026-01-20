package version

import (
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	// Test with default values
	result := String()
	if !strings.Contains(result, Version) {
		t.Errorf("String() should contain version %q, got %q", Version, result)
	}
	if !strings.Contains(result, Commit) {
		t.Errorf("String() should contain commit %q, got %q", Commit, result)
	}
	if !strings.Contains(result, Date) {
		t.Errorf("String() should contain date %q, got %q", Date, result)
	}
}

func TestDefaultValues(t *testing.T) {
	// Verify default values are set
	if Version == "" {
		t.Error("Version should not be empty")
	}
	if Commit == "" {
		t.Error("Commit should not be empty")
	}
	if Date == "" {
		t.Error("Date should not be empty")
	}
}

