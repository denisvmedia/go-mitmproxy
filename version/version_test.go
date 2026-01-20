package version

import (
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestString(t *testing.T) {
	c := qt.New(t)
	// Test with default values
	result := String()
	c.Assert(strings.Contains(result, Version), qt.IsTrue, qt.Commentf("String() should contain version %q, got %q", Version, result))
	c.Assert(strings.Contains(result, Commit), qt.IsTrue, qt.Commentf("String() should contain commit %q, got %q", Commit, result))
	c.Assert(strings.Contains(result, Date), qt.IsTrue, qt.Commentf("String() should contain date %q, got %q", Date, result))
}

func TestDefaultValues(t *testing.T) {
	c := qt.New(t)
	// Verify default values are set
	c.Assert(Version, qt.Not(qt.Equals), "", qt.Commentf("Version should not be empty"))
	c.Assert(Commit, qt.Not(qt.Equals), "", qt.Commentf("Commit should not be empty"))
	c.Assert(Date, qt.Not(qt.Equals), "", qt.Commentf("Date should not be empty"))
}
