package version_test

import (
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/denisvmedia/go-mitmproxy/version"
)

func TestString(t *testing.T) {
	c := qt.New(t)
	// Test with default values
	result := version.String()
	c.Assert(strings.Contains(result, version.Version), qt.IsTrue, qt.Commentf("String() should contain version %q, got %q", version.Version, result))
	c.Assert(strings.Contains(result, version.Commit), qt.IsTrue, qt.Commentf("String() should contain commit %q, got %q", version.Commit, result))
	c.Assert(strings.Contains(result, version.Date), qt.IsTrue, qt.Commentf("String() should contain date %q, got %q", version.Date, result))
}

func TestDefaultValues(t *testing.T) {
	c := qt.New(t)
	// Verify default values are set
	c.Assert(version.Version, qt.Not(qt.Equals), "", qt.Commentf("Version should not be empty"))
	c.Assert(version.Commit, qt.Not(qt.Equals), "", qt.Commentf("Commit should not be empty"))
	c.Assert(version.Date, qt.Not(qt.Equals), "", qt.Commentf("Date should not be empty"))
}
