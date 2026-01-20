package addons_test

import (
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/denisvmedia/go-mitmproxy/proxy/addons"
)

// TestMapRemotePublicAPI tests the public API of MapRemote addon.
// Internal matching and replacement logic is tested in mapremote_internal_test.go.
func TestMapRemotePublicAPI(t *testing.T) {
	c := qt.New(t)

	// Test that we can create a MapRemote instance
	mr := &addons.MapRemote{
		Enable: true,
	}
	c.Assert(mr, qt.IsNotNil)
	c.Assert(mr.Enable, qt.IsTrue)
}
