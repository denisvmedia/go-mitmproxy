package web_test

import (
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/denisvmedia/go-mitmproxy/web"
)

func TestNewWebAddonCreatesAddon(t *testing.T) {
	c := qt.New(t)

	addon := web.NewWebAddon(":0")

	c.Assert(addon, qt.IsNotNil)
}
