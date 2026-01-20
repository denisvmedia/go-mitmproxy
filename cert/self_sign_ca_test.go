package cert_test

import (
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/denisvmedia/go-mitmproxy/cert"
)

func TestNewCA(t *testing.T) {
	c := qt.New(t)
	ca, err := cert.NewSelfSignCA("")
	c.Assert(err, qt.IsNil)
	c.Assert(ca, qt.IsNotNil)
}
