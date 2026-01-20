package websocket_test

import (
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/denisvmedia/go-mitmproxy/proxy/internal/websocket"
)

func TestNewCreatesHandler(t *testing.T) {
	c := qt.New(t)

	handler := websocket.New()

	c.Assert(handler, qt.IsNotNil)
}
