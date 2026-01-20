package helper_test

import (
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/denisvmedia/go-mitmproxy/internal/helper"
)

func TestGetTLSKeyLogWriterReturnsNilWhenNotConfigured(t *testing.T) {
	c := qt.New(t)

	writer := helper.GetTLSKeyLogWriter()

	c.Assert(writer, qt.IsNil)
}
