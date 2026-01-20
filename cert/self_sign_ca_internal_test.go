// This file contains tests that require access to internal/unexported functions and types.
//
// Justification:
// - getStorePath: Tests the internal logic for determining the certificate storage path
// - saveTo: Tests the internal PEM encoding logic for saving certificates
// - caFile: Tests the internal path construction for the CA file
//
// These tests verify critical internal behavior that cannot be adequately tested through
// the public API alone, as they test specific implementation details and edge cases.

package cert

import (
	"bytes"
	"os"
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestGetStorePath(t *testing.T) {
	c := qt.New(t)
	path, err := getStorePath("")
	c.Assert(err, qt.IsNil)
	c.Assert(path, qt.Not(qt.Equals), "", qt.Commentf("should have path"))
}

func TestSaveToAndCaFile(t *testing.T) {
	c := qt.New(t)
	caAPI, err := NewSelfSignCA("")
	c.Assert(err, qt.IsNil)
	ca := caAPI.(*SelfSignCA)

	data := make([]byte, 0)
	buf := bytes.NewBuffer(data)

	err = ca.saveTo(buf)
	c.Assert(err, qt.IsNil)

	fileContent, err := os.ReadFile(ca.caFile())
	c.Assert(err, qt.IsNil)

	c.Assert(fileContent, qt.DeepEquals, buf.Bytes(), qt.Commentf("pem content should equal"))
}
