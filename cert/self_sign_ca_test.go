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

func TestNewCA(t *testing.T) {
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
