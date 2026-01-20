// This file contains tests for internal map local functionality.
//
// Justification:
// - mapLocalItem.match, mapLocalItem.response: core matching and file serving logic
// - MapLocal.validate: validation of configuration rules
//
// These functions define how local file mappings work and cannot be adequately
// tested through the public API alone since they involve unexported types.

package addons

import (
	"net/url"
	"os"
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/denisvmedia/go-mitmproxy/proxy"
)

func TestMapLocalItemMatchWithEnabledItem(t *testing.T) {
	c := qt.New(t)

	item := &mapLocalItem{
		From: &mapFrom{
			Protocol: "http",
			Host:     "example.com",
			Path:     "/api",
		},
		Enable: true,
	}

	req := &proxy.Request{
		URL:    &url.URL{Scheme: "http", Host: "example.com", Path: "/api"},
		Method: "GET",
		Header: make(map[string][]string),
	}

	c.Assert(item.match(req), qt.IsTrue)
}

func TestMapLocalItemMatchWithDisabledItem(t *testing.T) {
	c := qt.New(t)

	item := &mapLocalItem{
		From: &mapFrom{
			Protocol: "http",
			Host:     "example.com",
			Path:     "/api",
		},
		Enable: false,
	}

	req := &proxy.Request{
		URL:    &url.URL{Scheme: "http", Host: "example.com", Path: "/api"},
		Method: "GET",
		Header: make(map[string][]string),
	}

	c.Assert(item.match(req), qt.IsFalse)
}

func TestMapLocalItemResponseReturns404ForMissingFile(t *testing.T) {
	c := qt.New(t)

	item := &mapLocalItem{
		From: &mapFrom{
			Path: "/api",
		},
		To: &mapLocalTo{
			Path: "/nonexistent/file.txt",
		},
	}

	req := &proxy.Request{
		URL:    &url.URL{Path: "/api"},
		Method: "GET",
		Header: make(map[string][]string),
	}

	_, resp := item.response(req)

	c.Assert(resp.StatusCode, qt.Equals, 404)
}

func TestMapLocalItemResponseServesFileFromPath(t *testing.T) {
	c := qt.New(t)

	dir := t.TempDir()
	targetFile := dir + "/content.txt"
	_ = os.WriteFile(targetFile, []byte("file content"), 0o644)

	item := &mapLocalItem{
		From: &mapFrom{
			Path: "/api",
		},
		To: &mapLocalTo{
			Path: targetFile,
		},
	}

	req := &proxy.Request{
		URL:    &url.URL{Path: "/api"},
		Method: "GET",
		Header: make(map[string][]string),
	}

	path, resp := item.response(req)

	c.Assert(path, qt.Equals, targetFile)
	c.Assert(resp.StatusCode, qt.Equals, 200)
	c.Assert(resp.BodyReader, qt.IsNotNil)
}

func TestMapLocalItemResponseServesFromDirectory(t *testing.T) {
	c := qt.New(t)

	dir := t.TempDir()
	subDir := dir + "/subdir"
	_ = os.Mkdir(subDir, 0o755)
	targetFile := subDir + "/file.txt"
	_ = os.WriteFile(targetFile, []byte("content"), 0o644)

	item := &mapLocalItem{
		From: &mapFrom{
			Path: "/api/*",
		},
		To: &mapLocalTo{
			Path: dir,
		},
	}

	req := &proxy.Request{
		URL:    &url.URL{Path: "/api/subdir/file.txt"},
		Method: "GET",
		Header: make(map[string][]string),
	}

	_, resp := item.response(req)

	c.Assert(resp.StatusCode, qt.Equals, 200)
	c.Assert(resp.BodyReader, qt.IsNotNil)
}

func TestMapLocalValidateFailsOnMissingFrom(t *testing.T) {
	c := qt.New(t)

	ml := &MapLocal{
		Items: []*mapLocalItem{
			{From: nil, To: &mapLocalTo{Path: "/tmp"}},
		},
	}

	err := ml.validate()

	c.Assert(err, qt.IsNotNil)
}

func TestMapLocalValidateFailsOnInvalidProtocol(t *testing.T) {
	c := qt.New(t)

	ml := &MapLocal{
		Items: []*mapLocalItem{
			{
				From: &mapFrom{Protocol: "ftp"},
				To:   &mapLocalTo{Path: "/tmp"},
			},
		},
	}

	err := ml.validate()

	c.Assert(err, qt.IsNotNil)
}

func TestMapLocalValidateFailsOnMissingTo(t *testing.T) {
	c := qt.New(t)

	ml := &MapLocal{
		Items: []*mapLocalItem{
			{From: &mapFrom{}, To: nil},
		},
	}

	err := ml.validate()

	c.Assert(err, qt.IsNotNil)
}

func TestMapLocalValidateFailsOnEmptyPath(t *testing.T) {
	c := qt.New(t)

	ml := &MapLocal{
		Items: []*mapLocalItem{
			{From: &mapFrom{}, To: &mapLocalTo{Path: ""}},
		},
	}

	err := ml.validate()

	c.Assert(err, qt.IsNotNil)
}

func TestMapLocalValidatePassesForValidConfig(t *testing.T) {
	c := qt.New(t)

	ml := &MapLocal{
		Items: []*mapLocalItem{
			{
				From: &mapFrom{Protocol: "http", Host: "example.com"},
				To:   &mapLocalTo{Path: "/tmp/file.txt"},
			},
		},
	}

	err := ml.validate()

	c.Assert(err, qt.IsNil)
}

func TestMapLocalFromFileLoadsConfig(t *testing.T) {
	c := qt.New(t)

	dir := t.TempDir()
	targetFile := dir + "/target.txt"
	_ = os.WriteFile(targetFile, []byte("content"), 0o644)

	configContent := `{
		"Enable": true,
		"Items": [
			{
				"From": {"Protocol": "http", "Host": "example.com", "Path": "/api"},
				"To": {"Path": "` + targetFile + `"},
				"Enable": true
			}
		]
	}`
	configFile := dir + "/maplocal.json"
	_ = os.WriteFile(configFile, []byte(configContent), 0o644)

	ml, err := NewMapLocalFromFile(configFile)

	c.Assert(err, qt.IsNil)
	c.Assert(ml.Enable, qt.IsTrue)
	c.Assert(len(ml.Items), qt.Equals, 1)
}
