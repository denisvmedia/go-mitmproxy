// This file contains tests that require access to internal/unexported types and methods.
//
// Justification:
// - mapRemoteItem: Tests the internal matching and replacement logic for map remote rules
// - mapFrom: Tests the internal request matching logic
// - match() and replace() methods: Test critical internal behavior for URL rewriting
//
// These tests verify the core logic of the MapRemote addon that cannot be adequately
// tested through the public API alone. The internal matching and replacement algorithms
// need thorough unit testing to ensure correctness across various edge cases.

package addons

import (
	"net/url"
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/denisvmedia/go-mitmproxy/proxy"
)

func TestMapItemMatch(t *testing.T) {
	c := qt.New(t)

	req := &proxy.Request{
		Method: "GET",
		URL: &url.URL{
			Scheme: "https",
			Host:   "example.com",
			Path:   "/path/to/resource",
		},
	}

	// test match

	item := &mapRemoteItem{
		From: &mapFrom{
			Protocol: "https",
			Host:     "example.com",
			Method:   []string{"GET", "POST"},
			Path:     "/path/to/resource",
		},
		To:     nil,
		Enable: true,
	}
	result := item.match(req)
	c.Assert(result, qt.IsTrue)

	// empty Protocol and empty Method match
	item.From = &mapFrom{
		Protocol: "",
		Host:     "example.com",
		Method:   nil,
		Path:     "/path/to/resource",
	}
	result = item.match(req)
	c.Assert(result, qt.IsTrue)

	// empty Host match
	item.From = &mapFrom{
		Protocol: "",
		Host:     "",
		Method:   nil,
		Path:     "/path/to/*",
	}
	result = item.match(req)
	c.Assert(result, qt.IsTrue)

	// all empty match
	item.From = &mapFrom{
		Protocol: "",
		Host:     "",
		Method:   nil,
		Path:     "",
	}
	result = item.match(req)
	c.Assert(result, qt.IsTrue)

	// test not match

	// diff Protocol
	item.From = &mapFrom{
		Protocol: "http",
		Host:     "example.com",
		Method:   nil,
		Path:     "/path/to/resource",
	}
	result = item.match(req)
	c.Assert(result, qt.IsFalse)

	// diff Host
	item.From = &mapFrom{
		Protocol: "https",
		Host:     "hello.com",
		Method:   nil,
		Path:     "/path/to/resource",
	}
	result = item.match(req)
	c.Assert(result, qt.IsFalse)

	// diff Method
	item.From = &mapFrom{
		Protocol: "https",
		Host:     "example.com",
		Method:   []string{"PUT"},
		Path:     "/path/to/resource",
	}
	result = item.match(req)
	c.Assert(result, qt.IsFalse)

	// diff Path
	item.From = &mapFrom{
		Protocol: "http",
		Host:     "example.com",
		Method:   nil,
		Path:     "/hello/world",
	}
	result = item.match(req)
	c.Assert(result, qt.IsFalse)
}

func TestMapItemReplace(t *testing.T) {
	c := qt.New(t)

	rawreq := func() *proxy.Request {
		return &proxy.Request{
			Method: "GET",
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/path/to/resource",
			},
		}
	}

	item := &mapRemoteItem{
		From: &mapFrom{
			Protocol: "https",
			Host:     "example.com",
			Method:   []string{"GET", "POST"},
			Path:     "/path/to/resource",
		},
		To: &mapRemoteTo{
			Protocol: "http",
			Host:     "hello.com",
			Path:     "",
		},
		Enable: true,
	}
	req := item.replace(rawreq())
	should := "http://hello.com/path/to/resource"
	c.Assert(req.URL.String(), qt.Equals, should)

	item = &mapRemoteItem{
		From: &mapFrom{
			Protocol: "https",
			Host:     "example.com",
			Method:   []string{"GET", "POST"},
			Path:     "/path/to/resource",
		},
		To: &mapRemoteTo{
			Protocol: "http",
			Host:     "hello.com",
			Path:     "/path/to/resource",
		},
		Enable: true,
	}
	req = item.replace(rawreq())
	should = "http://hello.com/path/to/resource"
	c.Assert(req.URL.String(), qt.Equals, should)

	item = &mapRemoteItem{
		From: &mapFrom{
			Protocol: "https",
			Host:     "example.com",
			Method:   []string{"GET", "POST"},
			Path:     "/path/to/resource",
		},
		To: &mapRemoteTo{
			Protocol: "http",
			Host:     "hello.com",
			Path:     "/path/to/world",
		},
		Enable: true,
	}
	req = item.replace(rawreq())
	should = "http://hello.com/path/to/world"
	c.Assert(req.URL.String(), qt.Equals, should)

	item = &mapRemoteItem{
		From: &mapFrom{
			Protocol: "https",
			Host:     "example.com",
			Method:   []string{"GET", "POST"},
			Path:     "/path/to/*",
		},
		To: &mapRemoteTo{
			Protocol: "http",
			Host:     "hello.com",
			Path:     "",
		},
		Enable: true,
	}
	req = item.replace(rawreq())
	should = "http://hello.com/path/to/resource"
	c.Assert(req.URL.String(), qt.Equals, should)

	item = &mapRemoteItem{
		From: &mapFrom{
			Protocol: "https",
			Host:     "example.com",
			Method:   []string{"GET", "POST"},
			Path:     "/path/to/*",
		},
		To: &mapRemoteTo{
			Protocol: "http",
			Host:     "hello.com",
			Path:     "/world",
		},
		Enable: true,
	}
	req = item.replace(rawreq())
	should = "http://hello.com/world/resource"
	c.Assert(req.URL.String(), qt.Equals, should)
}
