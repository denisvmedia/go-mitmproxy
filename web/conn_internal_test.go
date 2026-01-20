// This file contains tests for internal web connection breakpoint logic.
//
// Justification:
// - concurrentConn.isIntercpt: determines if a request should be intercepted based on breakpoint rules
// - breakPointRule matching: validates URL and method matching for interception
//
// These functions implement the interception decision logic which is core to the
// web debugging interface but requires access to unexported types.

package web

import (
	"net/url"
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/denisvmedia/go-mitmproxy/proxy"
)

func TestConcurrentConnIsInterceptWithNoRules(t *testing.T) {
	c := qt.New(t)

	conn := &concurrentConn{
		breakPointRules: nil,
	}

	flow := &proxy.Flow{
		Request: &proxy.Request{
			Method: "GET",
			URL:    &url.URL{Scheme: "http", Host: "example.com", Path: "/api"},
			Header: make(map[string][]string),
		},
	}

	result := conn.isIntercpt(flow, messageTypeRequestBody)

	c.Assert(result, qt.IsFalse)
}

func TestConcurrentConnIsInterceptWithMatchingRule(t *testing.T) {
	c := qt.New(t)

	conn := &concurrentConn{
		breakPointRules: []*breakPointRule{
			{
				Method: "GET",
				URL:    "example.com",
				Action: 1,
			},
		},
	}

	flow := &proxy.Flow{
		Request: &proxy.Request{
			Method: "GET",
			URL:    &url.URL{Scheme: "http", Host: "example.com", Path: "/api"},
			Header: make(map[string][]string),
		},
	}

	result := conn.isIntercpt(flow, messageTypeRequestBody)

	c.Assert(result, qt.IsTrue)
}

func TestConcurrentConnIsInterceptWithNonMatchingMethod(t *testing.T) {
	c := qt.New(t)

	conn := &concurrentConn{
		breakPointRules: []*breakPointRule{
			{
				Method: "POST",
				URL:    "example.com",
				Action: 1,
			},
		},
	}

	flow := &proxy.Flow{
		Request: &proxy.Request{
			Method: "GET",
			URL:    &url.URL{Scheme: "http", Host: "example.com", Path: "/api"},
			Header: make(map[string][]string),
		},
	}

	result := conn.isIntercpt(flow, messageTypeRequestBody)

	c.Assert(result, qt.IsFalse)
}

func TestConcurrentConnIsInterceptWithResponseBodyType(t *testing.T) {
	c := qt.New(t)

	conn := &concurrentConn{
		breakPointRules: []*breakPointRule{
			{
				Method: "GET",
				URL:    "example.com",
				Action: 2,
			},
		},
	}

	flow := &proxy.Flow{
		Request: &proxy.Request{
			Method: "GET",
			URL:    &url.URL{Scheme: "http", Host: "example.com", Path: "/api"},
			Header: make(map[string][]string),
		},
	}

	result := conn.isIntercpt(flow, messageTypeResponseBody)

	c.Assert(result, qt.IsTrue)
}

func TestConcurrentConnIsInterceptWithBothAction(t *testing.T) {
	c := qt.New(t)

	conn := &concurrentConn{
		breakPointRules: []*breakPointRule{
			{
				Method: "GET",
				URL:    "example.com",
				Action: 3,
			},
		},
	}

	flow := &proxy.Flow{
		Request: &proxy.Request{
			Method: "GET",
			URL:    &url.URL{Scheme: "http", Host: "example.com", Path: "/api"},
			Header: make(map[string][]string),
		},
	}

	requestResult := conn.isIntercpt(flow, messageTypeRequestBody)
	responseResult := conn.isIntercpt(flow, messageTypeResponseBody)

	c.Assert(requestResult, qt.IsTrue)
	c.Assert(responseResult, qt.IsTrue)
}

func TestConcurrentConnIsInterceptIgnoresNonBodyMessageTypes(t *testing.T) {
	c := qt.New(t)

	conn := &concurrentConn{
		breakPointRules: []*breakPointRule{
			{
				Method: "GET",
				URL:    "example.com",
				Action: 3,
			},
		},
	}

	flow := &proxy.Flow{
		Request: &proxy.Request{
			Method: "GET",
			URL:    &url.URL{Scheme: "http", Host: "example.com", Path: "/api"},
			Header: make(map[string][]string),
		},
	}

	result := conn.isIntercpt(flow, messageTypeRequest)

	c.Assert(result, qt.IsFalse)
}
