package helper_test

import (
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/denisvmedia/go-mitmproxy/internal/helper"
)

func TestMatchHost(t *testing.T) {
	c := qt.New(t)

	// Test case 1: Exact match
	address := "www.baidu.com:443"
	hosts := []string{
		"www.baidu.com:443",
		"www.baidu.com",
		"www.google.com",
	}
	result := helper.MatchHost(address, hosts)
	c.Assert(result, qt.IsTrue)

	// Test case 2: Exact match with port
	address = "www.google.com:80"
	hosts = []string{
		"www.baidu.com:443",
		"www.baidu.com",
		"www.google.com",
	}
	result = helper.MatchHost(address, hosts)
	c.Assert(result, qt.IsTrue)

	// Test case 3: No match
	address = "www.test.com:80"
	hosts = []string{
		"www.baidu.com:443",
		"www.baidu.com",
		"www.google.com",
	}
	result = helper.MatchHost(address, hosts)
	c.Assert(result, qt.IsFalse)

	// Test case 4: Wildcard match
	address = "test.baidu.com:443"
	hosts = []string{
		"*.baidu.com",
		"www.baidu.com:443",
		"www.baidu.com",
		"www.google.com",
	}
	result = helper.MatchHost(address, hosts)
	c.Assert(result, qt.IsTrue)

	// Test case 5: Wildcard match with port
	address = "test.baidu.com:443"
	hosts = []string{
		"*.baidu.com:443",
		"www.baidu.com:443",
		"www.baidu.com",
		"www.google.com",
	}
	result = helper.MatchHost(address, hosts)
	c.Assert(result, qt.IsTrue)

	// Test case 6: Wildcard mismatch
	address = "test.baidu.com:80"
	hosts = []string{
		"*.baidu.com:443",
		"www.baidu.com:443",
		"www.baidu.com",
		"www.google.com",
	}
	result = helper.MatchHost(address, hosts)
	c.Assert(result, qt.IsFalse)

	// Test case 7: Wildcard mismatch
	address = "test.google.com:80"
	hosts = []string{
		"*.baidu.com",
		"www.baidu.com:443",
		"www.baidu.com",
		"www.google.com",
	}
	result = helper.MatchHost(address, hosts)
	c.Assert(result, qt.IsFalse)
}
