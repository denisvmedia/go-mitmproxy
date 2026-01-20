package addonregistry_test

import (
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/denisvmedia/go-mitmproxy/proxy/internal/addonregistry"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/types"
)

type testAddon struct {
	types.BaseAddon
	name string
}

func TestRegistryAddAndGetReturnsAllAddonsInOrder(t *testing.T) {
	c := qt.New(t)

	reg := addonregistry.New()
	first := &testAddon{name: "first"}
	second := &testAddon{name: "second"}

	reg.Add(first)
	reg.Add(second)

	addons := reg.Get()

	c.Assert(len(addons), qt.Equals, 2)
	c.Assert(addons[0].(*testAddon).name, qt.Equals, "first")
	c.Assert(addons[1].(*testAddon).name, qt.Equals, "second")
}

func TestRegistryGetReturnsCopy(t *testing.T) {
	c := qt.New(t)

	reg := addonregistry.New()
	addon := &testAddon{name: "only"}
	reg.Add(addon)

	firstSnapshot := reg.Get()
	secondSnapshot := reg.Get()

	firstSnapshot[0] = &testAddon{name: "mutated"}

	c.Assert(len(firstSnapshot), qt.Equals, 1)
	c.Assert(len(secondSnapshot), qt.Equals, 1)
	c.Assert(secondSnapshot[0].(*testAddon).name, qt.Equals, "only")
}
