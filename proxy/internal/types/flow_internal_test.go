// This file contains tests for internal Flow functionality.
//
// Justification:
// - NewFlow: constructor that creates flows with proper initialization
// - Done/Finish: channel-based synchronization mechanism for flow completion
//
// These are core mechanisms that define how flows are created and lifecycle events
// are managed, requiring whitebox testing.

package types

import (
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	uuid "github.com/satori/go.uuid"
)

func TestNewFlowCreatesFlowWithID(t *testing.T) {
	c := qt.New(t)

	flow := NewFlow()

	c.Assert(flow, qt.IsNotNil)
	c.Assert(flow.ID, qt.Not(qt.Equals), uuid.UUID{})
	c.Assert(flow.Done(), qt.IsNotNil)
}

func TestFlowFinishClosesChannel(t *testing.T) {
	c := qt.New(t)

	flow := NewFlow()
	done := flow.Done()

	flow.Finish()

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		c.Fatal("Done channel should be closed")
	}
}

func TestFlowDoneChannelRemainsOpenBeforeFinish(t *testing.T) {
	c := qt.New(t)

	flow := NewFlow()
	done := flow.Done()

	select {
	case <-done:
		c.Fatal("Done channel should not be closed before Finish()")
	case <-time.After(10 * time.Millisecond):
	}

	flow.Finish()
}
