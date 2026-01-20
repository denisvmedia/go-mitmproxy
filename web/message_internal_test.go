// This file contains tests for internal web message parsing and validation.
//
// Justification:
// - validMessageType: validates binary protocol message types
// - parseMessageEdit, parseMessageMeta: parse binary websocket messages
// - messageFlow.toBytes, messageEdit.toBytes: serialize messages to wire format
//
// These are core protocol parsing functions that define the websocket communication
// protocol between the proxy and the web interface. They require whitebox testing
// to ensure correctness of the binary format implementation.

package web

import (
	"encoding/binary"
	"testing"

	qt "github.com/frankban/quicktest"
	uuid "github.com/satori/go.uuid"

	"github.com/denisvmedia/go-mitmproxy/proxy"
)

func TestValidMessageTypeAcceptsKnownTypes(t *testing.T) {
	c := qt.New(t)

	knownTypes := []byte{0, 1, 2, 3, 4, 5, 11, 12, 13, 14, 21}

	for _, typ := range knownTypes {
		c.Assert(validMessageType(typ), qt.IsTrue)
	}
}

func TestValidMessageTypeRejectsUnknownTypes(t *testing.T) {
	c := qt.New(t)

	unknownTypes := []byte{6, 7, 8, 9, 10, 15, 99, 255}

	for _, typ := range unknownTypes {
		c.Assert(validMessageType(typ), qt.IsFalse)
	}
}

func TestMessageFlowToBytesHasCorrectFormat(t *testing.T) {
	c := qt.New(t)

	id := uuid.NewV4()
	msg := &messageFlow{
		mType:         messageTypeRequest,
		id:            id,
		waitIntercept: 1,
		content:       []byte("test content"),
	}

	bytes := msg.toBytes()

	c.Assert(bytes[0], qt.Equals, byte(messageVersion))
	c.Assert(bytes[1], qt.Equals, byte(messageTypeRequest))
	c.Assert(string(bytes[2:38]), qt.Equals, id.String())
	c.Assert(bytes[38], qt.Equals, byte(1))
	c.Assert(string(bytes[39:]), qt.Equals, "test content")
}

func TestParseMessageEditReturnsNilForShortData(t *testing.T) {
	c := qt.New(t)

	shortData := []byte{1, 2, 3}
	msg := parseMessageEdit(shortData)

	c.Assert(msg, qt.IsNil)
}

func TestParseMessageEditParsesDropRequest(t *testing.T) {
	c := qt.New(t)

	id := uuid.NewV4()
	data := make([]byte, 38)
	data[0] = messageVersion
	data[1] = byte(messageTypeDropRequest)
	copy(data[2:38], []byte(id.String()))

	msg := parseMessageEdit(data)

	c.Assert(msg, qt.IsNotNil)
	c.Assert(msg.mType, qt.Equals, messageTypeDropRequest)
	c.Assert(msg.id, qt.Equals, id)
}

func TestParseMessageEditParsesChangeRequest(t *testing.T) {
	c := qt.New(t)

	id := uuid.NewV4()
	headerJSON := []byte(`{"method":"GET","url":"http://example.com","proto":"HTTP/1.1","header":{}}`)
	body := []byte("request body")

	data := make([]byte, 46+len(headerJSON)+len(body))
	data[0] = messageVersion
	data[1] = byte(messageTypeChangeRequest)
	copy(data[2:38], []byte(id.String()))
	binary.BigEndian.PutUint32(data[38:42], uint32(len(headerJSON)))
	copy(data[42:42+len(headerJSON)], headerJSON)
	binary.BigEndian.PutUint32(data[42+len(headerJSON):46+len(headerJSON)], uint32(len(body)))
	copy(data[46+len(headerJSON):], body)

	msg := parseMessageEdit(data)

	c.Assert(msg, qt.IsNotNil)
	c.Assert(msg.mType, qt.Equals, messageTypeChangeRequest)
	c.Assert(msg.id, qt.Equals, id)
	c.Assert(msg.request, qt.IsNotNil)
	c.Assert(msg.request.Method, qt.Equals, "GET")
	c.Assert(msg.request.Body, qt.DeepEquals, body)
}

func TestParseMetaMessageExtractsBreakpointRules(t *testing.T) {
	c := qt.New(t)

	rulesJSON := []byte(`[{"method":"GET","url":"http://example.com","action":3}]`)
	data := make([]byte, 2+len(rulesJSON))
	data[0] = messageVersion
	data[1] = byte(messageTypeChangeBreakPointRules)
	copy(data[2:], rulesJSON)

	msg := parseMessageMeta(data)

	c.Assert(msg, qt.IsNotNil)
	c.Assert(msg.mType, qt.Equals, messageTypeChangeBreakPointRules)
	c.Assert(len(msg.breakPointRules), qt.Equals, 1)
	c.Assert(msg.breakPointRules[0].Method, qt.Equals, "GET")
	c.Assert(msg.breakPointRules[0].URL, qt.Equals, "http://example.com")
	c.Assert(msg.breakPointRules[0].Action, qt.Equals, 3)
}

func TestNewMessageConnCloseEncodesFlowCount(t *testing.T) {
	c := qt.New(t)

	connCtx := &proxy.ConnContext{
		ClientConn: &proxy.ClientConn{},
	}
	connCtx.FlowCount.Store(42)

	msg := newMessageConnClose(connCtx)

	c.Assert(msg.mType, qt.Equals, messageTypeConnClose)
	c.Assert(msg.id, qt.Equals, connCtx.ID())
	c.Assert(len(msg.content), qt.Equals, 4)

	flowCount := binary.BigEndian.Uint32(msg.content)
	c.Assert(flowCount, qt.Equals, uint32(42))
}
