package web

import (
	"log/slog"
	"strings"
	"sync"

	"github.com/gorilla/websocket"

	"github.com/denisvmedia/go-mitmproxy/proxy"
)

type breakPointRule struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	Action int    `json:"action"` // 1 - change request 2 - change response 3 - both
}

type concurrentConn struct {
	conn *websocket.Conn
	mu   sync.Mutex

	sendConnMessageMap map[string]bool

	waitChans   map[string]chan any
	waitChansMu sync.Mutex

	breakPointRules []*breakPointRule
}

func newConn(c *websocket.Conn) *concurrentConn {
	return &concurrentConn{
		conn:               c,
		sendConnMessageMap: make(map[string]bool),
		waitChans:          make(map[string]chan any),
	}
}

func (c *concurrentConn) trySendConnMessage(f *proxy.Flow) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := f.ConnContext.ID().String()
	if send := c.sendConnMessageMap[key]; send {
		return
	}
	c.sendConnMessageMap[key] = true
	msg, err := newMessageFlow(messageTypeConn, f)
	if err != nil {
		slog.Error("web addon gen msg failed", "error", err)
		return
	}
	if err := c.conn.WriteMessage(websocket.BinaryMessage, msg.toBytes()); err != nil {
		slog.Error("write websocket message failed", "error", err)
		return
	}
}

func (c *concurrentConn) whenConnClose(connCtx *proxy.ConnContext) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.sendConnMessageMap, connCtx.ID().String())

	msg := newMessageConnClose(connCtx)
	if err := c.conn.WriteMessage(websocket.BinaryMessage, msg.toBytes()); err != nil {
		slog.Error("write websocket message failed", "error", err)
		return
	}
}

func (c *concurrentConn) writeMessageMayWait(msg *messageFlow, f *proxy.Flow) {
	if c.isIntercpt(f, msg.mType) {
		msg.waitIntercept = 1
	}

	c.mu.Lock()
	err := c.conn.WriteMessage(websocket.BinaryMessage, msg.toBytes())
	c.mu.Unlock()
	if err != nil {
		slog.Error("write websocket message failed", "error", err)
		return
	}

	if msg.waitIntercept == 1 {
		c.waitIntercept(f)
	}
}

func (c *concurrentConn) writeMessage(msg *messageFlow) {
	msg.waitIntercept = 0
	c.mu.Lock()
	err := c.conn.WriteMessage(websocket.BinaryMessage, msg.toBytes())
	c.mu.Unlock()
	if err != nil {
		slog.Error("write websocket message failed", "error", err)
		return
	}
}

func (c *concurrentConn) readloop() {
	for {
		mt, data, err := c.conn.ReadMessage()
		if err != nil {
			slog.Error("read websocket message failed", "error", err)
			break
		}

		if mt != websocket.BinaryMessage {
			slog.Warn("not BinaryMessage, skip")
			continue
		}

		msg := parseMessage(data)
		if msg == nil {
			slog.Warn("parseMessage error, skip")
			continue
		}

		if msgEdit, ok := msg.(*messageEdit); ok {
			ch := c.initWaitChan(msgEdit.id.String())
			go func(m *messageEdit, ch chan<- any) {
				ch <- m
			}(msgEdit, ch)
		} else if msgMeta, ok := msg.(*messageMeta); ok {
			c.breakPointRules = msgMeta.breakPointRules
		} else {
			slog.Warn("invalid message, skip")
		}
	}
}

func (c *concurrentConn) initWaitChan(key string) chan any {
	c.waitChansMu.Lock()
	defer c.waitChansMu.Unlock()

	if ch, ok := c.waitChans[key]; ok {
		return ch
	}
	ch := make(chan any)
	c.waitChans[key] = ch
	return ch
}

// Check whether to intercept.
func (c *concurrentConn) isIntercpt(f *proxy.Flow, mType messageType) bool {
	if mType != messageTypeRequestBody && mType != messageTypeResponseBody {
		return false
	}

	if len(c.breakPointRules) == 0 {
		return false
	}

	var action int
	if mType == messageTypeRequestBody {
		action = 1
	} else {
		action = 2
	}

	for _, rule := range c.breakPointRules {
		if rule.URL == "" {
			continue
		}
		if action&rule.Action == 0 {
			continue
		}
		if rule.Method != "" && rule.Method != f.Request.Method {
			continue
		}
		if strings.Contains(f.Request.URL.String(), rule.URL) {
			return true
		}
	}

	return false
}

// Intercept.
func (c *concurrentConn) waitIntercept(f *proxy.Flow) {
	ch := c.initWaitChan(f.ID.String())
	msgRaw := <-ch
	msg, ok := msgRaw.(*messageEdit)
	if !ok {
		slog.Error("received message is not a *messageEdit")
		f.Response = &proxy.Response{
			StatusCode: 500,
		}
		return
	}

	// drop
	if msg.mType == messageTypeDropRequest || msg.mType == messageTypeDropResponse {
		f.Response = &proxy.Response{
			StatusCode: 502,
		}
		return
	}

	// change
	switch msg.mType {
	case messageTypeChangeRequest:
		f.Request.Method = msg.request.Method
		f.Request.URL = msg.request.URL
		f.Request.Header = msg.request.Header
		f.Request.Body = msg.request.Body
	case messageTypeChangeResponse:
		f.Response.StatusCode = msg.response.StatusCode
		f.Response.Header = msg.response.Header
		f.Response.Body = msg.response.Body
	}
}
