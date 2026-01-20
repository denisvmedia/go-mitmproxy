package types

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"

	uuid "github.com/satori/go.uuid"

	"github.com/denisvmedia/go-mitmproxy/proxy/internal/conn"
)

// Request represents an HTTP request in the proxy flow.
type Request struct {
	Method string
	URL    *url.URL
	Proto  string
	Header http.Header
	Body   []byte

	raw *http.Request
}

// NewRequest creates a new Request from an http.Request.
func NewRequest(req *http.Request) *Request {
	return &Request{
		Method: req.Method,
		URL:    req.URL,
		Proto:  req.Proto,
		Header: req.Header,
		raw:    req,
	}
}

// Raw returns the underlying http.Request.
func (r *Request) Raw() *http.Request {
	return r.raw
}

func (r *Request) MarshalJSON() ([]byte, error) {
	m := make(map[string]any)
	m["method"] = r.Method
	m["url"] = r.URL.String()
	m["proto"] = r.Proto
	m["header"] = r.Header
	return json.Marshal(m)
}

func (r *Request) UnmarshalJSON(data []byte) error {
	m := make(map[string]any)
	err := json.Unmarshal(data, &m)
	if err != nil {
		return err
	}

	rawurl, ok := m["url"].(string)
	if !ok {
		return errors.New("url parse error")
	}
	u, err := url.Parse(rawurl)
	if err != nil {
		return err
	}

	rawheader, ok := m["header"].(map[string]any)
	if !ok {
		return errors.New("rawheader parse error")
	}

	header := make(map[string][]string)
	for k, v := range rawheader {
		vals, ok := v.([]any)
		if !ok {
			return errors.New("header parse error")
		}

		svals := make([]string, 0)
		for _, val := range vals {
			sval, ok := val.(string)
			if !ok {
				return errors.New("header parse error")
			}
			svals = append(svals, sval)
		}
		header[k] = svals
	}

	*r = Request{
		Method: m["method"].(string),
		URL:    u,
		Proto:  m["proto"].(string),
		Header: header,
	}
	return nil
}

// Response represents an HTTP response in the proxy flow.
type Response struct {
	StatusCode int         `json:"statusCode"`
	Header     http.Header `json:"header"`
	Body       []byte      `json:"-"`
	BodyReader io.Reader

	Close bool // connection close
}

// Flow represents a complete HTTP request/response flow.
type Flow struct {
	ID          uuid.UUID
	ConnContext *conn.Context
	Request     *Request
	Response    *Response

	// https://docs.mitmproxy.org/stable/overview-features/#streaming
	// If true, Request.Body and Response.Body are not buffered, and will not enter subsequent Addon.Request and Addon.Response
	Stream            bool
	UseSeparateClient bool // use separate http client to send http request
	done              chan struct{}
}

// NewFlow creates a new Flow instance.
func NewFlow() *Flow {
	return &Flow{
		ID:   uuid.NewV4(),
		done: make(chan struct{}),
	}
}

// Done returns a channel that is closed when the flow is finished.
func (f *Flow) Done() <-chan struct{} {
	return f.done
}

// Finish marks the flow as complete.
func (f *Flow) Finish() {
	close(f.done)
}

func (f *Flow) MarshalJSON() ([]byte, error) {
	j := make(map[string]any)
	j["id"] = f.ID
	j["request"] = f.Request
	j["response"] = f.Response
	return json.Marshal(j)
}
