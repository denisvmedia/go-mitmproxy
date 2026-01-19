package proxy

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"

	uuid "github.com/satori/go.uuid"
)

// flow http request.
type Request struct {
	Method string
	URL    *url.URL
	Proto  string
	Header http.Header
	Body   []byte

	raw *http.Request
}

func newRequest(req *http.Request) *Request {
	return &Request{
		Method: req.Method,
		URL:    req.URL,
		Proto:  req.Proto,
		Header: req.Header,
		raw:    req,
	}
}

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

// flow http response.
type Response struct {
	StatusCode int         `json:"statusCode"`
	Header     http.Header `json:"header"`
	Body       []byte      `json:"-"`
	BodyReader io.Reader

	close bool // connection close
}

// flow.
type Flow struct {
	ID          uuid.UUID
	ConnContext *ConnContext
	Request     *Request
	Response    *Response

	// https://docs.mitmproxy.org/stable/overview-features/#streaming
	// If true, Request.Body and Response.Body are not buffered, and will not enter subsequent Addon.Request and Addon.Response
	Stream            bool
	UseSeparateClient bool // use separate http client to send http request
	done              chan struct{}
}

func newFlow() *Flow {
	return &Flow{
		ID:   uuid.NewV4(),
		done: make(chan struct{}),
	}
}

func (f *Flow) Done() <-chan struct{} {
	return f.done
}

func (f *Flow) finish() {
	close(f.done)
}

func (f *Flow) MarshalJSON() ([]byte, error) {
	j := make(map[string]any)
	j["id"] = f.ID
	j["request"] = f.Request
	j["response"] = f.Response
	return json.Marshal(j)
}
