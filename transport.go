package oidclogout

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"golang.org/x/net/http/httpguts"
)

func init() { caddy.RegisterModule(SessionTransport{}) }

// SessionTransport delegates HTTP traffic to Caddy's standard transport and
// registers upgraded streams with the authenticated session. Configure it on
// each reverse_proxy protected by the oidc_session handler.
//
// Embedding HTTPTransport preserves Caddy's TLS, H2C, proxy protocol, request
// header, and active health check interfaces as well as its provisioning and
// cleanup lifecycle. Its configuration is nested under the "http" JSON key.
type SessionTransport struct {
	reverseproxy.HTTPTransport `json:"http,omitempty"`
}

func (SessionTransport) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.transport.oidc_session",
		New: func() caddy.Module { return new(SessionTransport) },
	}
}

// UnmarshalCaddyfile accepts the following syntax:
//
//	transport oidc_session {
//	    http {
//	        # standard HTTP transport options, including upstream TLS
//	    }
//	}
func (t *SessionTransport) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		seenHTTP := false
		for d.NextBlock(0) {
			if d.Val() != "http" {
				return d.Errf("unknown oidc_session transport option %q; use an http block for HTTP transport options", d.Val())
			}
			if seenHTTP {
				return d.Err("duplicate http transport block")
			}
			if d.CountRemainingArgs() != 0 {
				return d.ArgErr()
			}
			seenHTTP = true
			if err := t.HTTPTransport.UnmarshalCaddyfile(d.NewFromNextSegment()); err != nil {
				return err
			}
		}
	}
	return nil
}

// RoundTrip tracks the upgraded response body, not a pooled HTTP connection or
// the lifetime of the middleware call. A stream can outlive its request handler
// when Caddy detaches upgraded connections.
func (t *SessionTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	binding, hasBinding := bindingFromContext(r.Context())
	if websocketUpgradeRequest(r) && !hasBinding {
		return nil, errors.New("oidc_session transport: WebSocket request has no authenticated session; configure oidc_session before reverse_proxy")
	}

	res, err := t.HTTPTransport.RoundTrip(r)
	if err != nil || res.StatusCode != http.StatusSwitchingProtocols {
		return res, err
	}
	if !hasBinding {
		res.Body.Close()
		return nil, errors.New("oidc_session transport: refusing an upgrade without an authenticated session")
	}
	stream, ok := res.Body.(io.ReadWriteCloser)
	if !ok {
		res.Body.Close()
		return nil, errors.New("oidc_session transport: upgraded response is not a bidirectional stream")
	}

	wrapped, tracked := wrapSessionStream(stream)
	unregister, err := binding.register(tracked)
	if err != nil {
		tracked.Close()
		return nil, fmt.Errorf("oidc_session transport: session no longer valid: %w", err)
	}
	tracked.setUnregister(unregister)
	res.Body = wrapped
	return res, nil
}

func websocketUpgradeRequest(r *http.Request) bool {
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") &&
		httpguts.HeaderValuesContainsToken(r.Header.Values("Connection"), "upgrade")
}

// sessionStream owns cleanup even if logout closes the stream while its
// registration is still returning. Each stream and registration is closed once.
type sessionStream struct {
	io.ReadWriteCloser
	closeOnce  sync.Once
	closeErr   error
	mu         sync.Mutex
	closed     bool
	unregister func()
}

func (s *sessionStream) setUnregister(unregister func()) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		unregister()
		return
	}
	s.unregister = unregister
	s.mu.Unlock()
}

func (s *sessionStream) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		unregister := s.unregister
		s.unregister = nil
		s.mu.Unlock()
		if unregister != nil {
			unregister()
		}
		s.closeErr = s.ReadWriteCloser.Close()
	})
	return s.closeErr
}

type streamCloseWriter interface{ CloseWrite() error }
type streamCloseReader interface{ CloseRead() error }

type sessionWriteCloser struct {
	*sessionStream
	writer streamCloseWriter
}

func (s sessionWriteCloser) CloseWrite() error { return s.writer.CloseWrite() }

type sessionReadCloser struct {
	*sessionStream
	reader streamCloseReader
}

func (s sessionReadCloser) CloseRead() error { return s.reader.CloseRead() }

type sessionHalfCloser struct {
	*sessionStream
	writer streamCloseWriter
	reader streamCloseReader
}

func (s sessionHalfCloser) CloseWrite() error { return s.writer.CloseWrite() }
func (s sessionHalfCloser) CloseRead() error  { return s.reader.CloseRead() }

func wrapSessionStream(stream io.ReadWriteCloser) (io.ReadWriteCloser, *sessionStream) {
	tracked := &sessionStream{ReadWriteCloser: stream}
	w, hasW := stream.(streamCloseWriter)
	r, hasR := stream.(streamCloseReader)
	switch {
	case hasW && hasR:
		return sessionHalfCloser{sessionStream: tracked, writer: w, reader: r}, tracked
	case hasW:
		return sessionWriteCloser{sessionStream: tracked, writer: w}, tracked
	case hasR:
		return sessionReadCloser{sessionStream: tracked, reader: r}, tracked
	default:
		return tracked, tracked
	}
}

var (
	_ caddy.Module                           = (*SessionTransport)(nil)
	_ caddy.Provisioner                      = (*SessionTransport)(nil)
	_ caddy.CleanerUpper                     = (*SessionTransport)(nil)
	_ caddyfile.Unmarshaler                  = (*SessionTransport)(nil)
	_ http.RoundTripper                      = (*SessionTransport)(nil)
	_ reverseproxy.TLSTransport              = (*SessionTransport)(nil)
	_ reverseproxy.H2CTransport              = (*SessionTransport)(nil)
	_ reverseproxy.ProxyProtocolTransport    = (*SessionTransport)(nil)
	_ reverseproxy.RequestHeaderOpsTransport = (*SessionTransport)(nil)
)
