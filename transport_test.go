package oidclogout

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	_ "github.com/caddyserver/caddy/v2/modules/filestorage"
	"github.com/gorilla/websocket"
)

type transportTestStream struct {
	bytes.Buffer
	closes atomic.Int32
}

var errTransportTestClose = errors.New("test stream close result")

func (s *transportTestStream) Close() error {
	s.closes.Add(1)
	return errTransportTestClose
}

type transportTestWriteCloser struct {
	*transportTestStream
	writes atomic.Int32
}

func (s *transportTestWriteCloser) CloseWrite() error { s.writes.Add(1); return nil }

type transportTestReadCloser struct {
	*transportTestStream
	reads atomic.Int32
}

func (s *transportTestReadCloser) CloseRead() error { s.reads.Add(1); return nil }

type transportTestHalfCloser struct {
	*transportTestStream
	writes atomic.Int32
	reads  atomic.Int32
}

func (s *transportTestHalfCloser) CloseWrite() error { s.writes.Add(1); return nil }
func (s *transportTestHalfCloser) CloseRead() error  { s.reads.Add(1); return nil }

func TestSessionStreamPreservesHalfCloseCapabilities(t *testing.T) {
	for _, tc := range []struct {
		name        string
		stream      io.ReadWriteCloser
		read, write bool
	}{
		{"neither", &transportTestStream{}, false, false},
		{"write", &transportTestWriteCloser{transportTestStream: &transportTestStream{}}, false, true},
		{"read", &transportTestReadCloser{transportTestStream: &transportTestStream{}}, true, false},
		{"both", &transportTestHalfCloser{transportTestStream: &transportTestStream{}}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wrapped, tracked := wrapSessionStream(tc.stream)
			var unregistered atomic.Int32
			tracked.setUnregister(func() { unregistered.Add(1) })
			w, hasW := wrapped.(streamCloseWriter)
			r, hasR := wrapped.(streamCloseReader)
			if hasW != tc.write || hasR != tc.read {
				t.Fatalf("capabilities read=%v write=%v; want read=%v write=%v", hasR, hasW, tc.read, tc.write)
			}
			if hasW {
				if err := w.CloseWrite(); err != nil {
					t.Fatal(err)
				}
			}
			if hasR {
				if err := r.CloseRead(); err != nil {
					t.Fatal(err)
				}
			}
			if unregistered.Load() != 0 {
				t.Fatal("half-close unregistered a still-active stream")
			}
			if _, err := wrapped.Write([]byte("still tracked")); err != nil {
				t.Fatal(err)
			}
			data := make([]byte, len("still tracked"))
			if _, err := io.ReadFull(wrapped, data); err != nil {
				t.Fatal(err)
			}
			if string(data) != "still tracked" {
				t.Fatalf("stream data = %q", data)
			}
			if err := wrapped.Close(); !errors.Is(err, errTransportTestClose) {
				t.Fatalf("close error: %v", err)
			}
			if unregistered.Load() != 1 {
				t.Fatal("stream close did not unregister")
			}
		})
	}
}

func TestSessionStreamCloseRegistrationRace(t *testing.T) {
	// Logout can close a registered stream before register returns its cleanup
	// function. Run both orderings and concurrent callers under the race detector.
	for _, closeFirst := range []bool{false, true} {
		stream := &transportTestStream{}
		_, tracked := wrapSessionStream(stream)
		var unregistered atomic.Int32
		unregister := func() { unregistered.Add(1) }
		if closeFirst {
			tracked.Close()
			tracked.setUnregister(unregister)
		} else {
			tracked.setUnregister(unregister)
			tracked.Close()
		}
		tracked.Close()
		if stream.closes.Load() != 1 || unregistered.Load() != 1 {
			t.Fatalf("closeFirst=%v closes=%d unregisters=%d", closeFirst, stream.closes.Load(), unregistered.Load())
		}
	}
	for range 100 {
		stream := &transportTestStream{}
		_, tracked := wrapSessionStream(stream)
		var unregistered atomic.Int32
		var wg sync.WaitGroup
		wg.Add(9)
		go func() {
			defer wg.Done()
			tracked.setUnregister(func() { unregistered.Add(1) })
		}()
		for range 8 {
			go func() {
				defer wg.Done()
				if err := tracked.Close(); !errors.Is(err, errTransportTestClose) {
					t.Errorf("close error: %v", err)
				}
			}()
		}
		wg.Wait()
		if stream.closes.Load() != 1 || unregistered.Load() != 1 {
			t.Fatalf("closes=%d unregisters=%d", stream.closes.Load(), unregistered.Load())
		}
	}
}

func TestSessionTransportRejectsMissingSessionBeforeUpstream(t *testing.T) {
	var called atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	tr := &SessionTransport{HTTPTransport: reverseproxy.HTTPTransport{Transport: &http.Transport{}}}
	defer tr.Cleanup()
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Upgrade", "WebSocket")
	req.Header.Set("Connection", "keep-alive, Upgrade")
	res, err := tr.RoundTrip(req)
	if err == nil || res != nil {
		t.Fatalf("got response %v, error %v", res, err)
	}
	if called.Load() {
		t.Fatal("unauthenticated websocket reached upstream")
	}

	// Active health checks and ordinary requests have no stream to register.
	req.Header.Del("Upgrade")
	req.Header.Del("Connection")
	res, err = tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if !called.Load() || res.StatusCode != http.StatusNoContent {
		t.Fatal("ordinary HTTP delegation failed")
	}
}

func TestSessionTransportCaddyfileAndTLSInterfaces(t *testing.T) {
	var tr SessionTransport
	err := tr.UnmarshalCaddyfile(caddyfile.NewTestDispenser(`oidc_session {
		http {
			tls
			tls_server_name backend.example.com
			dial_timeout 7s
			versions 1.1 2
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if !tr.TLSEnabled() || tr.TLS.ServerName != "backend.example.com" || time.Duration(tr.DialTimeout) != 7*time.Second {
		t.Fatalf("standard HTTP transport configuration was lost: %+v", tr.HTTPTransport)
	}
	if tr.RequestHeaderOps() == nil {
		t.Fatal("TLS upstream Host behavior was lost")
	}
	u := &url.URL{Scheme: "http"}
	tr.OverrideHealthCheckScheme(u, "443")
	if u.Scheme != "https" {
		t.Fatal("TLS health check behavior was lost")
	}
	data, err := json.Marshal(&tr)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		HTTP struct {
			TLS struct {
				ServerName string `json:"server_name"`
			} `json:"tls"`
		} `json:"http"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.HTTP.TLS.ServerName != "backend.example.com" {
		t.Fatalf("nested HTTP configuration missing: %s", data)
	}
	for _, input := range []string{
		"oidc_session extra",
		"oidc_session {\n tls\n}",
		"oidc_session {\n http extra\n}",
		"oidc_session {\n http {}\n http {}\n}",
		"oidc_session {\n http {\n unknown_option\n }\n}",
	} {
		var invalid SessionTransport
		if err := invalid.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
			t.Errorf("accepted invalid configuration %q", input)
		}
	}
}

// This middleware exists only in the test binary. It supplies synthetic
// authenticated identities so the test can exercise the actual Caddy transport
// and durable registry independently of the OIDC login integration tests.
var transportTestRegistries sync.Map

type transportTestSessionHandler struct {
	Registry string `json:"registry"`
}

func init() { caddy.RegisterModule(transportTestSessionHandler{}) }

func (transportTestSessionHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.test_logout_transport_session",
		New: func() caddy.Module { return new(transportTestSessionHandler) },
	}
}

func (h *transportTestSessionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	value, ok := transportTestRegistries.Load(h.Registry)
	if !ok {
		return errors.New("test registry missing")
	}
	reg := value.(*registry)
	sid := r.URL.Query().Get("sid")
	id := identity{
		Issuer: "https://issuer.example/realms/test", ClientID: "proxy", Subject: sid, SID: sid,
		IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := reg.check(id); err != nil {
		return caddyhttp.Error(http.StatusUnauthorized, err)
	}
	binding := &sessionBinding{registry: reg, identity: id}
	return next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), bindingKey{}, binding)))
}

func TestSessionTransportRealCaddySelectiveLogout(t *testing.T) {
	reg, err := openRegistry(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Destruct()
	registryID := t.Name()
	transportTestRegistries.Store(registryID, reg)
	defer transportTestRegistries.Delete(registryID)
	closed := make(chan string, 2)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		defer func() { closed <- r.URL.Query().Get("sid") }()
		for {
			kind, data, err := ws.ReadMessage()
			if err != nil {
				return
			}
			if err := ws.WriteMessage(kind, data); err != nil {
				return
			}
		}
	}))
	defer backend.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	config := fmt.Sprintf(`{
		"admin":{"disabled":true,"config":{"persist":false}},
		"storage":{"module":"file_system","root":%q},
		"apps":{"http":{"servers":{"test":{"listen":[%q],"routes":[{"handle":[
			{"handler":"test_logout_transport_session","registry":%q},
			{"handler":"reverse_proxy","upstreams":[{"dial":%q}],"transport":{"protocol":"oidc_session"}}
		]}]}}}}}`, t.TempDir(), address, registryID, strings.TrimPrefix(backend.URL, "http://"))
	if err := caddy.Load([]byte(config), true); err != nil {
		t.Fatal(err)
	}
	defer caddy.Stop()
	connect := func(sid string) *websocket.Conn {
		t.Helper()
		ws, _, err := websocket.DefaultDialer.Dial("ws://"+address+"/?sid="+sid, nil)
		if err != nil {
			t.Fatal(err)
		}
		return ws
	}
	first, second := connect("first"), connect("second")
	defer first.Close()
	defer second.Close()
	echo := func(ws *websocket.Conn) {
		t.Helper()
		ws.SetReadDeadline(time.Now().Add(3 * time.Second))
		if err := ws.WriteMessage(websocket.TextMessage, []byte("still connected")); err != nil {
			t.Fatal(err)
		}
		_, data, err := ws.ReadMessage()
		if err != nil || string(data) != "still connected" {
			t.Fatalf("echo data %q, error %v", data, err)
		}
	}
	echo(first)
	echo(second)
	if err := reg.revoke("https://issuer.example/realms/test", "proxy", logoutEvent{SID: "first", JTI: "logout-first", IssuedAt: time.Now()}, time.Hour, time.Minute); err != nil {
		t.Fatal(err)
	}
	first.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := first.ReadMessage(); err == nil {
		t.Fatal("logged-out client connection stayed open")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("client timed out instead of disconnecting")
	}
	select {
	case sid := <-closed:
		if sid != "first" {
			t.Fatalf("wrong backend connection closed: %q", sid)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("logged-out backend connection stayed open")
	}
	echo(second)
	ws, response, err := websocket.DefaultDialer.Dial("ws://"+address+"/?sid=first", nil)
	if ws != nil {
		ws.Close()
	}
	if err == nil || response == nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked session reconnected: response=%v error=%v", response, err)
	}
	response.Body.Close()
	reg.mu.Lock()
	remaining := len(reg.streams)
	reg.mu.Unlock()
	if remaining != 1 {
		t.Fatalf("registered streams=%d, expected unaffected connection only", remaining)
	}
}
