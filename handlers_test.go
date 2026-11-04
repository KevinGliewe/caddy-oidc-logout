package oidclogout

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	oidc "github.com/relvacode/caddy-oidc"
	"github.com/relvacode/caddy-oidc/session"
)

func testLogoutHandlers(t *testing.T) (*logoutIssuerFixture, *App, *Provider) {
	t.Helper()
	f := newLogoutIssuerFixture(t)
	p := &Provider{Issuer: f.server.URL, ClientID: "caddy", verifier: newLogoutVerifier(f.server.URL, "caddy", 5*time.Minute, 30*time.Second)}
	a := &App{registry: testRegistry(t), Providers: map[string]*Provider{"company": p}, MaxSessionAge: caddy.Duration(24 * time.Hour), LogoutMaxAge: caddy.Duration(5 * time.Minute), ClockSkew: caddy.Duration(30 * time.Second)}
	return f, a, p
}

func serveTestHandler(t *testing.T, h caddyhttp.MiddlewareHandler, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	err := h.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		t.Error("logout endpoint called downstream handler")
		return nil
	}))
	if err != nil {
		var status caddyhttp.HandlerError
		if errors.As(err, &status) {
			http.Error(w, status.Error(), status.StatusCode)
		} else {
			t.Fatalf("untyped HTTP error: %v", err)
		}
	}
	return w
}

func TestBackchannelHandlerValidatesTransportAndRejectsInvalidLogout(t *testing.T) {
	f, a, p := testLogoutHandlers(t)
	h := &BackchannelHandler{Provider: "company", app: a, provider: p}
	tests := []struct {
		name, method, contentType string
		build                     func(string) (string, string)
		alter                     func(map[string]any)
		status                    int
	}{
		{"GET", http.MethodGet, "", func(raw string) (string, string) { return "/backchannel?logout_token=" + url.QueryEscape(raw), "" }, nil, http.StatusMethodNotAllowed},
		{"wrong media type", http.MethodPost, "application/json", func(raw string) (string, string) { return "/backchannel", `{"logout_token":"` + raw + `"}` }, nil, http.StatusUnsupportedMediaType},
		{"missing media type", http.MethodPost, "", func(raw string) (string, string) { return "/backchannel", url.Values{"logout_token": {raw}}.Encode() }, nil, http.StatusUnsupportedMediaType},
		{"query only", http.MethodPost, "application/x-www-form-urlencoded", func(raw string) (string, string) { return "/backchannel?logout_token=" + url.QueryEscape(raw), "" }, nil, http.StatusBadRequest},
		{"query and body", http.MethodPost, "application/x-www-form-urlencoded", func(raw string) (string, string) {
			return "/backchannel?logout_token=" + url.QueryEscape(raw), url.Values{"logout_token": {raw}}.Encode()
		}, nil, http.StatusBadRequest},
		{"duplicate body values", http.MethodPost, "application/x-www-form-urlencoded", func(raw string) (string, string) {
			return "/backchannel", url.Values{"logout_token": {raw, raw}}.Encode()
		}, nil, http.StatusBadRequest},
		{"empty body value", http.MethodPost, "application/x-www-form-urlencoded", func(string) (string, string) { return "/backchannel", "logout_token=" }, nil, http.StatusBadRequest},
		{"malformed form", http.MethodPost, "application/x-www-form-urlencoded", func(string) (string, string) { return "/backchannel", "logout_token=%invalid" }, nil, http.StatusBadRequest},
		{"oversized body", http.MethodPost, "application/x-www-form-urlencoded", func(string) (string, string) { return "/backchannel", "logout_token=" + strings.Repeat("x", 64<<10) }, nil, http.StatusBadRequest},
		{"invalid token", http.MethodPost, "application/x-www-form-urlencoded", func(string) (string, string) { return "/backchannel", "logout_token=not-a-jwt" }, nil, http.StatusBadRequest},
		{"wrong audience", http.MethodPost, "application/x-www-form-urlencoded", nil, func(c map[string]any) { c["aud"] = "other-client" }, http.StatusBadRequest},
		{"wrong realm", http.MethodPost, "application/x-www-form-urlencoded", nil, func(c map[string]any) { c["iss"] = "https://id.example/realms/another" }, http.StatusBadRequest},
		{"expired token", http.MethodPost, "application/x-www-form-urlencoded", nil, func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() }, http.StatusBadRequest},
		{"valid", http.MethodPost, "application/x-www-form-urlencoded", nil, nil, http.StatusOK},
		{"valid with content type charset", http.MethodPost, "application/x-www-form-urlencoded; charset=UTF-8", nil, nil, http.StatusOK},
		{"unknown query and form fields", http.MethodPost, "application/x-www-form-urlencoded", func(raw string) (string, string) {
			return "/backchannel?trace=example", url.Values{"logout_token": {raw}, "unknown": {"ignored"}}.Encode()
		}, nil, http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id := testIdentity(tc.name)
			id.Issuer = p.Issuer
			closer := newRegistryTestCloser()
			unregister, err := a.registry.register(id, closer)
			if err != nil {
				t.Fatal(err)
			}
			defer unregister()
			claims := f.claims(time.Now())
			claims["sid"] = id.SID
			claims["sub"] = id.Subject
			claims["jti"] = tc.name
			if tc.alter != nil {
				tc.alter(claims)
			}
			raw := signLogoutClaims(t, f.key, "key-1", claims)
			path, body := "/backchannel", url.Values{"logout_token": {raw}}.Encode()
			if tc.build != nil {
				path, body = tc.build(raw)
			}
			r := httptest.NewRequest(tc.method, path, strings.NewReader(body))
			r.Header.Set("Content-Type", tc.contentType)
			w := serveTestHandler(t, h, r)
			if w.Code != tc.status {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.status, w.Body.String())
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("logout response is cacheable")
			}
			if tc.status == http.StatusOK {
				if !closer.isClosed() {
					t.Fatal("valid logout did not disconnect session")
				}
				if err := a.registry.check(id); !errors.Is(err, errRevoked) {
					t.Fatalf("valid logout did not revoke cookie: %v", err)
				}
				// A retry is a successful, idempotent logout response.
				retry := httptest.NewRequest(http.MethodPost, "/backchannel", strings.NewReader(url.Values{"logout_token": {raw}}.Encode()))
				retry.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				if w := serveTestHandler(t, h, retry); w.Code != http.StatusOK {
					t.Fatalf("duplicate status=%d body=%s", w.Code, w.Body.String())
				}
			} else {
				if closer.isClosed() {
					t.Fatal("invalid logout disconnected session")
				}
				if err := a.registry.check(id); err != nil {
					t.Fatalf("invalid logout changed revocation state: %v", err)
				}
			}
		})
	}
}

func authenticatedSignoutRequest(t *testing.T, p *Provider, id identity) *http.Request {
	t.Helper()
	claims, err := json.Marshal(map[string]any{"iss": p.Issuer, "aud": p.ClientID, "sub": id.Subject, "sid": id.SID, "iat": id.IssuedAt.Unix(), "exp": id.ExpiresAt.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	sess := &session.Session{UID: id.Subject, Claims: claims, ExpiresAt: id.ExpiresAt.Unix()}
	r := httptest.NewRequest(http.MethodPost, "https://app.example/logout", nil)
	r.Header.Set("Origin", "https://app.example")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	return r.WithContext(context.WithValue(r.Context(), oidc.SessionCtxKey, sess))
}

func TestSignoutRequiresAuthenticatedSameOriginPOST(t *testing.T) {
	_, a, p := testLogoutHandlers(t)
	h := &SignoutHandler{Provider: "company", CookieName: "caddy", CookiePath: "/", Redirect: "/signed-out", app: a, provider: p}
	tests := []struct {
		name   string
		alter  func(*http.Request) *http.Request
		status int
	}{
		{"GET", func(r *http.Request) *http.Request { r.Method = http.MethodGet; return r }, http.StatusMethodNotAllowed},
		{"missing origin", func(r *http.Request) *http.Request { r.Header.Del("Origin"); return r }, http.StatusForbidden},
		{"cross origin", func(r *http.Request) *http.Request { r.Header.Set("Origin", "https://attacker.example"); return r }, http.StatusForbidden},
		{"null origin", func(r *http.Request) *http.Request { r.Header.Set("Origin", "null"); return r }, http.StatusForbidden},
		{"cross site fetch", func(r *http.Request) *http.Request { r.Header.Set("Sec-Fetch-Site", "cross-site"); return r }, http.StatusForbidden},
		{"same site fetch", func(r *http.Request) *http.Request { r.Header.Set("Sec-Fetch-Site", "same-site"); return r }, http.StatusForbidden},
		{"client headers cannot authenticate", func(r *http.Request) *http.Request {
			r.Header.Set("X-Auth-Subject", "user")
			r.Header.Set("X-Auth-Session", "session")
			return r.WithContext(context.Background())
		}, http.StatusUnauthorized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id := testIdentity(tc.name)
			id.Issuer = p.Issuer
			closer := newRegistryTestCloser()
			unregister, err := a.registry.register(id, closer)
			if err != nil {
				t.Fatal(err)
			}
			defer unregister()
			r := tc.alter(authenticatedSignoutRequest(t, p, id))
			w := serveTestHandler(t, h, r)
			if w.Code != tc.status {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.status, w.Body.String())
			}
			if closer.isClosed() {
				t.Fatal("invalid browser logout disconnected session")
			}
			if err := a.registry.check(id); err != nil {
				t.Fatalf("invalid browser logout revoked session: %v", err)
			}
		})
	}
}

func TestSignoutRevokesBeforeProviderRedirect(t *testing.T) {
	f, a, p := testLogoutHandlers(t)
	h := &SignoutHandler{Provider: "company", CookieName: "session-cookie", CookiePath: "/", CookieDomain: "app.example", Redirect: "/signed-out", app: a, provider: p}
	id := testIdentity("browser-session")
	id.Issuer = p.Issuer
	closer := newRegistryTestCloser()
	unregister, err := a.registry.register(id, closer)
	if err != nil {
		t.Fatal(err)
	}
	defer unregister()
	w := serveTestHandler(t, h, authenticatedSignoutRequest(t, p, id))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !closer.isClosed() {
		t.Fatal("browser logout did not disconnect socket")
	}
	if err := a.registry.check(id); !errors.Is(err, errRevoked) {
		t.Fatalf("browser logout did not reject old cookie: %v", err)
	}
	location, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Scheme+"://"+location.Host+location.Path != f.server.URL+"/logout" {
		t.Fatalf("unexpected redirect %q", location)
	}
	if location.Query().Get("client_id") != p.ClientID || location.Query().Get("post_logout_redirect_uri") != "https://app.example/signed-out" {
		t.Fatalf("wrong provider logout query: %s", location.RawQuery)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "session-cookie" || cookies[0].MaxAge != -1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Domain != "app.example" {
		t.Fatalf("session cookie not cleared correctly: %+v", cookies)
	}
}

func TestSignoutProviderFailureStillRevokesAndCloses(t *testing.T) {
	f, a, p := testLogoutHandlers(t)
	f.failDiscovery.Store(true)
	h := &SignoutHandler{Provider: "company", CookieName: "caddy", CookiePath: "/", Redirect: "/", app: a, provider: p}
	id := testIdentity("browser-session")
	id.Issuer = p.Issuer
	closer := newRegistryTestCloser()
	unregister, err := a.registry.register(id, closer)
	if err != nil {
		t.Fatal(err)
	}
	defer unregister()
	w := serveTestHandler(t, h, authenticatedSignoutRequest(t, p, id))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !closer.isClosed() {
		t.Fatal("provider failure left local socket open")
	}
	if err := a.registry.check(id); !errors.Is(err, errRevoked) {
		t.Fatalf("provider failure left old cookie usable: %v", err)
	}
	if len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("provider failure did not clear browser cookie")
	}
}

func TestBackchannelPersistenceFailureDoesNotReportSuccess(t *testing.T) {
	f, a, p := testLogoutHandlers(t)
	// A closed DB simulates a storage failure while preserving the registry object.
	if err := a.registry.db.Close(); err != nil {
		t.Fatal(err)
	}
	raw := signLogoutClaims(t, f.key, "key-1", f.claims(time.Now()))
	r := httptest.NewRequest(http.MethodPost, "/backchannel", strings.NewReader(url.Values{"logout_token": {raw}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := serveTestHandler(t, &BackchannelHandler{Provider: "company", app: a, provider: p}, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("uncommitted logout status=%d body=%s", w.Code, w.Body.String())
	}
}
