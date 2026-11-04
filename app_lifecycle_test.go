package oidclogout

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	oidc "github.com/relvacode/caddy-oidc"
	"github.com/relvacode/caddy-oidc/session"
)

func lifecycleApp(path string) *App {
	return &App{StateFile: path, Providers: map[string]*Provider{
		"company": {Issuer: "https://id.example/realms/company", ClientID: "caddy"},
	}}
}

// Caddy provisions a replacement configuration before cleaning up its old one.
// Both configurations must share revocations and existing stream registrations.
func TestAppOverlappingReloadAndRestartPreserveRevocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "sessions.db")
	old := lifecycleApp(path)
	if err := old.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = old.Cleanup() })
	id := testIdentity("reload-session")
	closer := newRegistryTestCloser()
	unregister, err := old.registry.register(id, closer)
	if err != nil {
		t.Fatal(err)
	}
	defer unregister()

	next := lifecycleApp(path)
	if err := next.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = next.Cleanup() })
	if next.registry != old.registry {
		t.Fatal("reload did not share the existing registry")
	}
	if err := old.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := old.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if closer.isClosed() {
		t.Fatal("old configuration cleanup closed a stream owned by the shared registry")
	}
	if err := next.registry.check(id); err != nil {
		t.Fatalf("old cleanup destroyed the replacement registry: %v", err)
	}
	event := logoutEvent{Issuer: id.Issuer, SID: id.SID, Subject: id.Subject, JTI: "reload-logout", IssuedAt: time.Now()}
	if err := next.registry.revoke(id.Issuer, id.ClientID, event, revocationRetention, time.Minute); err != nil {
		t.Fatal(err)
	}
	if !closer.isClosed() {
		t.Fatal("new configuration could not close old configuration's stream")
	}
	if err := next.Stop(); err != nil {
		t.Fatal(err)
	}

	restarted := lifecycleApp(path)
	if err := restarted.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Cleanup() })
	if restarted.registry == next.registry {
		t.Fatal("restart unexpectedly reused the closed registry")
	}
	if err := restarted.registry.check(id); !errors.Is(err, errRevoked) {
		t.Fatalf("restart resurrected old credentials: %v", err)
	}
	if _, err := restarted.registry.register(id, newRegistryTestCloser()); !errors.Is(err, errRevoked) {
		t.Fatalf("restart allowed a revoked reconnect: %v", err)
	}
}

func TestAppRejectsUnsafeProviderAndLifetimeConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*App)
	}{
		{"HTTP issuer without opt-in", func(a *App) { a.Providers["company"].Issuer = "http://id.example/realm" }},
		{"relative issuer", func(a *App) { a.Providers["company"].Issuer = "/realm" }},
		{"issuer credentials", func(a *App) { a.Providers["company"].Issuer = "https://user:password@id.example/realm" }},
		{"issuer query", func(a *App) { a.Providers["company"].Issuer += "?other=realm" }},
		{"issuer fragment", func(a *App) { a.Providers["company"].Issuer += "#realm" }},
		{"empty client", func(a *App) { a.Providers["company"].ClientID = " " }},
		{"nil provider", func(a *App) { a.Providers["company"] = nil }},
		{"no providers", func(a *App) { a.Providers = nil }},
		{"unbounded session lifetime", func(a *App) { a.MaxSessionAge = caddy.Duration(31 * 24 * time.Hour) }},
		{"negative session lifetime", func(a *App) { a.MaxSessionAge = -1 }},
		{"excessive clock skew", func(a *App) { a.ClockSkew = caddy.Duration(6 * time.Minute) }},
		{"negative clock skew", func(a *App) { a.ClockSkew = -1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := lifecycleApp(filepath.Join(t.TempDir(), "sessions.db"))
			tc.change(a)
			if err := a.Provision(caddy.Context{}); err == nil {
				_ = a.Cleanup()
				t.Fatal("accepted unsafe configuration")
			}
		})
	}
	a := lifecycleApp(filepath.Join(t.TempDir(), "sessions.db"))
	a.Providers["company"].Issuer = "http://localhost:8080/realm"
	a.Providers["company"].AllowInsecureIssuer = true
	if err := a.Provision(caddy.Context{}); err != nil {
		t.Fatalf("explicit development HTTP issuer rejected: %v", err)
	}
	defer a.Cleanup()
}

func identityClaims() map[string]any {
	now := time.Now().Truncate(time.Second)
	return map[string]any{"iss": "https://id.example/realms/company", "aud": "caddy", "sub": "user", "sid": "session", "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix()}
}

func identityRequest(claims map[string]any, typed bool) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://apps.example/app1", nil)
	if typed {
		raw, _ := json.Marshal(claims)
		s := &session.Session{UID: "user", Claims: raw}
		return r.WithContext(context.WithValue(r.Context(), oidc.SessionCtxKey, s))
	}
	repl := caddy.NewReplacer()
	repl.Set("http.auth.user.anonymous", false)
	repl.Set("http.auth.result", "allow")
	for key, value := range claims {
		switch v := value.(type) {
		case string:
			repl.Set("http.auth.user.claim."+key, v)
		default:
			encoded, _ := json.Marshal(v)
			repl.Set("http.auth.user.claim."+key, string(encoded))
		}
	}
	return r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl))
}

func TestAuthenticatedIdentityEnforcesProviderBindingAndDeadlines(t *testing.T) {
	a := &App{MaxSessionAge: caddy.Duration(24 * time.Hour), ClockSkew: caddy.Duration(30 * time.Second)}
	p := &Provider{Issuer: "https://id.example/realms/company", ClientID: "caddy"}
	for _, typed := range []bool{false, true} {
		for _, tc := range []struct {
			name   string
			change func(map[string]any)
		}{
			{"wrong realm", func(c map[string]any) { c["iss"] = "https://id.example/realms/other" }},
			{"wrong client", func(c map[string]any) { c["aud"] = "different-client" }},
			{"missing audience", func(c map[string]any) { delete(c, "aud") }},
			{"missing session", func(c map[string]any) { delete(c, "sid") }},
			{"missing subject", func(c map[string]any) { delete(c, "sub") }},
			{"expired", func(c map[string]any) { c["exp"] = time.Now().Add(-time.Second).Unix() }},
			{"future issuance", func(c map[string]any) { c["iat"] = time.Now().Add(time.Hour).Unix() }},
			{"too old", func(c map[string]any) { c["iat"] = time.Now().Add(-25 * time.Hour).Unix() }},
			{"non-numeric issuance", func(c map[string]any) { c["iat"] = "yesterday" }},
			{"null issuance", func(c map[string]any) { c["iat"] = nil }},
		} {
			t.Run(tc.name+map[bool]string{false: "/placeholders", true: "/typed"}[typed], func(t *testing.T) {
				claims := identityClaims()
				tc.change(claims)
				if _, _, err := authenticatedIdentity(identityRequest(claims, typed), p, a); err == nil {
					t.Fatal("accepted invalid identity")
				}
			})
		}
		if _, _, err := authenticatedIdentity(identityRequest(identityClaims(), typed), p, a); err != nil {
			t.Fatalf("valid identity rejected (typed=%v): %v", typed, err)
		}
	}
	claims := identityClaims()
	claims["aud"] = []string{"other", "caddy"}
	if _, _, err := authenticatedIdentity(identityRequest(claims, true), p, a); err != nil {
		t.Fatalf("typed multiple audience rejected: %v", err)
	}
	// Stock caddy-oidc flattens array placeholders; never guess the audience from
	// that ambiguous string. The typed-context patch supports multiple audiences.
	claims["aud"] = "other,caddy"
	if _, _, err := authenticatedIdentity(identityRequest(claims, false), p, a); err == nil {
		t.Fatal("ambiguous stock audience placeholder accepted")
	}

	r := httptest.NewRequest(http.MethodGet, "https://apps.example/app1", nil)
	r.Header.Set("X-Auth-Issuer", p.Issuer)
	r.Header.Set("X-Auth-Subject", "user")
	r.Header.Set("X-Auth-Sid", "session")
	if _, _, err := authenticatedIdentity(r, p, a); err == nil {
		t.Fatal("client-supplied identity headers were trusted")
	}
	r = identityRequest(identityClaims(), true)
	s := r.Context().Value(oidc.SessionCtxKey).(*session.Session)
	s.ExpiresAt = time.Now().Add(20 * time.Second).Unix()
	id, _, err := authenticatedIdentity(r, p, a)
	if err != nil {
		t.Fatal(err)
	}
	if !id.ExpiresAt.Equal(s.Expires()) {
		t.Fatal("stream lifetime was not capped to local session/access-token expiry")
	}
}

func TestLogoutCaddyfileRejectsMisconfiguredProviders(t *testing.T) {
	for _, input := range []string{
		"oidc_logout extra {\n provider company {\n issuer https://id.example\n client_id caddy\n}\n}",
		"oidc_logout {\n provider company {\n issuer https://id.example\n client_id caddy\n}\n provider company {\n issuer https://other.example\n client_id caddy\n}\n}",
		"oidc_logout {\n max_session_age forever\n}",
		"oidc_logout {\n provider company {\n unknown true\n}\n}",
		"oidc_logout {\n provider company {\n allow_insecure_issuer true\n}\n}",
	} {
		if _, err := parseGlobal(caddyfile.NewTestDispenser(input), nil); err == nil {
			t.Errorf("accepted invalid Caddyfile: %s", input)
		}
	}
}
