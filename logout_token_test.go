package oidclogout

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
)

type logoutIssuerFixture struct {
	server         *httptest.Server
	key            *rsa.PrivateKey
	mu             sync.RWMutex
	publicKey      jose.JSONWebKey
	metadata       map[string]any
	discoveryCalls atomic.Int32
	keyCalls       atomic.Int32
	failDiscovery  atomic.Bool
}

func newLogoutIssuerFixture(t *testing.T) *logoutIssuerFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &logoutIssuerFixture{key: key, publicKey: jose.JSONWebKey{Key: &key.PublicKey, KeyID: "key-1", Algorithm: "RS256", Use: "sig"}}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			f.discoveryCalls.Add(1)
			if f.failDiscovery.Load() {
				http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
			f.mu.RLock()
			defer f.mu.RUnlock()
			_ = json.NewEncoder(w).Encode(f.metadata)
		case "/jwks":
			f.keyCalls.Add(1)
			f.mu.RLock()
			defer f.mu.RUnlock()
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{f.publicKey}})
		default:
			http.NotFound(w, r)
		}
	}))
	f.metadata = map[string]any{
		"issuer":                                f.server.URL,
		"jwks_uri":                              f.server.URL + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"end_session_endpoint":                  f.server.URL + "/logout",
	}
	t.Cleanup(f.server.Close)
	return f
}

func (f *logoutIssuerFixture) claims(now time.Time) map[string]any {
	return map[string]any{
		"iss": f.server.URL, "aud": "caddy", "iat": now.Unix(),
		"jti": "event-1", "sub": "user-1", "sid": "session-1",
		"events": map[string]any{backchannelLogoutEvent: map[string]any{}},
	}
}

func signLogoutClaims(t *testing.T, key *rsa.PrivateKey, kid string, claims any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return signLogoutPayload(t, key, kid, payload)
}

func signLogoutPayload(t *testing.T, key *rsa.PrivateKey, kid string, payload []byte) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("logout+jwt").WithHeader("kid", kid)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	object, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestLogoutTokenValidation(t *testing.T) {
	f := newLogoutIssuerFixture(t)
	now := time.Unix(1793780000, 0)
	v := newLogoutVerifier(f.server.URL, "caddy", 5*time.Minute, 30*time.Second)
	v.now = func() time.Time { return now }
	tests := []struct {
		name   string
		change func(map[string]any)
		accept bool
	}{
		{"valid without exp", func(map[string]any) {}, true},
		{"valid with exp", func(c map[string]any) { c["exp"] = now.Add(time.Minute).Unix() }, true},
		{"valid sid only", func(c map[string]any) { delete(c, "sub") }, true},
		{"valid subject only", func(c map[string]any) { delete(c, "sid") }, true},
		{"valid audience array", func(c map[string]any) { c["aud"] = []string{"other", "caddy"} }, true},
		{"valid nbf within skew", func(c map[string]any) { c["nbf"] = now.Add(10 * time.Second).Unix() }, true},
		{"valid fractional iat", func(c map[string]any) { c["iat"] = float64(now.Unix()) + 0.5 }, true},
		{"wrong issuer", func(c map[string]any) { c["iss"] = "https://another.example/realms/company" }, false},
		{"wrong audience", func(c map[string]any) { c["aud"] = "another-client" }, false},
		{"missing audience", func(c map[string]any) { delete(c, "aud") }, false},
		{"null audience", func(c map[string]any) { c["aud"] = nil }, false},
		{"null audience array member", func(c map[string]any) { c["aud"] = []any{"caddy", nil} }, false},
		{"missing iat", func(c map[string]any) { delete(c, "iat") }, false},
		{"null iat", func(c map[string]any) { c["iat"] = nil }, false},
		{"string iat", func(c map[string]any) { c["iat"] = fmt.Sprint(now.Unix()) }, false},
		{"future iat", func(c map[string]any) { c["iat"] = now.Add(time.Minute).Unix() }, false},
		{"stale iat", func(c map[string]any) { c["iat"] = now.Add(-6 * time.Minute).Unix() }, false},
		{"missing jti", func(c map[string]any) { delete(c, "jti") }, false},
		{"empty jti", func(c map[string]any) { c["jti"] = "" }, false},
		{"null jti", func(c map[string]any) { c["jti"] = nil }, false},
		{"numeric jti", func(c map[string]any) { c["jti"] = 123 }, false},
		{"no session identity", func(c map[string]any) { delete(c, "sid"); delete(c, "sub") }, false},
		{"empty sid", func(c map[string]any) { c["sid"] = "" }, false},
		{"null sid", func(c map[string]any) { c["sid"] = nil }, false},
		{"numeric sid", func(c map[string]any) { c["sid"] = 123 }, false},
		{"null sub", func(c map[string]any) { c["sub"] = nil }, false},
		{"nonce", func(c map[string]any) { c["nonce"] = "login-nonce" }, false},
		{"empty nonce", func(c map[string]any) { c["nonce"] = "" }, false},
		{"null nonce", func(c map[string]any) { c["nonce"] = nil }, false},
		{"missing events", func(c map[string]any) { delete(c, "events") }, false},
		{"null events", func(c map[string]any) { c["events"] = nil }, false},
		{"empty events", func(c map[string]any) { c["events"] = map[string]any{} }, false},
		{"wrong event", func(c map[string]any) { c["events"] = map[string]any{"logout": map[string]any{}} }, false},
		{"null event value", func(c map[string]any) { c["events"] = map[string]any{backchannelLogoutEvent: nil} }, false},
		{"array event value", func(c map[string]any) { c["events"] = map[string]any{backchannelLogoutEvent: []any{}} }, false},
		{"expired", func(c map[string]any) { c["exp"] = now.Add(-time.Minute).Unix() }, false},
		{"expiry before issuance", func(c map[string]any) { c["exp"] = now.Add(-time.Second).Unix() }, false},
		{"null expiry", func(c map[string]any) { c["exp"] = nil }, false},
		{"string expiry", func(c map[string]any) { c["exp"] = fmt.Sprint(now.Add(time.Minute).Unix()) }, false},
		{"future not before", func(c map[string]any) { c["nbf"] = now.Add(time.Minute).Unix() }, false},
		{"null not before", func(c map[string]any) { c["nbf"] = nil }, false},
		{"string not before", func(c map[string]any) { c["nbf"] = fmt.Sprint(now.Unix()) }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := f.claims(now)
			tc.change(claims)
			raw := signLogoutClaims(t, f.key, "key-1", claims)
			event, err := v.Verify(context.Background(), raw)
			if (err == nil) != tc.accept {
				t.Fatalf("accept=%v, error=%v", tc.accept, err)
			}
			if tc.accept && (event.Issuer != f.server.URL || event.JTI != "event-1") {
				t.Fatalf("wrong event: %+v", event)
			}
		})
	}
	if calls := f.discoveryCalls.Load(); calls != 1 {
		t.Fatalf("discovery called %d times", calls)
	}
}

func TestLogoutTokenRejectsInvalidSignaturesAndDuplicateClaims(t *testing.T) {
	f := newLogoutIssuerFixture(t)
	now := time.Now()
	v := newLogoutVerifier(f.server.URL, "caddy", 5*time.Minute, 30*time.Second)
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(f.claims(now))
	if err != nil {
		t.Fatal(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	duplicate := append([]byte(`{"jti":"earlier",`), payload[1:]...)
	hmacSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte(strings.Repeat("s", 32))}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hmacObject, err := hmacSigner.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	hmacToken, err := hmacObject.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	tokens := map[string]string{
		"wrong signing key":   signLogoutClaims(t, wrongKey, "key-1", f.claims(now)),
		"unsigned":            encode([]byte(`{"alg":"none"}`)) + "." + encode(payload) + ".",
		"symmetric algorithm": hmacToken,
		"duplicate jti":       signLogoutPayload(t, f.key, "key-1", duplicate),
		"malformed":           "not-a-jwt",
		"empty":               "",
		"oversized":           strings.Repeat("x", (64<<10)+1),
	}
	for name, raw := range tokens {
		t.Run(name, func(t *testing.T) {
			if _, err := v.Verify(context.Background(), raw); err == nil {
				t.Fatal("accepted invalid logout token")
			}
		})
	}
}

func TestLogoutVerifierRetriesDiscoveryAndHandlesKeyRotation(t *testing.T) {
	f := newLogoutIssuerFixture(t)
	v := newLogoutVerifier(f.server.URL, "caddy", 5*time.Minute, 30*time.Second)
	raw := signLogoutClaims(t, f.key, "key-1", f.claims(time.Now()))
	f.failDiscovery.Store(true)
	if _, err := v.Verify(context.Background(), raw); err == nil {
		t.Fatal("expected discovery failure")
	}
	f.failDiscovery.Store(false)
	if _, err := v.Verify(context.Background(), raw); err != nil {
		t.Fatalf("discovery did not recover: %v", err)
	}
	rotated, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.publicKey = jose.JSONWebKey{Key: &rotated.PublicKey, KeyID: "key-2", Algorithm: "RS256", Use: "sig"}
	f.mu.Unlock()
	raw = signLogoutClaims(t, rotated, "key-2", f.claims(time.Now()))
	if _, err := v.Verify(context.Background(), raw); err != nil {
		t.Fatalf("rotated key rejected: %v", err)
	}
	if calls := f.keyCalls.Load(); calls < 2 {
		t.Fatalf("key set was not refreshed: %d calls", calls)
	}
	endpoint, err := v.endSessionEndpoint(context.Background())
	if err != nil || endpoint != f.server.URL+"/logout" {
		t.Fatalf("endpoint=%q error=%v", endpoint, err)
	}
}

func TestLogoutVerifierDiscoveryCannotRelaxIssuerValidation(t *testing.T) {
	f := newLogoutIssuerFixture(t)
	f.mu.Lock()
	f.metadata["issuer"] = "https://different.example"
	f.mu.Unlock()
	v := newLogoutVerifier(f.server.URL, "caddy", 5*time.Minute, 30*time.Second)
	ctx := oidc.InsecureIssuerURLContext(context.Background(), "https://different.example")
	if _, err := v.loadVerifier(ctx); err == nil {
		t.Fatal("accepted mismatched discovery issuer")
	}
}

func TestLogoutVerifierConcurrentInitialization(t *testing.T) {
	f := newLogoutIssuerFixture(t)
	v := newLogoutVerifier(f.server.URL, "caddy", 5*time.Minute, 30*time.Second)
	raw := signLogoutClaims(t, f.key, "key-1", f.claims(time.Now()))
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.Verify(context.Background(), raw); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if calls := f.discoveryCalls.Load(); calls != 1 {
		t.Fatalf("discovery called %d times", calls)
	}
}

func TestLogoutVerifierRejectsMalformedDiscoveryURLs(t *testing.T) {
	for _, value := range []string{"", "/relative", "file:///tmp/keys", "https://user:password@example.com/keys", "https://example.com/keys#fragment"} {
		t.Run(value, func(t *testing.T) {
			f := newLogoutIssuerFixture(t)
			f.mu.Lock()
			f.metadata["jwks_uri"] = value
			f.mu.Unlock()
			v := newLogoutVerifier(f.server.URL, "caddy", 5*time.Minute, 30*time.Second)
			if _, err := v.loadVerifier(context.Background()); err == nil {
				t.Fatal("accepted invalid JWKS URL")
			}
		})
	}
}

func TestLogoutVerifierRejectsHTTPSDowngrades(t *testing.T) {
	var insecureRequests atomic.Int32
	insecure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		insecureRequests.Add(1)
		http.Error(w, "must not be reached", http.StatusInternalServerError)
	}))
	defer insecure.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, insecure.URL, http.StatusFound)
	}))
	defer redirect.Close()
	v := newLogoutVerifier(redirect.URL, "caddy", 5*time.Minute, 30*time.Second)
	ctx := oidc.ClientContext(context.Background(), redirect.Client())
	if _, err := v.loadVerifier(ctx); err == nil {
		t.Fatal("accepted HTTPS-to-HTTP discovery redirect")
	}
	if insecureRequests.Load() != 0 {
		t.Fatal("contacted HTTP redirect destination")
	}

	var secure *httptest.Server
	secure = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":               secure.URL,
			"jwks_uri":             secure.URL + "/jwks",
			"end_session_endpoint": insecure.URL,
		})
	}))
	defer secure.Close()
	v = newLogoutVerifier(secure.URL, "caddy", 5*time.Minute, 30*time.Second)
	ctx = oidc.ClientContext(context.Background(), secure.Client())
	if _, err := v.endSessionEndpoint(ctx); err == nil {
		t.Fatal("accepted HTTP end-session endpoint for HTTPS issuer")
	}
}
