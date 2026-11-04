package oidclogout

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// logoutEvent contains authenticated logout instructions. Replay detection and
// durable revocation belong to the shared session registry, not this verifier.
type logoutEvent struct {
	Issuer   string
	Subject  string
	SID      string
	JTI      string
	IssuedAt time.Time
}

type logoutVerifier struct {
	issuer   string
	clientID string
	maxAge   time.Duration
	skew     time.Duration
	now      func() time.Time

	mu            sync.Mutex
	verifier      *oidc.IDTokenVerifier
	endSessionURL string
}

func newLogoutVerifier(issuer, clientID string, maxAge, skew time.Duration) *logoutVerifier {
	return &logoutVerifier{issuer: issuer, clientID: clientID, maxAge: maxAge, skew: skew, now: time.Now}
}

// loadVerifier discovers the provider lazily so a temporarily unavailable IdP
// does not prevent Caddy from starting. Failed discovery is retried next time.
func (v *logoutVerifier) loadVerifier(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if v.verifier != nil {
		return v.verifier, nil
	}
	issuerURL, err := url.Parse(v.issuer)
	if err != nil {
		return nil, fmt.Errorf("parse logout issuer: %w", err)
	}

	// go-oidc shares key-fetch requests and intentionally ignores the discovery
	// context's cancellation for those requests. Bound the HTTP client as well.
	client := *http.DefaultClient
	if configured, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok && configured != nil {
		client = *configured
	}
	if client.Timeout <= 0 || client.Timeout > 10*time.Second {
		client.Timeout = 10 * time.Second
	}
	previousRedirectCheck := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many logout discovery/key redirects")
		}
		if req.URL.User != nil || (req.URL.Scheme != "http" && req.URL.Scheme != "https") ||
			(issuerURL.Scheme == "https" && req.URL.Scheme != "https") {
			return errors.New("insecure logout discovery/key redirect")
		}
		if previousRedirectCheck != nil {
			return previousRedirectCheck(req, via)
		}
		return nil
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, &client), v.issuer)
	if err != nil {
		return nil, fmt.Errorf("discover logout issuer: %w", err)
	}
	var metadata struct {
		Issuer        string `json:"issuer"`
		JWKSURL       string `json:"jwks_uri"`
		EndSessionURL string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&metadata); err != nil {
		return nil, fmt.Errorf("decode logout issuer metadata: %w", err)
	}
	// Check explicitly even though go-oidc normally does this: a caller's context
	// must never weaken our issuer binding through InsecureIssuerURLContext.
	if metadata.Issuer != v.issuer {
		return nil, errors.New("logout discovery issuer mismatch")
	}
	keysURL, err := url.Parse(metadata.JWKSURL)
	if err != nil || keysURL.Host == "" || keysURL.User != nil || keysURL.Fragment != "" ||
		(keysURL.Scheme != "https" && keysURL.Scheme != "http") ||
		(issuerURL.Scheme == "https" && keysURL.Scheme != "https") {
		return nil, errors.New("logout issuer supplied an invalid or insecure JWKS URL")
	}
	// Provider.Verifier permits only the provider's supported asymmetric signing
	// algorithms (RS/PS/ES/EdDSA), defaulting to RS256. Expiry is checked below:
	// logout tokens can omit exp, unlike ID tokens; SkipExpiryCheck also skips
	// nbf inside go-oidc, so we explicitly validate both optional claims.
	v.verifier = provider.Verifier(&oidc.Config{ClientID: v.clientID, SkipExpiryCheck: true})
	v.endSessionURL = metadata.EndSessionURL
	return v.verifier, nil
}

// An empty endpoint means the provider does not advertise RP-initiated logout.
func (v *logoutVerifier) endSessionEndpoint(ctx context.Context) (string, error) {
	if _, err := v.loadVerifier(ctx); err != nil {
		return "", err
	}
	v.mu.Lock()
	endpoint := v.endSessionURL
	v.mu.Unlock()
	if endpoint == "" {
		return "", nil
	}
	issuerURL, _ := url.Parse(v.issuer)
	endpointURL, err := url.Parse(endpoint)
	if err != nil || endpointURL.Host == "" || endpointURL.User != nil || endpointURL.Fragment != "" ||
		(endpointURL.Scheme != "https" && endpointURL.Scheme != "http") ||
		(issuerURL != nil && issuerURL.Scheme == "https" && endpointURL.Scheme != "https") {
		return "", errors.New("logout issuer supplied an invalid or insecure end-session URL")
	}
	return endpoint, nil
}

func (v *logoutVerifier) Verify(ctx context.Context, raw string) (logoutEvent, error) {
	var event logoutEvent
	if v.issuer == "" || v.clientID == "" || v.maxAge <= 0 || v.skew < 0 {
		return event, errors.New("invalid logout verifier configuration")
	}
	if len(raw) == 0 || len(raw) > 64<<10 {
		return event, errors.New("invalid logout token size")
	}
	verifier, err := v.loadVerifier(ctx)
	if err != nil {
		return event, err
	}
	token, err := verifier.Verify(ctx, raw)
	if err != nil {
		return event, fmt.Errorf("verify logout token: %w", err)
	}
	// go-oidc has a legacy Google issuer exception. Logout uses exact issuer
	// matching so session identities cannot cross issuer boundaries.
	if token.Issuer != v.issuer {
		return event, errors.New("logout token issuer mismatch")
	}
	var payload json.RawMessage
	if err := token.Claims(&payload); err != nil {
		return event, fmt.Errorf("decode logout token: %w", err)
	}
	claims, err := logoutJSONObject(payload)
	if err != nil {
		return event, fmt.Errorf("decode logout claims: %w", err)
	}
	if _, present := claims["nonce"]; present {
		return event, errors.New("logout token must not contain nonce")
	}
	if event.Issuer, err = logoutString(claims, "iss", true); err != nil {
		return event, err
	}
	if event.Subject, err = logoutString(claims, "sub", false); err != nil {
		return event, err
	}
	if event.SID, err = logoutString(claims, "sid", false); err != nil {
		return event, err
	}
	if event.Subject == "" && event.SID == "" {
		return event, errors.New("logout token requires sub or sid")
	}
	if event.JTI, err = logoutString(claims, "jti", true); err != nil {
		return event, err
	}
	if err := logoutAudience(claims["aud"], v.clientID); err != nil {
		return event, err
	}
	if event.IssuedAt, err = logoutDate(claims["iat"]); err != nil {
		return event, fmt.Errorf("invalid logout iat: %w", err)
	}
	now := v.now()
	if event.IssuedAt.After(now.Add(v.skew)) || event.IssuedAt.Before(now.Add(-v.maxAge-v.skew)) {
		return event, errors.New("logout token iat is outside the accepted window")
	}
	if rawExpiry, exists := claims["exp"]; exists {
		expires, err := logoutDate(rawExpiry)
		if err != nil {
			return event, fmt.Errorf("invalid logout exp: %w", err)
		}
		if !expires.After(now.Add(-v.skew)) || !expires.After(event.IssuedAt) {
			return event, errors.New("logout token is expired or has invalid exp")
		}
	}
	if rawNotBefore, exists := claims["nbf"]; exists {
		notBefore, err := logoutDate(rawNotBefore)
		if err != nil {
			return event, fmt.Errorf("invalid logout nbf: %w", err)
		}
		if notBefore.After(now.Add(v.skew)) {
			return event, errors.New("logout token is not valid yet")
		}
	}
	events, err := logoutJSONObject(claims["events"])
	if err != nil {
		return event, fmt.Errorf("invalid logout events: %w", err)
	}
	if _, err := logoutJSONObject(events[backchannelLogoutEvent]); err != nil {
		return event, errors.New("logout token requires a backchannel-logout event object")
	}
	return event, nil
}

func logoutString(claims map[string]json.RawMessage, name string, required bool) (string, error) {
	raw, exists := claims[name]
	raw = bytes.TrimSpace(raw)
	if !exists && !required {
		return "", nil
	}
	var value string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &value) != nil || value == "" {
		return "", fmt.Errorf("logout %s must be a nonempty string", name)
	}
	return value, nil
}

func logoutAudience(raw json.RawMessage, clientID string) error {
	raw = bytes.TrimSpace(raw)
	var values []string
	if len(raw) > 0 && raw[0] == '"' {
		var single string
		if err := json.Unmarshal(raw, &single); err != nil {
			return errors.New("invalid logout audience")
		}
		values = []string{single}
	} else if len(raw) > 0 && raw[0] == '[' {
		var entries []json.RawMessage
		if err := json.Unmarshal(raw, &entries); err != nil {
			return errors.New("invalid logout audience")
		}
		for _, entry := range entries {
			value, err := logoutString(map[string]json.RawMessage{"aud": entry}, "aud", true)
			if err != nil {
				return err
			}
			values = append(values, value)
		}
	}
	for _, value := range values {
		if value == clientID {
			return nil
		}
	}
	return errors.New("logout token audience does not contain this client")
}

func logoutDate(raw json.RawMessage) (time.Time, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return time.Time{}, err
	}
	number, ok := value.(json.Number)
	if !ok {
		return time.Time{}, errors.New("expected a NumericDate number")
	}
	seconds, err := strconv.ParseFloat(number.String(), 64)
	if err != nil || math.IsInf(seconds, 0) || math.IsNaN(seconds) || seconds < -62135596800 || seconds > 253402300799 {
		return time.Time{}, errors.New("NumericDate is outside the supported range")
	}
	whole, fraction := math.Modf(seconds)
	return time.Unix(int64(whole), int64(fraction*1e9)), nil
}

// Reject duplicate claim names instead of depending on a JSON decoder's choice
// of first/last value. Nested event objects use the same check.
func logoutJSONObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, errors.New("expected a JSON object")
	}
	object := make(map[string]json.RawMessage)
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		name, ok := key.(string)
		if !ok {
			return nil, errors.New("expected a JSON member name")
		}
		if _, duplicate := object[name]; duplicate {
			return nil, fmt.Errorf("duplicate JSON member %q", name)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		object[name] = value
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("unexpected data after JSON object")
	}
	return object, nil
}
