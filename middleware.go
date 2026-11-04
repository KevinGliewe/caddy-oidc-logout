package oidclogout

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	oidc "github.com/relvacode/caddy-oidc"
	"github.com/relvacode/caddy-oidc/session"
)

func init() { caddy.RegisterModule(SessionHandler{}) }

// SessionHandler must follow OIDC authentication and precede reverse_proxy on
// every protected route. No claims are accepted from client-supplied headers.
type SessionHandler struct {
	Provider           string `json:"provider"`
	ForwardAccessToken bool   `json:"forward_access_token,omitempty"`
	app                *App
	provider           *Provider
}

func (SessionHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.oidc_session", New: func() caddy.Module { return new(SessionHandler) }}
}
func (h *SessionHandler) Provision(ctx caddy.Context) error {
	var err error
	h.app, h.provider, err = getProvider(ctx, h.Provider)
	return err
}

func (h *SessionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	id, sess, err := authenticatedIdentity(r, h.provider, h.app)
	if err != nil {
		return caddyhttp.Error(http.StatusUnauthorized, err)
	}
	if err := h.app.registry.check(id); err != nil {
		return caddyhttp.Error(http.StatusUnauthorized, errRevoked)
	}
	if h.ForwardAccessToken {
		accessToken, _ := sessionTokens(sess)
		if accessToken == "" {
			return caddyhttp.Error(http.StatusUnauthorized, fmt.Errorf("forward_access_token requires patched caddy-oidc and retain_access_token"))
		}
		r.Header.Set("Authorization", "Bearer "+accessToken)
	}
	binding := &sessionBinding{registry: h.app.registry, identity: id}
	return next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), bindingKey{}, binding)))
}

func authenticatedIdentity(r *http.Request, p *Provider, app *App) (identity, *session.Session, error) {
	var id identity
	id.ClientID = p.ClientID
	sess, _ := r.Context().Value(oidc.SessionCtxKey).(*session.Session)
	claims := make(map[string]json.RawMessage)
	if sess != nil {
		if sess.Anonymous || json.Unmarshal(sess.Claims, &claims) != nil {
			return id, nil, fmt.Errorf("missing authenticated OIDC claims")
		}
	} else {
		// Stock caddy-oidc v0.4.3 exposes verified claims through its replacer;
		// the optional token-retention patch also propagates its typed session.
		repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
		if !ok {
			return id, nil, fmt.Errorf("missing OIDC authentication")
		}
		anon, ok := repl.Get("http.auth.user.anonymous")
		result, _ := repl.GetString("http.auth.result")
		if !ok || anon != false || result != "allow" {
			return id, nil, fmt.Errorf("missing successful OIDC authentication")
		}
		for _, name := range []string{"iss", "sub", "sid", "iat", "exp", "aud"} {
			value, ok := repl.GetString("http.auth.user.claim." + name)
			if !ok {
				continue
			}
			if name == "iat" || name == "exp" {
				claims[name] = json.RawMessage(value)
			} else {
				claims[name], _ = json.Marshal(value)
			}
		}
	}
	stringClaim := func(name string) string { var v string; _ = json.Unmarshal(claims[name], &v); return v }
	id.Issuer, id.Subject, id.SID = stringClaim("iss"), stringClaim("sub"), stringClaim("sid")
	if id.Issuer != p.Issuer || id.Subject == "" || id.SID == "" {
		return id, sess, fmt.Errorf("missing or mismatched OIDC issuer, sub or sid; retain them with id_claim")
	}
	var audience []string
	var singleAudience string
	if json.Unmarshal(claims["aud"], &singleAudience) == nil {
		audience = []string{singleAudience}
	} else {
		_ = json.Unmarshal(claims["aud"], &audience)
	}
	matched := false
	for _, client := range audience {
		if client == p.ClientID {
			matched = true
		}
	}
	if !matched {
		return id, sess, fmt.Errorf("missing or mismatched OIDC aud claim; retain it with id_claim")
	}
	for name, dst := range map[string]*time.Time{"iat": &id.IssuedAt, "exp": &id.ExpiresAt} {
		date, err := logoutDate(claims[name])
		if err != nil || date.Unix() <= 0 {
			return id, sess, fmt.Errorf("missing or malformed OIDC %s claim", name)
		}
		*dst = date
	}
	now := time.Now()
	if id.IssuedAt.After(now.Add(time.Duration(app.ClockSkew))) || !id.ExpiresAt.After(now) || !id.ExpiresAt.After(id.IssuedAt) || now.Sub(id.IssuedAt) > time.Duration(app.MaxSessionAge) {
		return id, sess, errRevoked
	}
	// Enforce a bound independent of cookie max_age so durable revocations can
	// safely expire. Cap streams to both token and local session deadlines.
	maxExpiry := id.IssuedAt.Add(time.Duration(app.MaxSessionAge))
	if maxExpiry.Before(id.ExpiresAt) {
		id.ExpiresAt = maxExpiry
	}
	if sess != nil && !sess.Expires().IsZero() && sess.Expires().Before(id.ExpiresAt) {
		id.ExpiresAt = sess.Expires()
	}
	if !id.ExpiresAt.After(now) {
		return id, sess, errRevoked
	}
	return id, sess, nil
}

func sessionTokens(s *session.Session) (string, string) {
	if s == nil {
		return "", ""
	}
	if tokens, ok := any(s).(interface{ OIDCTokens() (string, string) }); ok {
		return tokens.OIDCTokens()
	}
	return "", ""
}
