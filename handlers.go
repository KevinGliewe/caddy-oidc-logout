package oidclogout

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() { caddy.RegisterModule(BackchannelHandler{}); caddy.RegisterModule(SignoutHandler{}) }

// Retain records through the longest allowed session plus maximum clock skew,
// even when a later reload increases max_session_age.
const revocationRetention = 30*24*time.Hour + 5*time.Minute

type BackchannelHandler struct {
	Provider string `json:"provider"`
	app      *App
	provider *Provider
}

func (BackchannelHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.oidc_backchannel", New: func() caddy.Module { return new(BackchannelHandler) }}
}
func (h *BackchannelHandler) Provision(ctx caddy.Context) error {
	var err error
	h.app, h.provider, err = getProvider(ctx, h.Provider)
	return err
}
func (h *BackchannelHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("POST required"))
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" {
		return caddyhttp.Error(http.StatusUnsupportedMediaType, fmt.Errorf("form-encoded logout_token required"))
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid logout form"))
	}
	tokens := r.PostForm["logout_token"]
	if len(tokens) != 1 || tokens[0] == "" || len(r.URL.Query()["logout_token"]) > 0 {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("exactly one body logout_token required"))
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	event, err := h.provider.verifier.Verify(ctx, tokens[0])
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid logout token"))
	}
	err = h.app.registry.revoke(h.provider.Issuer, h.provider.ClientID, event, revocationRetention, time.Duration(h.app.LogoutMaxAge+2*h.app.ClockSkew)+time.Second)
	if err != nil && !errors.Is(err, errReplay) {
		return caddyhttp.Error(http.StatusServiceUnavailable, fmt.Errorf("could not persist logout"))
	}
	w.WriteHeader(http.StatusOK)
	return nil
}

// SignoutHandler revokes locally before redirecting to the OP's logout endpoint.
// It must run after OIDC authentication and requires a same-origin POST.
type SignoutHandler struct {
	Provider     string `json:"provider"`
	CookieName   string `json:"cookie_name,omitempty"`
	CookiePath   string `json:"cookie_path,omitempty"`
	CookieDomain string `json:"cookie_domain,omitempty"`
	Redirect     string `json:"redirect,omitempty"`
	app          *App
	provider     *Provider
}

func (SignoutHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.oidc_signout", New: func() caddy.Module { return new(SignoutHandler) }}
}
func (h *SignoutHandler) Provision(ctx caddy.Context) error {
	var err error
	h.app, h.provider, err = getProvider(ctx, h.Provider)
	if err != nil {
		return err
	}
	if h.CookieName == "" {
		h.CookieName = "caddy"
	}
	if h.CookiePath == "" {
		h.CookiePath = "/"
	}
	if h.Redirect == "" {
		h.Redirect = "/"
	}
	u, err := url.Parse(h.Redirect)
	if err != nil || u.User != nil || strings.HasPrefix(h.Redirect, "//") || (u.IsAbs() && u.Scheme != "https" && u.Scheme != "http") || (!u.IsAbs() && !strings.HasPrefix(h.Redirect, "/")) {
		return fmt.Errorf("invalid signout redirect")
	}
	if err := (&http.Cookie{Name: h.CookieName, Path: h.CookiePath, Domain: h.CookieDomain}).Valid(); err != nil {
		return fmt.Errorf("invalid signout cookie: %w", err)
	}
	return nil
}
func (h *SignoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("POST required"))
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	origin := scheme + "://" + r.Host
	if r.Header.Get("Origin") != origin || (r.Header.Get("Sec-Fetch-Site") != "" && r.Header.Get("Sec-Fetch-Site") != "same-origin") {
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("same-origin logout required"))
	}
	id, sess, err := authenticatedIdentity(r, h.provider, h.app)
	if err != nil {
		return caddyhttp.Error(http.StatusUnauthorized, err)
	}
	if err = h.app.registry.revoke(id.Issuer, id.ClientID, logoutEvent{SID: id.SID, Subject: id.Subject, IssuedAt: time.Now()}, revocationRetention, 0); err != nil {
		return caddyhttp.Error(http.StatusServiceUnavailable, fmt.Errorf("could not persist logout"))
	}
	http.SetCookie(w, &http.Cookie{Name: h.CookieName, Value: "", Path: h.CookiePath, Domain: h.CookieDomain, MaxAge: -1, Expires: time.Unix(1, 0), HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	endpoint, err := h.provider.verifier.endSessionEndpoint(ctx)
	if err != nil {
		return caddyhttp.Error(http.StatusBadGateway, fmt.Errorf("session revoked locally; provider logout discovery failed"))
	}
	redirect := h.Redirect
	if endpoint != "" {
		u, _ := url.Parse(endpoint)
		q := u.Query()
		q.Set("client_id", h.provider.ClientID)
		_, idToken := sessionTokens(sess)
		if idToken != "" {
			q.Set("id_token_hint", idToken)
		}
		if strings.HasPrefix(redirect, "/") {
			redirect = origin + redirect
		}
		q.Set("post_logout_redirect_uri", redirect)
		u.RawQuery = q.Encode()
		redirect = u.String()
	}
	http.Redirect(w, r, redirect, http.StatusSeeOther)
	return nil
}
