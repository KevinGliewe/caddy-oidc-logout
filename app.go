// Package oidclogout adds OIDC logout and session-aware stream enforcement to Caddy.
package oidclogout

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
)

var registryPool = caddy.NewUsagePool()

func init() { caddy.RegisterModule(&App{}) }

// App shares durable revocations and active streams across all protected routes.
// A state file must be owned by one Caddy process. Multiple replicas are not a
// supported deployment until distributed logout delivery is implemented.
type App struct {
	StateFile     string               `json:"state_file,omitempty"`
	MaxSessionAge caddy.Duration       `json:"max_session_age,omitempty"`
	LogoutMaxAge  caddy.Duration       `json:"logout_max_age,omitempty"`
	ClockSkew     caddy.Duration       `json:"clock_skew,omitempty"`
	Providers     map[string]*Provider `json:"providers"`
	registry      *registry
	release       sync.Once
}

type Provider struct {
	Issuer              string `json:"issuer"`
	ClientID            string `json:"client_id"`
	AllowInsecureIssuer bool   `json:"allow_insecure_issuer,omitempty"`
	verifier            *logoutVerifier
}

func (*App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "oidc_logout", New: func() caddy.Module { return new(App) }}
}

func (a *App) Provision(ctx caddy.Context) error {
	if a.MaxSessionAge == 0 {
		a.MaxSessionAge = caddy.Duration(24 * time.Hour)
	}
	if a.LogoutMaxAge == 0 {
		a.LogoutMaxAge = caddy.Duration(5 * time.Minute)
	}
	if a.ClockSkew == 0 {
		a.ClockSkew = caddy.Duration(30 * time.Second)
	}
	if a.MaxSessionAge <= 0 || a.LogoutMaxAge <= 0 || a.ClockSkew < 0 {
		return fmt.Errorf("logout durations must be positive")
	}
	if a.MaxSessionAge > caddy.Duration(30*24*time.Hour) || a.LogoutMaxAge > caddy.Duration(time.Hour) || a.ClockSkew > caddy.Duration(5*time.Minute) {
		return fmt.Errorf("maximum session age is 30d, logout age 1h and clock skew 5m")
	}
	if len(a.Providers) == 0 {
		return fmt.Errorf("at least one logout provider is required")
	}
	repl := caddy.NewReplacer()
	for name, p := range a.Providers {
		if p == nil || name == "" {
			return fmt.Errorf("invalid logout provider")
		}
		var err error
		p.Issuer, err = repl.ReplaceOrErr(p.Issuer, true, true)
		if err != nil {
			return err
		}
		p.ClientID, err = repl.ReplaceOrErr(p.ClientID, true, true)
		if err != nil {
			return err
		}
		u, err := url.Parse(p.Issuer)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(p.AllowInsecureIssuer && u.Scheme == "http")) {
			return fmt.Errorf("provider %s requires an absolute HTTPS issuer (HTTP requires allow_insecure_issuer)", name)
		}
		if strings.TrimSpace(p.ClientID) == "" {
			return fmt.Errorf("provider %s has no client_id", name)
		}
		p.verifier = newLogoutVerifier(p.Issuer, p.ClientID, time.Duration(a.LogoutMaxAge), time.Duration(a.ClockSkew))
	}
	if a.StateFile == "" {
		a.StateFile = filepath.Join(caddy.AppDataDir(), "oidc-logout", "sessions.db")
	}
	var err error
	a.StateFile, err = repl.ReplaceOrErr(a.StateFile, true, true)
	if err != nil {
		return err
	}
	a.StateFile, err = filepath.Abs(a.StateFile)
	if err != nil {
		return err
	}
	v, _, err := registryPool.LoadOrNew(a.StateFile, func() (caddy.Destructor, error) { return openRegistry(a.StateFile) })
	if err != nil {
		return err
	}
	a.registry = v.(*registry)
	return nil
}

func (*App) Start() error  { return nil }
func (a *App) Stop() error { return a.Cleanup() }
func (a *App) Cleanup() error {
	var err error
	a.release.Do(func() {
		if a.registry != nil {
			_, err = registryPool.Delete(a.StateFile)
		}
	})
	return err
}

func getProvider(ctx caddy.Context, name string) (*App, *Provider, error) {
	value, err := ctx.App("oidc_logout")
	if err != nil {
		return nil, nil, err
	}
	app := value.(*App)
	p, ok := app.Providers[name]
	if !ok {
		return nil, nil, fmt.Errorf("unknown logout provider %q", name)
	}
	return app, p, nil
}

var _ caddy.App = (*App)(nil)
var _ caddy.Provisioner = (*App)(nil)
var _ caddy.CleanerUpper = (*App)(nil)
