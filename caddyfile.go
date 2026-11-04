package oidclogout

import (
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterGlobalOption("oidc_logout", parseGlobal)
	httpcaddyfile.RegisterHandlerDirective("oidc_session", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		v := new(SessionHandler)
		return v, v.UnmarshalCaddyfile(h.Dispenser)
	})
	httpcaddyfile.RegisterHandlerDirective("oidc_backchannel", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		v := new(BackchannelHandler)
		return v, v.UnmarshalCaddyfile(h.Dispenser)
	})
	httpcaddyfile.RegisterHandlerDirective("oidc_signout", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		v := new(SignoutHandler)
		return v, v.UnmarshalCaddyfile(h.Dispenser)
	})
	// Explicit route blocks are recommended; these defaults also put enforcement
	// after the OIDC handler (which is ordered before basic_auth) and before proxying.
	for _, name := range []string{"oidc_session", "oidc_signout", "oidc_backchannel"} {
		httpcaddyfile.RegisterDirectiveOrder(name, httpcaddyfile.Before, "reverse_proxy")
	}
}

func parseGlobal(d *caddyfile.Dispenser, existing any) (any, error) {
	if existing != nil {
		return nil, d.Err("only one oidc_logout global block is allowed")
	}
	a := &App{Providers: make(map[string]*Provider)}
	for d.Next() {
		if d.NextArg() {
			return nil, d.ArgErr()
		}
		for d.NextBlock(0) {
			switch d.Val() {
			case "state_file":
				if !d.AllArgs(&a.StateFile) {
					return nil, d.ArgErr()
				}
			case "max_session_age", "logout_max_age", "clock_skew":
				name := d.Val()
				var value string
				if !d.AllArgs(&value) {
					return nil, d.ArgErr()
				}
				duration, err := caddy.ParseDuration(value)
				if err != nil {
					return nil, d.Errf("invalid duration: %v", err)
				}
				switch name {
				case "max_session_age":
					a.MaxSessionAge = caddy.Duration(duration)
				case "logout_max_age":
					a.LogoutMaxAge = caddy.Duration(duration)
				case "clock_skew":
					a.ClockSkew = caddy.Duration(duration)
				}
			case "provider":
				var name string
				if !d.AllArgs(&name) {
					return nil, d.ArgErr()
				}
				if _, ok := a.Providers[name]; ok {
					return nil, d.Errf("duplicate provider %s", name)
				}
				p := new(Provider)
				for nesting := d.Nesting(); d.NextBlock(nesting); {
					switch d.Val() {
					case "issuer":
						if !d.AllArgs(&p.Issuer) {
							return nil, d.ArgErr()
						}
					case "client_id":
						if !d.AllArgs(&p.ClientID) {
							return nil, d.ArgErr()
						}
					case "allow_insecure_issuer":
						if d.NextArg() {
							return nil, d.ArgErr()
						}
						p.AllowInsecureIssuer = true
					default:
						return nil, d.Errf("unknown provider option %s", d.Val())
					}
				}
				a.Providers[name] = p
			default:
				return nil, d.Errf("unknown oidc_logout option %s", d.Val())
			}
		}
	}
	return httpcaddyfile.App{Name: "oidc_logout", Value: caddyconfig.JSON(a, nil)}, nil
}

func (h *SessionHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.AllArgs(&h.Provider) {
			return d.ArgErr()
		}
		for d.NextBlock(0) {
			if d.Val() != "forward_access_token" {
				return d.Errf("unknown oidc_session option %s", d.Val())
			}
			if d.NextArg() {
				return d.ArgErr()
			}
			h.ForwardAccessToken = true
		}
	}
	return nil
}
func (h *BackchannelHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.AllArgs(&h.Provider) {
			return d.ArgErr()
		}
		if d.NextBlock(0) {
			return d.Err("oidc_backchannel accepts no block")
		}
	}
	return nil
}
func (h *SignoutHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.AllArgs(&h.Provider) {
			return d.ArgErr()
		}
		for d.NextBlock(0) {
			var target *string
			switch d.Val() {
			case "cookie_name":
				target = &h.CookieName
			case "cookie_path":
				target = &h.CookiePath
			case "cookie_domain":
				target = &h.CookieDomain
			case "redirect":
				target = &h.Redirect
			default:
				return d.Err(fmt.Sprintf("unknown oidc_signout option %s", d.Val()))
			}
			if !d.AllArgs(target) {
				return d.ArgErr()
			}
		}
	}
	return nil
}
