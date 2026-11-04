package main

import (
	_ "github.com/KevinGliewe/caddy-oidc-logout"
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/relvacode/caddy-oidc"
)

func main() { caddycmd.Main() }
