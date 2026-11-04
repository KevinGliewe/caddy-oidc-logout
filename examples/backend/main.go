// The demo backend independently validates the original Keycloak access JWT.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/websocket"
)

type claims struct {
	Issuer      string `json:"iss"`
	Subject     string `json:"sub"`
	Username    string `json:"preferred_username"`
	Audience    any    `json:"aud"`
	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
}

func main() {
	issuer, audience := os.Getenv("OIDC_ISSUER"), os.Getenv("OIDC_AUDIENCE")
	if issuer == "" || audience == "" {
		log.Fatal("OIDC_ISSUER and OIDC_AUDIENCE are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	provider, err := oidc.NewProvider(ctx, issuer)
	cancel()
	if err != nil {
		log.Fatal(err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: audience})
	app, role := os.Getenv("APP_NAME"), os.Getenv("REQUIRED_ROLE")
	page := template.Must(template.New("page").Parse(pageHTML))
	server := &http.Server{Addr: ":8080", ReadHeaderTimeout: 5 * time.Second}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			http.Error(w, "Missing forwarded access token", http.StatusUnauthorized)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		token, err := verifier.Verify(ctx, bearer)
		if err != nil {
			http.Error(w, "Invalid access token", http.StatusUnauthorized)
			return
		}
		var identity claims
		if err := token.Claims(&identity); err != nil {
			http.Error(w, "Invalid claims", http.StatusUnauthorized)
			return
		}
		if !slices.Contains(identity.RealmAccess.Roles, role) {
			http.Error(w, "Missing realm role", http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/api":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"application": app, "required_role": role, "jwt_validated": true, "claims": identity})
		case "/ws":
			upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool {
				origin := r.Header.Get("Origin")
				if origin == "" {
					return true
				}
				u, err := url.Parse(origin)
				return err == nil && u.Host == r.Host
			}}
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			for {
				kind, data, err := conn.ReadMessage()
				if err != nil {
					return
				}
				if err := conn.WriteMessage(kind, []byte(fmt.Sprintf("%s / %s: %s", app, identity.Username, data))); err != nil {
					return
				}
			}
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			page.Execute(w, app)
		default:
			http.NotFound(w, r)
		}
	})
	log.Printf("%s listening on :8080; required realm role %s", app, role)
	log.Fatal(server.ListenAndServe())
}

const pageHTML = `<!doctype html>
<html lang="en"><meta charset="utf-8"><title>{{.}}</title>
<style>body{max-width:850px;margin:3rem auto;padding:0 1rem;font:18px system-ui}pre{padding:1rem;background:#eee;overflow:auto}button,a{margin-right:1rem}</style>
<h1>{{.}}</h1><p><a href="/app1/">Application 1</a><a href="/app2/">Application 2</a></p>
<p>The backend validates the Keycloak access token's signature, issuer, audience and required realm role.</p>
<h2>Identity received by this application</h2><pre id="identity">Loading…</pre>
<h2>WebSocket</h2><p id="status">Connecting…</p><button id="send">Send a message</button><pre id="messages"></pre>
<form action="/logout" method="post"><button>Log out of this session and Keycloak</button></form>
<script>
fetch('api').then(r=>r.json()).then(v=>identity.textContent=JSON.stringify(v,null,2));
const ws=new WebSocket((location.protocol==='https:'?'wss:':'ws:')+'//'+location.host+location.pathname+'ws');
ws.onopen=()=>document.getElementById('status').textContent='Connected';
ws.onmessage=e=>messages.textContent+=e.data+'\n';
ws.onclose=e=>document.getElementById('status').textContent='Disconnected (code '+e.code+')';
document.getElementById('send').onclick=()=>{if(ws.readyState===1)ws.send('Hello at '+new Date().toISOString());};
</script></html>`
