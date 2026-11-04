// Run against the development Compose stack: go run ./examples/e2e.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/net/html"
)

const appBase = "http://apps.localtest.me:8088"
const keycloakBase = "http://keycloak.localtest.me:8080"

var transport = &http.Transport{Proxy: localProxy, DialContext: localDial}

// The two names intentionally identify this local Compose stack. All other
// destinations retain the environment's proxy behavior.
func localProxy(r *http.Request) (*url.URL, error) {
	if r.URL.Hostname() == "apps.localtest.me" || r.URL.Hostname() == "keycloak.localtest.me" {
		return nil, nil
	}
	return http.ProxyFromEnvironment(r)
}

func localDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if host == "apps.localtest.me" || host == "keycloak.localtest.me" {
		address = net.JoinHostPort("127.0.0.1", port)
	}
	return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, address)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
	fmt.Println("PASS: real Keycloak login, separate realm roles, original JWT forwarding, back-channel logout, socket isolation, reconnect rejection and local logout")
}

func run() error {
	if err := waitForStack(); err != nil {
		return err
	}
	alice, err := login("alice", "/app1/")
	if err != nil {
		return err
	}
	if err := expectStatus(alice, "/app2/api", http.StatusForbidden); err != nil {
		return err
	}
	if err := verifyIdentity(alice, "/app1/api", "alice"); err != nil {
		return err
	}
	bob, err := login("bob", "/app2/")
	if err != nil {
		return err
	}
	if err := expectStatus(bob, "/app1/api", http.StatusForbidden); err != nil {
		return err
	}
	if err := verifyIdentity(bob, "/app2/api", "bob"); err != nil {
		return err
	}
	charlie, err := login("charlie", "/app1/")
	if err != nil {
		return err
	}
	for _, path := range []string{"/app1/api", "/app2/api"} {
		if err := verifyIdentity(charlie, path, "charlie"); err != nil {
			return err
		}
	}
	fmt.Println("PASS: each application enforces its realm role and validates the original Keycloak JWT")

	c1, err := socket(charlie, "/app1/ws")
	if err != nil {
		return err
	}
	defer c1.Close()
	c2, err := socket(charlie, "/app2/ws")
	if err != nil {
		return err
	}
	defer c2.Close()
	b, err := socket(bob, "/app2/ws")
	if err != nil {
		return err
	}
	defer b.Close()
	for _, c := range []*websocket.Conn{c1, c2, b} {
		if err := echo(c); err != nil {
			return err
		}
	}
	if err := logoutKeycloakUser("charlie"); err != nil {
		return err
	}
	for _, c := range []*websocket.Conn{c1, c2} {
		if err := expectClosed(c); err != nil {
			return err
		}
	}
	if err := echo(b); err != nil {
		return fmt.Errorf("unrelated user's connection closed: %w", err)
	}
	fmt.Println("PASS: signed Keycloak back-channel logout closes both applications' sockets while another user stays connected")
	if err := expectStatus(charlie, "/app1/api", http.StatusUnauthorized); err != nil {
		return err
	}
	if err := expectReconnectDenied(charlie, "/app1/ws"); err != nil {
		return err
	}
	fmt.Println("PASS: old browser cookie and WebSocket reconnect rejected")

	// Preserve the old cookie separately because successful local logout clears it.
	oldBob := newClient()
	base, _ := url.Parse(appBase)
	oldBob.Jar.SetCookies(base, bob.Jar.Cookies(base))
	req, _ := http.NewRequest(http.MethodPost, appBase+"/logout", strings.NewReader(""))
	req.Header.Set("Origin", appBase)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := bob.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Host != "apps.localtest.me:8088" || resp.Request.URL.Path != "/logged-out" {
		return fmt.Errorf("local/provider logout returned %d at %s%s", resp.StatusCode, resp.Request.URL.Host, resp.Request.URL.Path)
	}
	if err := expectClosed(b); err != nil {
		return fmt.Errorf("local logout: %w", err)
	}
	if err := expectStatus(oldBob, "/app2/api", http.StatusUnauthorized); err != nil {
		return err
	}
	if err := expectReconnectDenied(oldBob, "/app2/ws"); err != nil {
		return err
	}
	// A fresh protected-page visit must require credentials at Keycloak again;
	// silent SSO would reveal that the provider session survived local logout.
	req, _ = http.NewRequest(http.MethodGet, appBase+"/app2/", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Sec-Fetch-Dest", "document")
	resp, err = bob.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	doc, err := html.Parse(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	action, _ := loginForm(doc)
	if resp.Request.URL.Host != "keycloak.localtest.me:8080" || action == "" {
		return errors.New("Keycloak session survived browser logout")
	}
	fmt.Println("PASS: browser logout closes sockets, revokes the saved cookie and ends the Keycloak SSO session")
	return nil
}

func waitForStack() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	for _, target := range []string{keycloakBase + "/realms/company/.well-known/openid-configuration", appBase + "/"} {
		for {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					break
				}
			}
			select {
			case <-ctx.Done():
				return fmt.Errorf("stack did not become ready at %s", target)
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	return nil
}

func newClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Transport: transport, Jar: jar, Timeout: 20 * time.Second}
}

func login(username, path string) (*http.Client, error) {
	client := newClient()
	req, _ := http.NewRequest(http.MethodGet, appBase+path, nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Sec-Fetch-Dest", "document")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("start %s login: %w", username, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s login page status %d", username, resp.StatusCode)
	}
	doc, err := html.Parse(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	action, form := loginForm(doc)
	if action == "" {
		return nil, fmt.Errorf("Keycloak login form not found for %s at %s%s", username, resp.Request.URL.Host, resp.Request.URL.Path)
	}
	ref, err := url.Parse(action)
	if err != nil {
		return nil, err
	}
	target := resp.Request.URL.ResolveReference(ref)
	if target.Host != "keycloak.localtest.me:8080" {
		return nil, errors.New("unexpected login form host")
	}
	form.Set("username", username)
	form.Set("password", "example-password")
	req, _ = http.NewRequest(http.MethodPost, target.String(), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Sec-Fetch-Dest", "document")
	resp, err = client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("submit %s login: %w", username, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Host != "apps.localtest.me:8088" || resp.Request.URL.Path != path {
		return nil, fmt.Errorf("%s login failed: status %d, final location %s%s", username, resp.StatusCode, resp.Request.URL.Host, resp.Request.URL.Path)
	}
	return client, nil
}

func loginForm(root *html.Node) (string, url.Values) {
	var formNode *html.Node
	var find func(*html.Node)
	find = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" && attribute(n, "id") == "kc-form-login" {
			formNode = n
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			find(c)
		}
	}
	find(root)
	values := make(url.Values)
	if formNode == nil {
		return "", values
	}
	var fields func(*html.Node)
	fields = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" && attribute(n, "type") == "hidden" && attribute(n, "name") != "" {
			values.Set(attribute(n, "name"), attribute(n, "value"))
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			fields(c)
		}
	}
	fields(formNode)
	return attribute(formNode, "action"), values
}

func attribute(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func expectStatus(client *http.Client, path string, want int) error {
	req, _ := http.NewRequest(http.MethodGet, appBase+path, nil)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		return fmt.Errorf("%s: status %d, expected %d", path, resp.StatusCode, want)
	}
	return nil
}

func verifyIdentity(client *http.Client, path, username string) error {
	req, _ := http.NewRequest(http.MethodGet, appBase+path, nil)
	// Caddy must overwrite caller-supplied credentials with the token belonging
	// to its verified browser session before forwarding to the application.
	req.Header.Set("Authorization", "Bearer caller-controlled-invalid-token")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: status %d", path, resp.StatusCode)
	}
	var result struct {
		JWTValidated bool `json:"jwt_validated"`
		Claims       struct {
			Issuer   string `json:"iss"`
			Username string `json:"preferred_username"`
		} `json:"claims"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return err
	}
	if !result.JWTValidated || result.Claims.Username != username || result.Claims.Issuer != keycloakBase+"/realms/company" {
		return fmt.Errorf("%s did not validate expected original Keycloak access token", path)
	}
	return nil
}

func socket(client *http.Client, path string) (*websocket.Conn, error) {
	conn, resp, err := dialSocket(client, path)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("WebSocket %s: status %d: %w", path, resp.StatusCode, err)
		}
		return nil, err
	}
	return conn, nil
}

func dialSocket(client *http.Client, path string) (*websocket.Conn, *http.Response, error) {
	u, _ := url.Parse(appBase + path)
	headers := make(http.Header)
	for _, c := range client.Jar.Cookies(u) {
		headers.Add("Cookie", c.String())
	}
	headers.Set("Origin", appBase)
	u.Scheme = "ws"
	dialer := websocket.Dialer{NetDialContext: localDial, Proxy: localProxy, HandshakeTimeout: 10 * time.Second}
	return dialer.Dial(u.String(), headers)
}

func echo(c *websocket.Conn) error {
	c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := c.WriteMessage(websocket.TextMessage, []byte("test-message")); err != nil {
		return err
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, data, err := c.ReadMessage()
	if err != nil {
		return err
	}
	if !strings.Contains(string(data), "test-message") {
		return errors.New("unexpected WebSocket echo")
	}
	return nil
}

func expectClosed(c *websocket.Conn) error {
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, _, err := c.ReadMessage()
	if err == nil {
		return errors.New("WebSocket still open after logout")
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return errors.New("WebSocket timed out instead of closing after logout")
	}
	return nil
}

func expectReconnectDenied(client *http.Client, path string) error {
	c, resp, err := dialSocket(client, path)
	if err == nil {
		c.Close()
		return errors.New("revoked session reconnected")
	}
	if resp == nil {
		return fmt.Errorf("reconnect failed without an HTTP rejection: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("reconnect returned %d instead of 401", resp.StatusCode)
	}
	return nil
}

func logoutKeycloakUser(username string) error {
	client := newClient()
	form := url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {"admin"}, "password": {"example-admin-password"}}
	resp, err := client.PostForm(keycloakBase+"/realms/master/protocol/openid-connect/token", form)
	if err != nil {
		return err
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&token)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || token.AccessToken == "" {
		return fmt.Errorf("admin authentication failed: status %d", resp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodGet, keycloakBase+"/admin/realms/company/users?exact=true&username="+url.QueryEscape(username), nil)
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	resp, err = client.Do(req)
	if err != nil {
		return err
	}
	var users []struct {
		ID string `json:"id"`
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&users)
	resp.Body.Close()
	if err != nil || len(users) != 1 {
		return fmt.Errorf("expected one Keycloak user %s", username)
	}
	req, _ = http.NewRequest(http.MethodGet, keycloakBase+"/admin/realms/company/users/"+url.PathEscape(users[0].ID)+"/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	resp, err = client.Do(req)
	if err != nil {
		return err
	}
	var sessions []struct {
		Clients map[string]string `json:"clients"`
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&sessions)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || len(sessions) == 0 {
		return fmt.Errorf("signed-in Keycloak user %s has no active provider sessions", username)
	}
	clientPresent := false
	for _, s := range sessions {
		for _, name := range s.Clients {
			if name == "caddy" {
				clientPresent = true
			}
		}
	}
	if !clientPresent {
		return errors.New("Keycloak session does not contain the caddy client")
	}
	req, _ = http.NewRequest(http.MethodPost, keycloakBase+"/admin/realms/company/users/"+url.PathEscape(users[0].ID)+"/logout", nil)
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	resp, err = client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("Keycloak logout returned %d", resp.StatusCode)
	}
	return nil
}
