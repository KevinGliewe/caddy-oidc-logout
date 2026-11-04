# Two applications, one Caddy, one Keycloak realm

This development example runs one Caddy container, Keycloak, and two demonstration
applications. Both applications receive the original Keycloak access JWT and
independently verify its signature, issuer, audience and realm role. Caddy also
enforces each application's realm role before forwarding the request.

From the repository root:

```sh
docker compose -f examples/keycloak/compose.yaml up --build -d
```

Open <http://apps.localtest.me:8088/app1/> or
<http://apps.localtest.me:8088/app2/>. `*.localtest.me` resolves to `127.0.0.1`.
If your DNS blocks loopback answers, add this local hosts entry:

```text
127.0.0.1 apps.localtest.me keycloak.localtest.me
```

| Username | Password | Realm roles | Access |
| --- | --- | --- | --- |
| alice | example-password | app1-admin | Application 1 |
| bob | example-password | app2-admin | Application 2 |
| charlie | example-password | app1-admin, app2-admin | Both applications |

The realm is `company`. These are **realm roles**, not client roles or groups.
The Keycloak administration console is <http://keycloak.localtest.me:8080/admin/>,
with username `admin` and password `example-admin-password`.

Log in as `charlie` and open both applications. Each page opens a WebSocket.
Logging out closes both connections for that session. Alternatively, open
Keycloak's administration console, select the `company` realm, find `charlie`,
and sign out the user's sessions. Keycloak sends a signed back-channel logout
request to Caddy; Caddy closes the associated connections and rejects their old
cookies. A different user's connections remain active.

Run the automated browser-login and WebSocket check after starting the stack
(Go 1.26 or newer is required on the host):

```sh
./scripts/prepare-oidc.sh
go run ./examples/e2e
```

The check signs in through the real authorization-code flow, verifies both
applications' JWT validation and separate role rules, opens multiple WebSockets,
logs a user out through Keycloak's administrative API, and verifies disconnection
and reconnect rejection while another user's socket stays connected. It also
exercises local browser logout. The test uses only the development accounts above.

The example uses HTTP, fixed development passwords and a fixed cookie encryption
key. For deployment, use HTTPS, remove `insecure` and `allow_insecure_issuer`,
replace the passwords and cookie/client secrets, and set the real issuer,
callback and logout URLs. Keep `/data` persistent to retain revocation state.
Only Caddy and Keycloak publish ports; the application containers are reachable
through Caddy on the Docker network.

The initial token-forwarding implementation expires the browser session when
its access token expires; it does not refresh tokens automatically. Log in again
after expiry. An existing Keycloak SSO session can make that login transparent.
Changing a user's roles alone does not emit a back-channel logout event; explicitly
end their Keycloak session when immediate disconnection is required.

Remove the development environment with:

```sh
docker compose -f examples/keycloak/compose.yaml down -v
```

`-v` deletes this example's Caddy data, including its revocation history.
