# Caddy OIDC Logout

OIDC back-channel logout and session-aware WebSocket termination for Caddy.
Reuse `relvacode/caddy-oidc` for authentication and per-application authorization;
this module revokes sessions, closes their WebSockets and rejects reconnects.

One custom Caddy binary can protect multiple applications, with different realm
roles for each application. The included build also supports forwarding the
original provider access token through a focused patch to `caddy-oidc`.

## Run the two-application example

```sh
docker compose -f examples/keycloak/compose.yaml up --build -d
```

Open <http://apps.localtest.me:8088/app1/> or
<http://apps.localtest.me:8088/app2/>. See the
[example instructions](examples/keycloak/README.md) for development accounts,
Keycloak settings and automated verification. The example includes one Caddy,
one Keycloak realm and two JWT-validating WebSocket applications.

## Build

The repository pins Caddy **v2.11.8** and `caddy-oidc` **v0.4.3**. Go 1.26 is
required. The preparation script fetches an exact upstream commit and applies
the [optional token-storage patch](patches/README.md).

```sh
./scripts/prepare-oidc.sh
go build -trimpath -o bin/caddy ./cmd/caddy
bin/caddy list-modules
bin/caddy run --config /path/to/Caddyfile
```

Or build the container:

```sh
docker build -t caddy-oidc-logout:local .
```

Mount a Caddyfile at `/etc/caddy/Caddyfile` and persist `/data`. There is no
separate authentication proxy container. Modules are compiled into Caddy, not
loaded from a mounted plugin directory. The runtime base image supplies Caddy's
container layout; its executable is replaced by the pinned v2.11.8 build.

For an existing custom Caddy build, include both modules with `xcaddy`. To enable
original-token forwarding, also replace `github.com/relvacode/caddy-oidc` with
the generated patched checkout:

```sh
xcaddy build v2.11.8 \
  --with github.com/KevinGliewe/caddy-oidc-logout=/absolute/path/to/caddy-oidc-logout \
  --with github.com/relvacode/caddy-oidc=/absolute/path/to/caddy-oidc-logout/.build/oidc
```

The logout-only integration also compiles against unpatched `caddy-oidc` v0.4.3.
It uses verified claim placeholders when the typed session is unavailable.
Original-token forwarding and ID-token logout hints need the patch.

## Configuration

Use explicit `route` blocks so authentication, revocation checks and proxying
run in the stated order. Use one `oidc` authentication handler per protected
chain. The issuer must identify the exact realm; roles are read from verified
token claims, never client-supplied identity headers.

```caddyfile
{
    oidc company {
        issuer https://login.example.com/realms/company
        client_id caddy
        client_secret {env.OIDC_CLIENT_SECRET}
        scope openid profile email
        authenticate cookie {
            name caddy
            secret {env.COOKIE_SECRET}
            same_site lax
            redirect_url /oauth2/callback
            id_claim iss aud sub sid iat exp realm_access
            retain_access_token
        }
    }
    oidc_logout {
        state_file /data/oidc-logout/sessions.db
        max_session_age 24h
        provider company {
            issuer https://login.example.com/realms/company
            client_id caddy
        }
    }
}

app1.example.com {
    handle /_oidc/backchannel {
        oidc_backchannel company
    }
    handle /logged-out {
        respond "You are logged out."
    }
    handle /logout {
        route {
            oidc company {
                allow {
                    user *
                }
            }
            oidc_signout company {
                cookie_name caddy
                redirect https://app1.example.com/logged-out
            }
        }
    }
    handle {
        route {
            oidc company {
                allow {
                    user *
                    claim realm_access.roles app1-admin
                }
            }
            oidc_session company {
                forward_access_token
            }
            reverse_proxy app1:8080 {
                transport oidc_session
            }
        }
    }
}
```

For another application, add another site/route using `claim realm_access.roles
app2-admin`, its own upstream, and the same session handler/transport. The
[complete example Caddyfile](examples/keycloak/Caddyfile) shows both applications
and their common callback endpoint. A session can own connections to both;
logout closes every matching connection across the routes.

Configure Keycloak's client with the corresponding callback and post-logout
redirect URLs. Set **Backchannel logout URL** to the public
`/_oidc/backchannel` URL, disable **Front channel logout**, and enable
**Backchannel logout session required**. Include realm roles in the ID token
using the realm-role mapper. Configure the access-token audience for the backend
API; an ID token's client audience and an API access token's audience differ.

Use a random 64-byte `COOKIE_SECRET`. Keep its value stable across reloads and
restarts. For logout-only operation, omit `retain_access_token` and
`forward_access_token`. Stock placeholder integration requires a single ID-token
audience equal to `client_id`; the patched typed-session integration also accepts
audience arrays. Identity claims must come from `id_claim`; do not override them
with UserInfo `claim` mappings.

### Directives

| Directive | Purpose |
| --- | --- |
| Global `oidc_logout` | Providers, durable state and lifetime bounds |
| `oidc_session <provider>` | Check authenticated identity/revocation and attach stream identity |
| `oidc_backchannel <provider>` | Public POST endpoint accepting a signed `logout_token` |
| `oidc_signout <provider>` | Authenticated same-origin POST logout, then provider logout redirect |
| `transport oidc_session` | Track upgraded backend streams; accepts a nested `http` transport block |

Global defaults are `max_session_age 24h`, `logout_max_age 5m`, and `clock_skew
30s`. The maximum allowed values are 30 days, one hour and five minutes
respectively. The state path defaults to `oidc-logout/sessions.db` under Caddy's
data directory. Providers require `issuer` and `client_id`; HTTP issuers require
the explicit development-only `allow_insecure_issuer` option.

The signout handler accepts `cookie_name`, `cookie_path`, `cookie_domain` and
`redirect`. Match these cookie settings to the authenticator. Use a browser form
with `method="post"` and `action="/logout"`; a cross-origin request or a missing
Origin is rejected. Local revocation and socket closure happen before contacting
the identity provider. A provider error cannot undo local logout.

`forward_access_token` overwrites `Authorization` with `Bearer <original access
token>`. The backend should verify its signature, issuer, audience and expiry.
The module does not substitute an ID token or mint a replacement JWT.

## Session lifetime and persistence

Revocation is committed to a locked bbolt database before matching streams are
closed. Duplicate logout tokens are idempotent. SID logout affects that provider
session; a subject-only logout rejects sessions issued at or before the logout
token's issuance time. Identical subjects or SIDs in other issuers/clients remain
independent. New logins with a new SID can proceed.

The database is shared across routes and overlapping Caddy configurations.
Reloading or restarting with the same data volume preserves revocations. Records
are retained for the maximum supported session lifetime (30 days plus clock
skew), so increasing a lifetime setting cannot revive an old cookie. Expired
records are periodically removed during logout processing. Deleting the data
volume deletes this history.

Connections close at their authenticated token/session deadline as well as on
logout. The token-storage extension does **not** refresh tokens automatically;
the browser starts another OIDC login after expiry. An existing provider SSO
session can complete that without a password prompt. Token storage is encrypted
and requires the same persistent Caddy storage and encryption key after restart.

## Supported scope

- One Caddy process. A shared filesystem or database alone does not deliver
  logout to other replicas; distributed event delivery is not implemented.
- Providers must include `sid`, `sub`, `iss`, `aud`, `iat` and `exp` in retained
  session claims. Keycloak is exercised by the included integration test.
- Every protected request and upgraded connection must traverse the session
  handler and tracking transport. Backends must not have a public bypass route.
- Role changes are reflected at authentication. Removing a role alone does not
  emit an OIDC logout event; terminate the provider session for immediate closure.
- Closing a tracked stream is a hard disconnect; clients may see WebSocket
  close code 1006 and must handle it. No WebSocket application messages are read
  or rewritten by the module.
- HTTP/1.1 WebSockets have live integration coverage. Caddy's HTTP/2/3 upgrade
  paths use the same backend stream, but those protocols are not yet runtime
  verified. Pin and retest Caddy upgrades.

## Verification

```sh
./scripts/prepare-oidc.sh
go test -race ./...
go vet ./...
(cd .build/oidc && go test ./...)
docker compose -f examples/keycloak/compose.yaml up --build -d
go run ./examples/e2e
```

Unit and integration tests cover logout JWT validation, invalid forms, browser
logout CSRF protection, durable revocations, replay handling, expiry,
registration/logout races, reload ownership, original JWT forwarding, and live
WebSocket closure while unrelated sessions remain connected.
