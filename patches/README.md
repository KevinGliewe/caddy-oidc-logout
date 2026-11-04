# Optional caddy-oidc token retention

The patch applies to [`relvacode/caddy-oidc v0.4.3`](https://github.com/relvacode/caddy-oidc/tree/v0.4.3), commit `4552b569c6b9920c5d37001c856d26be108bb8c7`. The upstream source and its MIT license remain in the generated checkout; this repository does not contain a copied authentication implementation.

Run `sh scripts/prepare-oidc.sh` to create `.build/oidc`. The script verifies the exact upstream commit and refuses to overwrite a checkout containing a different patch. The Docker build and development instructions use this local checkout as the replacement for `github.com/relvacode/caddy-oidc`.

The patch makes two focused changes:

- Forward the authenticated request context to downstream middleware. Upstream v0.4.3 otherwise exposes the typed session only inside its own authorization checks.
- Add the opt-in cookie option `retain_access_token`. It stores the original access token and ID token in encrypted, authenticated records in Caddy storage. The session cookie contains only an opaque random reference and selected user claims. Trusted middleware reads them through `interface { OIDCTokens() (string, string) }`. They are not exposed as logging placeholders or forwarded automatically.

```caddyfile
authenticate cookie {
    name caddy
    secret {env.COOKIE_SECRET}
    id_claim iss sub sid iat exp aud realm_access
    retain_access_token
}
```

With retention enabled, session expiry is the earliest of the ID token expiry, access token expiry (including an earlier JWT `exp`) and an optional shorter `max_age`. Missing access-token expiry, unusable tokens and oversized cookies fail login. Previously issued cookies without a token reference require another login. Missing or invalid stored records fail authentication. Disabling retention hides tokens from old cookies as well.

**Automatic token refresh is not implemented.** Refresh tokens are never stored. At expiry, the browser must make another interactive OIDC login request; an existing provider SSO session may complete that flow without asking for credentials. WebSocket clients must handle disconnection and reopen the application login flow.

Both JWTs are stored server-side, so their size does not consume the browser cookie budget. Encrypted token records are capped at 64 KiB; the browser cookie, containing the reference and selected claims, remains capped at 4 KiB. Oversized records or cookies fail login and are never truncated.

Token records use the configured Caddy storage backend (`/data/caddy` in the supplied Docker image) and the cookie secret for encryption and authentication. Preserve both storage and the secret across restarts. Each record is bound to a cryptographically random 256-bit reference, the complete authenticated claims and user ID, and the exact session expiry. Copying or altering a record cannot change that binding. Raw credentials are excluded from cookie serialization and logging placeholders.

Expired records are removed lazily on subsequent logins: at most once per minute per handler, for up to 128 expiry buckets and two seconds per cleanup pass. Authentication always enforces expiry independently of cleanup. Revoked records may remain encrypted on disk until expiry; the logout module rejects their sessions immediately. Rotating the cookie secret invalidates existing cookies and stored credentials.

Regression tests included in the patch cover encryption, persistence across reprovisioning, swapped references, tampering, key rotation, missing or oversized records, bounded cleanup, cookie issuance failures, token expiry, disabled retention and propagation of the verified session context. Run them from `.build/oidc` using `go test ./authenticator ./session ./`.

The logout module can also be built with unpatched caddy-oidc for logout enforcement through verified claim placeholders. Original-token forwarding requires this patch.
