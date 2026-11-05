# spring-security-jwt

Stateless Spring Security where **every REST request must carry `Authorization: Bearer <JWT>`**.

| | |
|---|---|
| Java | 25 (Gradle toolchain) |
| Spring Boot | 3.5.16 (Spring Security 6.5) |
| Gradle | 9.8.2 (wrapper included) |
| JWT library | Nimbus JOSE+JWT, via `spring-boot-starter-oauth2-resource-server` |
| Signing | HS256 (shared secret) |
| API docs | springdoc-openapi 2.8.17 (Swagger UI; the 2.8.x line matches Boot 3.5) |

## Run

```powershell
.\gradlew.bat test       # 19 integration tests: every security path, account status, Swagger exposure
.\gradlew.bat bootRun    # http://localhost:8080
```

## Swagger UI

Open **http://localhost:8080/swagger-ui.html** (OpenAPI JSON: `/v3/api-docs`). Both are public; the APIs they describe are not.

1. **Authentication → POST /api/auth/token** → *Try it out* → body `{"username":"admin","password":"admin123"}` → *Execute*.
2. Copy `access_token` from the response.
3. Click **Authorize** (top right), paste the token **without** the `Bearer ` prefix, click *Authorize*.
4. Every *Try it out* call now sends `Authorization: Bearer <token>`. Try `crsardar`'s token on `/api/admin/stats` to see the 403.

How it's wired (`config/OpenApiConfig`): a global `@SecurityScheme` of type HTTP bearer/JWT creates the
Authorize button and the lock icons. `@SecurityRequirements` with no arguments on the login endpoint removes the lock from that one operation.
`SecurityConfig` permits `/swagger-ui.html`, `/swagger-ui/**` and `/v3/api-docs/**`.
In production, either keep these behind auth or turn them off with `springdoc.api-docs.enabled=false`.

## Users (the "user table")

Predefined in `user/InMemoryUserAccountRepository`:

| Username | Password | Roles | Status |
|---|---|---|---|
| `crsardar` | `Chitta@123` | USER | ACTIVE |
| `admin` | `admin123` | USER, ADMIN | ACTIVE |
| `bob` | `bob123` | USER | DISABLED (login refused) |

A JWT is accepted only if it is correctly signed, unexpired, from our issuer, **and its `sub` exists
in this table with status `ACTIVE`**. The last check runs on every request, so disabling or locking an account
locks out tokens that were already issued, starting with the next request.

```powershell
# 1. No token -> 401 + WWW-Authenticate: Bearer
curl.exe -i http://localhost:8080/api/hello

# 2. Get a token
$t = (Invoke-RestMethod -Method Post http://localhost:8080/api/auth/token `
       -ContentType 'application/json' -Body '{"username":"crsardar","password":"Chitta@123"}').access_token

# 3. Call with the header -> 200
curl.exe -H "Authorization: Bearer $t" http://localhost:8080/api/hello

# 4. Valid token, wrong role -> 403
curl.exe -i -H "Authorization: Bearer $t" http://localhost:8080/api/admin/stats

# 5. Admin locks crsardar -> the SAME token (still signed, unexpired) now gets 401
$a = (Invoke-RestMethod -Method Post http://localhost:8080/api/auth/token `
       -ContentType 'application/json' -Body '{"username":"admin","password":"admin123"}').access_token
Invoke-RestMethod -Method Patch http://localhost:8080/api/admin/users/crsardar/status `
       -Headers @{Authorization="Bearer $a"} -ContentType 'application/json' -Body '{"status":"LOCKED"}'
curl.exe -i -H "Authorization: Bearer $t" http://localhost:8080/api/hello      # 401 invalid_token

# 6. Reactivate -> the token works again (it was never "revoked", only the account check changed)
Invoke-RestMethod -Method Patch http://localhost:8080/api/admin/users/crsardar/status `
       -Headers @{Authorization="Bearer $a"} -ContentType 'application/json' -Body '{"status":"ACTIVE"}'
```

## Endpoints

| Method | Path | Access | Enforced by |
|---|---|---|---|
| POST | `/api/auth/token` | public | `permitAll()` |
| GET | `/api/hello` | any valid JWT | `anyRequest().authenticated()` |
| GET | `/api/admin/stats` | ROLE_ADMIN | URL rule `/api/admin/**` |
| DELETE | `/api/reports/{id}` | ROLE_ADMIN | `@PreAuthorize` (method security) |
| GET | `/api/admin/users` | ROLE_ADMIN | URL rule `/api/admin/**` |
| PATCH | `/api/admin/users/{username}/status` | ROLE_ADMIN | URL rule `/api/admin/**` |
| GET | `/swagger-ui.html`, `/v3/api-docs` | public | `permitAll()` |

## How a request flows

```
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
  │
  ├─ BearerTokenAuthenticationFilter    pulls the token out of the header
  ├─ JwtAuthenticationProvider
  │    └─ JwtDecoder (Nimbus)           1. verifies HS256 signature
  │                                     2. exp/nbf (60s skew), iss
  │                                     3. ActiveAccountJwtValidator: sub in user table AND status ACTIVE
  ├─ JwtAuthenticationConverter         "roles": ["ADMIN"]  ->  ROLE_ADMIN
  ├─ SecurityContextHolder              JwtAuthenticationToken, this request only (STATELESS)
  ├─ AuthorizationFilter                URL rules  -> 403 if role missing
  └─ @PreAuthorize                      method rules
```

Failures: no or invalid token → **401** with `WWW-Authenticate: Bearer error="invalid_token", ...`
(from `BearerTokenAuthenticationEntryPoint`). Authenticated but missing the role → **403**.

## Code map

- `config/SecurityConfig` – filter chain, `JwtDecoder` (with the validators), `JwtEncoder`, role converter
- `user/ActiveAccountJwtValidator` – the per-request "account exists and is ACTIVE" check
- `user/UserAccountRepository` + `InMemoryUserAccountRepository` – the user table (swap in JPA/MyBatis)
- `user/UserAccountDetailsService` – login reads the same table; DISABLED/LOCKED accounts are refused
- `user/UserAdminController` – list users, change status (admin only)
- `config/OpenApiConfig` – Swagger/OpenAPI metadata and the bearer-JWT security scheme
- `config/JwtProperties` – `app.jwt.secret / issuer / ttl` (a record bound with `@ConfigurationProperties`)
- `auth/TokenService` – builds and signs the claims (`iss, sub, iat, exp, roles`)
- `auth/AuthController` – `POST /api/auth/token` (username/password → JWT)
- `api/GreetingController` – protected endpoints; reads claims via `@AuthenticationPrincipal Jwt`

## Interview talking points

- **Why the resource-server starter instead of a custom `OncePerRequestFilter` + jjwt?**
  It's Spring's supported path. Signature/expiry validation, the 401 challenge format (RFC 6750)
  and the error handling all come built in, with less hand-written security code to get wrong.
  A custom filter still works, but then you own parsing, validation, exceptions and the entry point yourself.
- **HS256 vs RS256:** HS256 uses one shared secret, so anyone who can verify a token can also mint one.
  That's fine when a single service both issues and checks tokens. With several services or an
  external IdP (Entra ID, Keycloak, Auth0), use RS256/ES256 and point to a JWKS:
  `spring.security.oauth2.resourceserver.jwt.issuer-uri=...` and delete the decoder/encoder beans.
- **Why CSRF is disabled:** CSRF attacks ride on credentials the browser sends automatically (cookies).
  A header token isn't sent automatically, and the session is STATELESS. If you store the JWT in a cookie, CSRF protection is needed again.
- **Revocation:** a JWT stays valid until `exp`. Mitigations: short TTL (15 min here) + refresh tokens,
  a `jti` denylist in Redis, token introspection (opaque tokens), or what this project does:
  **check the account's status on every request**, which revokes access per user rather than per token.
- **Why an `OAuth2TokenValidator` rather than a filter or converter for the account check?** It runs
  inside `JwtDecoder.decode()` *after* the signature check, so forged tokens never cost a DB lookup.
  A failure becomes the standard 401 `invalid_token`, the same as an expired token, so nothing else needs wiring.
- **Cost of the check:** one user lookup per request makes this partly stateful. At scale, put a short-TTL
  cache (Caffeine/Redis, ~30-60s) in front of it. The trade-off is that revocation can take up to the TTL to apply.
  Use a primary-key lookup on `username`, never a scan.
- **Roles still come from the token.** If a user's roles change, old tokens keep the old roles until they expire.
  If that matters, load authorities from the table in the converter too.
- **Never put secrets in the payload.** It's only Base64URL-encoded, not encrypted (use JWE if you need encryption).
- **Secret management:** the key comes from `JWT_SECRET` (in production, Azure Key Vault). The dev default is only for local runs.
- **`ROLE_` prefix:** `hasRole("ADMIN")` checks for authority `ROLE_ADMIN`; the converter adds the prefix
  to the raw `roles` claim. By default Spring would read `scope`/`scp` and use the `SCOPE_` prefix.

## Notes

- Building on Gradle 9 prints one deprecation warning (`Configuration.setVisible`). It comes from the
  Spring Boot 3.5 / dependency-management Gradle plugins, not this build script. It's harmless until Gradle 11.
