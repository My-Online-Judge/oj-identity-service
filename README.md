# oj-identity-service

Identity for My Online Judge: password and Google login, refresh and logout, users, roles,
permissions, login attempts and IP/device bans. It issues the RS256 access tokens every other
service verifies through its `/.well-known/jwks.json`. Split out of judge-api in sub-project 1b;
the code kept its packages (`auth`, `user`, `role`, `permission`, `security`).

| Port | Purpose |
|---|---|
| 8000 | API — reachable only inside oj-net; the api-gateway routes `/api/v1/{auth,users,roles,permissions,security}/**` here |
| 8081 | actuator: `/actuator/health`, `/actuator/prometheus` (dev/prod profiles) |

Configuration comes from `judge-deployment/.env.identity` (see `.env.identity.example` there): its
own Postgres (`identity-db`, schema by Flyway `V1` + `V2`), the JWT RSA key pair and lifetimes,
Google OAuth, Redis.

## Login limits

- `OJ_LOGIN_IP_LIMIT` (`oj.login.ip-limit`, default 30 failed password checks per address in 5 minutes) and
  `OJ_LOGIN_ACCOUNT_LIMIT` (`oj.login.account-limit`, default 50 attempts per account in an hour) must be at least 1:
  a value below 1 makes the service refuse to start with an `IllegalStateException` naming the setting.
- A password change takes its place before BCrypt runs: 5 per user in 5 minutes, then one probe, and everything after
  it is refused 429 `PASSWORD_CHANGE_RATE_LIMITED` (Retry-After 2 s while the probe is in flight). The fifth wrong
  current password locks password changes for 15 minutes. So a burst of guesses gets at most 6 BCrypt checks.

## Build and test

`oj-common` must be installed first (`./mvnw install` in the sibling `oj-common` repo).

    ./mvnw verify

Docker builds compile `oj-common` from the named build context:
`docker build --build-context oj-common=../oj-common .`
