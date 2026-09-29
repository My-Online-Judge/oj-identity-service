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

## Build and test

`oj-common` must be installed first (`./mvnw install` in the sibling `oj-common` repo).

    ./mvnw verify

Docker builds compile `oj-common` from the named build context:
`docker build --build-context oj-common=../oj-common .`
