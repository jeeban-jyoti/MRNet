# MRNet auth service

The authentication backend for MRNet, built from the design doc
"MRNet Auth Service: Single-Region Design". It serves six endpoints
(signup, signin, signout, validate, renew, password change) and runs as
independent regions that can each sign in, renew and validate any user.

Everything runs on one machine with Docker Compose: two regions (`ap1`, `eu1`)
and a 3-node CockroachDB for the global email registry, 41 containers in all.

## Run it

Needs Docker, Go 1.26 and Python 3.

```sh
make up      # generate local secrets, build the image, start both regions
make e2e     # end-to-end tests against both regions
make test    # unit tests (no Docker needed)
make bench   # token verify and Argon2id benchmarks
make down    # stop (keeps data); `make reset` also deletes all data
```

Gateways: `https://localhost:8443` (ap1) and `https://localhost:9443` (eu1),
TLS 1.3 with a self-signed certificate (use `curl -k`). CockroachDB console:
`http://localhost:8090`.

```sh
curl -k https://localhost:8443/v1/signup \
  -d '{"email":"me@example.com","password":"orbiting-quokka-42","device_id":"quest-3"}'
curl -k https://localhost:9443/v1/token/validate -d '{"access_token":"<from above>"}'
```

## API

All JSON over HTTPS. Every token-issuing call returns
`access_token, access_expires_in, refresh_token, refresh_expires_in`.

| Endpoint | Request | Success | Failures |
|---|---|---|---|
| `POST /v1/signup` | email, password, display_name, device_id | 201, user_id + pair | 409 email_taken, 422 weak/breached password |
| `POST /v1/signin` | email, password, device_id | 200, pair | 401 invalid_credentials (same body for unknown email), 429 + Retry-After |
| `POST /v1/signout` | refresh_token; or `all_devices: true` + Bearer | 204 always | |
| `POST /v1/token/validate` | access_token, optional required_scope | 200, sub, sid, scope, exp, iss | 401 expired/revoked/invalid, 403 insufficient_scope |
| `POST /v1/token/renew` | refresh_token | 200, new pair | 401 expired/revoked/reused, 503 if the session's region is down |
| `POST /v1/password/change` | Bearer, current_password, new_password | 200, new pair for this device | 401 wrong_password, 422 weak password |
| `GET /.well-known/jwks.json` | | public keys | |

## Layout

One Go module, one binary (`cmd/mrnet`), one image; the first argument picks the component.

Clients reach the gateway over HTTPS/JSON. Everything behind it calls each
other over gRPC (port 9090), defined in `api/authv1/internal.proto`:
`Hasher` (Hash, Verify), `Sessions` (TakeSession, for moving a session between
regions) and `Accounts` (GetUserByEmail and ChangePassword, served by the
user's home region). Port 8080 on each service carries its public HTTP
endpoints and health checks. Regenerate the Go code with `make proto`.

| Component | Package | Role in the design |
|---|---|---|
| gateway | `internal/svc/gateway` | TLS 1.3 + HTTP/2, per-IP rate limit, routes by path (Envoy's job in production) |
| validator | `internal/svc/validator` | validate from memory: JWKS of every region, LRU of verified tokens, revocation list fed by Kafka; loads a Redis snapshot then catches up on Kafka before reporting ready |
| token | `internal/svc/token` | signin, renew, signout, JWKS, and the internal session-move endpoint |
| hasher | `internal/svc/hasher` | Argon2id (m=19 MiB, t=2, p=1) with a pepper; bounded workers with a 500 ms queue deadline, 429 when full |
| account | `internal/svc/account` | signup, password_change (forwarded to the home region), credentials outbox relay |
| replicator | `internal/svc/replicator` | copies credentials and revocations in from every other region's Kafka |

Shared code: `tokens` (EdDSA JWTs, JWKS, refresh-token format), `sessions`
(Redis Cluster Lua scripts), `revocation`, `keys` (KMS-wrapped Ed25519 keys,
30-day rotation), `users` (PostgreSQL + outbox), `registry` (CockroachDB),
`ratelimit`, `password` (length + k-anonymity breach check), `events` (Kafka).

Per region: PostgreSQL primary + streaming read replica, Redis Cluster
(3 primaries + 3 replicas, AOF every second) for sessions and revocations, a
separate Redis for rate limits, and a Kafka broker.

## How the key flows work

**Renew.** One Lua script on the user's shard compares the presented secret's
hash. Current: rotate, keep the old hash as `prev` for 10 s. Matches `prev`
within 10 s: a client retry, and the same new refresh token comes back,
because the next secret is derived as HMAC(rotation key, old secret) instead of
being stored. Anything else: the token was replayed, so the session is deleted
and a revocation goes out to every validator.

**Cross-region.** Each user has a home region (recorded in the global registry
at signup). Credentials flow out through a transactional outbox → Kafka → each
other region's replicator. Signin works anywhere from the local copy, falling
back to the home region for an account seconds old. A renew in a different
region moves the session there with one atomic take-and-delete call.
Password change is forwarded home, which bumps `credential_version` and
publishes a user-level revocation that deletes older sessions in every region.
Signout of a session that lives elsewhere is sent there through Kafka, and that
region checks the secret before signing it out.

## Differences from the production design

These are deliberate simplifications for one laptop:

- **Gateway** is a small Go reverse proxy with a self-signed certificate, not Envoy.
- **KMS** is simulated: keys are wrapped with AES-256-GCM under a master key from
  `deploy/.env` (generated by `make up`, never committed).
- **Debezium** is replaced by a transactional outbox the account service relays to Kafka.
- **Kafka mirroring** is done by the replicator consuming the other region's
  Kafka directly, instead of MirrorMaker.
- **Breach check** queries a local stand-in for the Have I Been Pwned range API
  (served by the hasher, with a short list of common passwords).
- **Scale**: one instance of each service per region, 3+3 Redis nodes instead
  of 12+12, one Kafka broker instead of 6. Add replicas with
  `docker compose -f deploy/compose.yaml up -d --scale eu1-validator=3`.
- **Service-to-service auth** is a shared secret in gRPC metadata instead of mTLS.
- **Per-IP limits** are raised in the local stack, because every test client shares one IP.

## Benchmarks (Apple M-series laptop, 10 cores)

| | Result | Design assumption |
|---|---|---|
| Access-token verify, no cache | 7.6 µs/op across 10 cores (about 13,000/s per core) | 8,000/s per vCPU |
| Argon2id hash | 23 ms per hash per core | 15 ms |

Go meets the validator target, so a Rust rewrite of the validator is not
needed on these numbers. The hasher is slower than assumed; benchmark on the
target servers before sizing the pool, and compare against a Rust Argon2id
if it stays above 15 ms.

## Changing the topology

`deploy/compose.yaml` is generated. Edit `deploy/gen_compose.py` (for example
add a third region to `REGIONS`), then run `make up`.
