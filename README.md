# envoy-ocsp-authz

An [Envoy external authorization](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter)
(`ext_authz`) gRPC service that performs **OCSP revocation checking of the client
certificate** of an mTLS connection — the one thing Envoy itself does not do.

Envoy validates the client certificate chain during the TLS handshake and can check
revocation via **CRL**, but it has no synchronous **OCSP** check for client
certificates (it would require a blocking external call in the connection path). This
service fills that gap: Envoy forwards the verified client certificate in the
`x-forwarded-client-cert` (XFCC) header, and this service does the OCSP lookup and
tells Envoy to allow or deny the request.

It is plain Envoy `ext_authz`, so it works with any Envoy-based gateway —
[kgateway](https://kgateway.dev), Istio, Gloo, Contour, or raw Envoy.

## What it does, per request

1. Reads the client certificate from the `x-forwarded-client-cert` header (the leaf
   that Envoy wrote from the handshake).
2. Confirms the certificate was issued by the configured CA and is within its validity
   window (defense in depth; Envoy already validated the chain).
3. Performs an OCSP check against the responder in the certificate's AIA extension,
   **failing closed** on any error (network, bad signature, stale response, `unknown`).
   - The OCSP response signature is verified against the issuer (or a delegated
     responder with the `id-kp-OCSPSigning` EKU).
   - The `thisUpdate`/`nextUpdate` window is enforced with a clock-skew tolerance.
   - Responses are cached up to `nextUpdate` (bounded), so the responder is not hit on
     every request.
4. On `good`, returns **OK**. Optionally injects the verified certificate into an
   upstream header (`FORWARD_CERT_HEADER`) as URL-encoded PEM — the same format nginx
   produces in `$ssl_client_escaped_cert`, so backends that already read `ssl-client-cert`
   (Keycloak's nginx x509 lookup, API gateways, …) work unchanged.
5. On `revoked` / `unknown` / any error / missing certificate, returns **401** with
   `{"error":"invalid_client"}`.

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|---|---|---|
| `LISTEN_ADDR` | `:9191` | gRPC address of the ext_authz service |
| `METRICS_ADDR` | `:9192` | HTTP address serving `/metrics` and `/healthz` |
| `ISSUER_CA_FILE` | *(required)* | PEM of the CA that issues the client certificates |
| `FORWARD_CERT_HEADER` | *(empty)* | Header to carry the verified cert upstream (URL-encoded PEM). Empty = allow/deny only |
| `OCSP_TIMEOUT` | `5s` | Per-request timeout to the OCSP responder |
| `OCSP_CACHE_TTL_CAP` | `10m` | Cache cap; never cached beyond `nextUpdate` |
| `OCSP_MAX_RESPONSE_AGE` | `24h` | Max age of a response that carries **no** `nextUpdate` (older than this → rejected, fail-closed) |
| `OCSP_ALLOWED_HOSTS` | *(empty)* | Comma-separated allowlist of responder hosts (anti-SSRF). Empty = no restriction |
| `OCSP_CA_FILE` | *(system roots)* | CA bundle to trust for the responder's TLS (e.g. an internal PKI) |

> **Security notes:**
> - The OCSP URL comes from the certificate's AIA. Even though the issuer is validated,
>   set `OCSP_ALLOWED_HOSTS` to the responder host(s) you expect, so an unexpected AIA
>   cannot become an SSRF vector. HTTP redirects from the responder are **not** followed.
> - A delegated OCSP responder certificate is only trusted if it carries the
>   `id-kp-OCSPSigning` EKU (so a plain client certificate cannot sign OCSP responses).
> - Responses with no `nextUpdate` are bounded by `OCSP_MAX_RESPONSE_AGE`; responses with
>   no `thisUpdate` are rejected.
>
> **ext_authz timeout:** Envoy's default ext_authz timeout is **200 ms**. Set the
> gateway's request timeout for this service **above** `OCSP_TIMEOUT`, or a cache miss
> (DNS + TLS + responder round-trip) is cut off before the OCSP check completes. See the
> `requestTimeout` in [`deploy/kgateway/gateway-extension.yaml`](deploy/kgateway/gateway-extension.yaml).

## Metrics

Prometheus metrics on `METRICS_ADDR`:

- `ocsp_authz_requests_total{result}` — `good`, `revoked`, `unknown`, `no_cert`,
  `bad_issuer`, `ocsp_error`.
- `ocsp_authz_decision_seconds{result}` — decision latency (includes the OCSP round-trip
  on a cache miss).

## Quickstart (kgateway)

Wire it as a `GatewayExtension` + `TrafficPolicy` on the mTLS listener:

```yaml
apiVersion: gateway.kgateway.dev/v1alpha1
kind: GatewayExtension
metadata:
  name: ocsp-authz
spec:
  type: ExtAuth
  extAuth:
    grpcService:
      backendRef:
        name: envoy-ocsp-authz
        port: 9191
    failOpen: false        # fail closed: if the authz service is down, deny
---
apiVersion: gateway.kgateway.dev/v1alpha1
kind: TrafficPolicy
metadata:
  name: ocsp-authz
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: Gateway
      name: my-mtls-gateway
  extAuth:
    extensionRef:
      name: ocsp-authz
```

The gateway listener must forward the client cert in XFCC. With kgateway, set
`forwardClientCertDetails` to `SanitizeSet` with `cert` details on the `ListenerPolicy`
so Envoy ignores any client-supplied XFCC and writes only the handshake certificate.

See [`deploy/`](deploy/) for complete, runnable examples.

## Build & test

```bash
make test      # unit tests (self-contained: test CA + fake OCSP responder)
make build     # binary
make image     # container image
```

## CI

GitHub Actions runs `go vet`, `go test -race` and `go build` on every push and PR
(see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

## License

[Apache 2.0](LICENSE).
