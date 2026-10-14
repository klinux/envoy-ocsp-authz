# Changelog

## v0.2.0

- Add `OCSP_RESPONDER_URL`: override the responder so the service ignores the certificate's
  AIA and always queries a fixed endpoint — the equivalent of nginx's `ssl_ocsp_responder`.
  Useful when client certificates carry no AIA, or to force a specific responder such as a
  Vault active-node OCSP endpoint. When set, the host allowlist does not apply (the URL is
  trusted config, not taken from the certificate).

## v0.1.0 — first release

Envoy `ext_authz` (gRPC) service that performs OCSP revocation checking of the mTLS client
certificate — the check Envoy itself does not do.

- Reads the client certificate from the `x-forwarded-client-cert` (XFCC) header.
- Confirms the certificate was issued by the configured CA and is in its validity window.
- OCSP check against the responder in the certificate AIA, **fail-closed**:
  - OCSP response signature verified against the issuer or a delegated responder that
    carries the `id-kp-OCSPSigning` EKU;
  - `thisUpdate`/`nextUpdate` window enforced; responses without `nextUpdate` bounded by
    `OCSP_MAX_RESPONSE_AGE`;
  - responder host allowlist (`OCSP_ALLOWED_HOSTS`) and no HTTP redirects (anti-SSRF);
  - bounded in-memory cache up to `nextUpdate`.
- Optional: forwards the verified certificate upstream as URL-encoded PEM
  (`$ssl_client_escaped_cert` format) via `FORWARD_CERT_HEADER`.
- Deploy examples for kgateway (`GatewayExtension` / `TrafficPolicy` / `ListenerPolicy`).
- Multi-arch image published to `ghcr.io/klinux/envoy-ocsp-authz` with provenance + SBOM.
