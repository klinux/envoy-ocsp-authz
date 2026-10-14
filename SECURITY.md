# Security Policy

`envoy-ocsp-authz` is an authorization component. Please report vulnerabilities privately.

## Reporting

Use **GitHub private vulnerability reporting** (the "Report a vulnerability" button under
the repository's *Security* tab). Please do **not** open a public issue for a security bug.

Include: affected version/commit, a description, and a reproduction if possible.

We aim to acknowledge a report within a few business days and to ship a fix or mitigation
for confirmed issues as soon as practical, coordinating disclosure with the reporter.

## Supported versions

The latest `v0.x` release line receives security fixes. Pre-1.0: the API and behavior may
change between minor versions.

## Scope notes

- The service **fails closed**: any error in certificate parsing or OCSP checking results
  in a `401`. Report cases where a request is wrongly **allowed**.
- Trust assumptions: the issuing CA is configured by the operator; the OCSP responder URL
  comes from the certificate AIA and should be constrained with `OCSP_ALLOWED_HOSTS`.
