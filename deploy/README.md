# Deploy

- `base/` — o serviço (Deployment com 2 réplicas, Service, PDB, ServiceAccount),
  genérico. Monte a imagem real e o Secret `envoy-ocsp-authz-issuer-ca` (chave
  `issuer-ca.pem` com a CA emissora dos certs de cliente) num overlay seu.
- `kgateway/` — exemplo de como ligar ao kgateway: `GatewayExtension` (ext_authz),
  `TrafficPolicy` (aplica ao Gateway) e `ListenerPolicy` (valida a cadeia + monta o
  XFCC com `SanitizeSet`, para o cliente não forjar o header).

## Overlay mínimo

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: kgateway-system
resources:
  - ../base
  - ../kgateway
images:
  - name: envoy-ocsp-authz:dev
    newName: your-registry/envoy-ocsp-authz
    newTag: v0.1.0
patches:
  - target: { kind: Deployment, name: envoy-ocsp-authz }
    patch: |
      - op: add
        path: /spec/template/spec/containers/0/env/-
        value: { name: FORWARD_CERT_HEADER, value: "ssl-client-cert" }
      - op: add
        path: /spec/template/spec/containers/0/env/-
        value: { name: OCSP_ALLOWED_HOSTS, value: "ocsp.your-pki.example" }
```

O Secret da CA emissora (e, se o responder OCSP tiver TLS de uma PKI interna, o
`OCSP_CA_FILE` apontando para o bundle dessa PKI) ficam no seu overlay — este repo não
carrega nada específico de ambiente.

## Teste de integração (ponta a ponta, contra um Vault real)

Em `internal/authz/integration_test.go` (build tag `integration`, pulado no CI). Emite
certs frescos, revoga um, e roda a matriz (válido→allow+header, cache hit, revogado→401,
header vazio→sem injeção, responder morto→fail-closed) contra o responder OCSP do Vault:

```bash
VAULT_ADDR=https://vault.stage.cora.local \
VAULT_TOKEN="$(cat ~/.vault-stage.token)" \
VAULT_PKI=cora_int_direta_pki VAULT_ROLE=cora-integration \
go test -tags integration -run TestE2E -v ./internal/authz/
```
