# build
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/authz ./cmd/authz

# runtime: distroless nonroot, sem shell
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/authz /authz
LABEL org.opencontainers.image.source="https://github.com/klinux/envoy-ocsp-authz" \
      org.opencontainers.image.description="Envoy ext_authz for OCSP revocation of mTLS client certificates" \
      org.opencontainers.image.licenses="Apache-2.0"
EXPOSE 9191 9192
USER nonroot:nonroot
ENTRYPOINT ["/authz"]
