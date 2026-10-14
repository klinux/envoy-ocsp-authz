package authz

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// O Envoy injeta o certificado do cliente no header x-forwarded-client-cert (XFCC).
// Formato: elementos separados por vírgula (um por hop), cada um com pares k=v separados
// por ';'. O campo "Cert" é o PEM do leaf URL-encoded; "Chain" (se presente) traz a cadeia.
// Com forwardClientCertDetails em SanitizeSet, o Envoy descarta o que o cliente mandar e
// escreve só os detalhes do handshake atual — então confiamos no primeiro elemento.
const XFCCHeader = "x-forwarded-client-cert"

var errNoCert = errors.New("XFCC sem campo Cert")

// LeafFromXFCC extrai o certificado do cliente (leaf) do valor do header XFCC.
func LeafFromXFCC(xfcc string) (*x509.Certificate, error) {
	if strings.TrimSpace(xfcc) == "" {
		return nil, errors.New("XFCC vazio")
	}
	// Primeiro elemento (o hop mais próximo = o handshake neste gateway).
	element := xfcc
	if i := strings.IndexByte(xfcc, ','); i >= 0 {
		element = xfcc[:i]
	}
	certPEM, ok := field(element, "Cert")
	if !ok {
		return nil, errNoCert
	}
	dec, err := url.QueryUnescape(certPEM)
	if err != nil {
		return nil, fmt.Errorf("URL-decode do Cert: %w", err)
	}
	block, _ := pem.Decode([]byte(dec))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("Cert do XFCC não é um PEM de certificado")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse do certificado: %w", err)
	}
	return cert, nil
}

// field devolve o valor de uma chave (case-insensitive) de um elemento XFCC, lidando com
// valor entre aspas. Ex.: field(`By=...;Cert="-----BEGIN..."`, "Cert").
func field(element, key string) (string, bool) {
	for _, kv := range splitTopLevel(element) {
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(kv[:eq]), key) {
			continue
		}
		val := strings.TrimSpace(kv[eq+1:])
		val = strings.Trim(val, `"`)
		return val, true
	}
	return "", false
}

// splitTopLevel separa por ';' respeitando aspas (um Subject pode conter ';' entre aspas).
func splitTopLevel(s string) []string {
	var out []string
	var b strings.Builder
	inQuotes := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuotes = !inQuotes
			b.WriteRune(r)
		case r == ';' && !inQuotes:
			out = append(out, b.String())
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}
