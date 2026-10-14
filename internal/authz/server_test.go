package authz

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc/codes"

	"github.com/klinux/envoy-ocsp-authz/internal/ocsp"
)

type fakeChecker struct {
	status ocsp.Status
	err    error
}

func (f fakeChecker) Check(context.Context, *x509.Certificate, *x509.Certificate) (ocsp.Status, error) {
	return f.status, f.err
}

func testCAandLeaf(t *testing.T) (*x509.Certificate, *x509.Certificate) {
	t.Helper()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "int-abc"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	leaf, _ := x509.ParseCertificate(leafDER)
	return ca, leaf
}

func xfccFor(leaf *x509.Certificate) string {
	p := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	return `Cert="` + url.QueryEscape(string(p)) + `"`
}

func checkReq(xfcc string) *authv3.CheckRequest {
	return &authv3.CheckRequest{Attributes: &authv3.AttributeContext{
		Request: &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{
			Headers: map[string]string{XFCCHeader: xfcc},
		}},
	}}
}

func TestDecide_GoodAllowsAndSetsHeader(t *testing.T) {
	ca, leaf := testCAandLeaf(t)
	s := NewServer(Config{Issuer: ca, Checker: fakeChecker{status: ocsp.StatusGood}, HeaderName: "ssl-client-cert"})
	resp, _ := s.Check(context.Background(), checkReq(xfccFor(leaf)))
	if resp.GetStatus().GetCode() != int32(codes.OK) {
		t.Fatalf("esperava OK, veio %d", resp.GetStatus().GetCode())
	}
	hdrs := resp.GetOkResponse().GetHeaders()
	if len(hdrs) != 1 || hdrs[0].GetHeader().GetKey() != "ssl-client-cert" {
		t.Fatalf("esperava header ssl-client-cert, veio %v", hdrs)
	}
	if hdrs[0].GetAppendAction() != corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD {
		t.Fatal("header do cliente deve ser sobrescrito")
	}
}

func TestDecide_RevokedDenies(t *testing.T) {
	ca, leaf := testCAandLeaf(t)
	s := NewServer(Config{Issuer: ca, Checker: fakeChecker{status: ocsp.StatusRevoked}})
	resp, _ := s.Check(context.Background(), checkReq(xfccFor(leaf)))
	assertDenied401(t, resp)
}

func TestDecide_OCSPErrorFailsClosed(t *testing.T) {
	ca, leaf := testCAandLeaf(t)
	s := NewServer(Config{Issuer: ca, Checker: fakeChecker{err: context.DeadlineExceeded}})
	resp, _ := s.Check(context.Background(), checkReq(xfccFor(leaf)))
	assertDenied401(t, resp)
}

func TestDecide_NoCertDenies(t *testing.T) {
	ca, _ := testCAandLeaf(t)
	s := NewServer(Config{Issuer: ca, Checker: fakeChecker{status: ocsp.StatusGood}})
	resp, _ := s.Check(context.Background(), checkReq(""))
	assertDenied401(t, resp)
}

func TestDecide_WrongIssuerDenies(t *testing.T) {
	_, leaf := testCAandLeaf(t)
	otherCA, _ := testCAandLeaf(t) // CA diferente da que emitiu o leaf
	s := NewServer(Config{Issuer: otherCA, Checker: fakeChecker{status: ocsp.StatusGood}})
	resp, _ := s.Check(context.Background(), checkReq(xfccFor(leaf)))
	assertDenied401(t, resp)
}

func assertDenied401(t *testing.T, resp *authv3.CheckResponse) {
	t.Helper()
	if resp.GetStatus().GetCode() != int32(codes.PermissionDenied) {
		t.Fatalf("esperava PermissionDenied, veio %d", resp.GetStatus().GetCode())
	}
	den := resp.GetDeniedResponse()
	if den.GetStatus().GetCode() != 401 {
		t.Fatalf("esperava 401, veio %v", den.GetStatus().GetCode())
	}
	if den.GetBody() != `{"error":"invalid_client"}` {
		t.Fatalf("corpo inesperado: %q", den.GetBody())
	}
}
