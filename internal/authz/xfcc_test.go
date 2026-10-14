package authz

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"
)

func sampleCertPEM(t *testing.T) (string, *x509.Certificate) {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "int-abc"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	c, _ := x509.ParseCertificate(der)
	p := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return string(p), c
}

func TestLeafFromXFCC(t *testing.T) {
	pemStr, want := sampleCertPEM(t)
	enc := url.QueryEscape(pemStr)
	xfcc := `By=spiffe://x;Hash=abc;Cert="` + enc + `";Subject="CN=int-abc"`
	got, err := LeafFromXFCC(xfcc)
	if err != nil {
		t.Fatal(err)
	}
	if got.SerialNumber.Cmp(want.SerialNumber) != 0 {
		t.Fatalf("serial diferente: %v vs %v", got.SerialNumber, want.SerialNumber)
	}
}

func TestLeafFromXFCC_FirstElementOnly(t *testing.T) {
	pemStr, _ := sampleCertPEM(t)
	enc := url.QueryEscape(pemStr)
	// Dois hops; pegamos o primeiro (o handshake neste gateway).
	xfcc := `Cert="` + enc + `",By=other;Cert="lixo"`
	if _, err := LeafFromXFCC(xfcc); err != nil {
		t.Fatalf("devia parsear o primeiro elemento: %v", err)
	}
}

func TestLeafFromXFCC_Errors(t *testing.T) {
	for _, tc := range []string{"", `By=x;Hash=y`, `Cert="nao-e-pem"`} {
		if _, err := LeafFromXFCC(tc); err == nil {
			t.Fatalf("esperava erro para %q", tc)
		}
	}
}
