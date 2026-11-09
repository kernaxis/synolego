package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/go-acme/lego/v4/certcrypto"
)

func TestPrivateKeyForCSR(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"example.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		pem     []byte
		wantErr string
	}{
		{"matching key", certcrypto.PEMEncode(key), ""},
		{"different key", certcrypto.PEMEncode(other), "does not match CSR"},
		{"invalid PEM", []byte("invalid"), "parse private key"},
		{"missing key", nil, "parse private key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := privateKeyForCSR(csr, tt.pem)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			signer, ok := got.(*ecdsa.PrivateKey)
			if !ok || !signer.PublicKey.Equal(&key.PublicKey) {
				t.Fatal("returned key does not match CSR")
			}
		})
	}
}
