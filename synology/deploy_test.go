package synology

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"github.com/go-acme/lego/v4/certificate"
	"math/big"
	"strings"
	"testing"
)

func TestDeployRejectsInvalidKeyPairBeforeWriting(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	otherDER, err := x509.MarshalECPrivateKey(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	otherPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: otherDER})
	tests := []struct {
		name     string
		resource *certificate.Resource
		want     string
	}{
		{"nil resource", nil, "without a private key"},
		{"missing private key", &certificate.Resource{Certificate: certPEM}, "without a private key"},
		{"invalid private key", &certificate.Resource{Certificate: certPEM, PrivateKey: []byte("invalid")}, "invalid certificate/private key pair"},
		{"mismatched private key", &certificate.Resource{Certificate: certPEM, PrivateKey: otherPEM}, "invalid certificate/private key pair"},
		{"missing certificate", &certificate.Resource{PrivateKey: otherPEM}, "invalid certificate/private key pair"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Each case must fail validation, before any access to the DSM archive.
			err := Deploy("audit-invalid-pair", tt.resource)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Deploy() error = %v, want %q", err, tt.want)
			}
		})
	}
}
