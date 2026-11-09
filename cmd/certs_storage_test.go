package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-acme/lego/v4/certificate"
	"software.sslmate.com/src/go-pkcs12"
)

func storageResource(t *testing.T) *certificate.Resource {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return &certificate.Resource{Domain: "example.test", Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})}
}

func TestResourceFilesPreparesExportsWithoutChangingStore(t *testing.T) {
	for _, format := range []string{"RC2", "DES", "SHA256"} {
		t.Run(format, func(t *testing.T) {
			s := &CertificatesStorage{rootPath: t.TempDir(), pem: true, pfx: true, pfxFormat: format, pfxPassword: "synthetic-test-password"}
			resource := storageResource(t)
			resource.IssuerCertificate = resource.Certificate
			files, err := s.resourceFiles(resource)
			if err != nil {
				t.Fatal(err)
			}
			if len(files) != 6 {
				t.Fatalf("files = %d", len(files))
			}
			_, _, _, err = pkcs12.DecodeChain(files["example.test.pfx"], s.pfxPassword)
			if err != nil {
				t.Fatal(err)
			}
			entries, err := os.ReadDir(s.rootPath)
			if err != nil || len(entries) != 0 {
				t.Fatal("export preparation modified active storage")
			}
		})
	}
}

func TestFailedExportPreservesActiveCertificate(t *testing.T) {
	s := &CertificatesStorage{rootPath: t.TempDir(), pfx: true, pfxFormat: "SHA256"}
	path := filepath.Join(s.rootPath, "example.test.crt")
	if err := os.WriteFile(path, []byte("old certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	resource := storageResource(t)
	resource.IssuerCertificate = []byte("invalid issuer")
	if _, err := s.resourceFiles(resource); err == nil {
		t.Fatal("expected export error")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "old certificate" {
		t.Fatal("active certificate was modified")
	}
}
