package synology

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-acme/lego/v4/certificate"
)

func transactionFixture(t *testing.T) (string, string, func(string, string) (string, error), *certificate.Resource) {
	t.Helper()
	root := t.TempDir()
	data := filepath.Join(root, "data")
	archive := filepath.Join(root, "archive")
	for _, dir := range []string{filepath.Join(data, "certificates"), filepath.Join(archive, "ABC123"), filepath.Join(root, "svc1"), filepath.Join(root, "svc2")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	info := `{"ABC123":{"services":[{"subscriber":"system","service":"svc1"},{"subscriber":"system","service":"svc2"}]}}`
	if err := os.WriteFile(filepath.Join(archive, "INFO"), []byte(info), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(archive, "DEFAULT"), []byte("ABC123"), 0600); err != nil {
		t.Fatal(err)
	}
	find := func(subscriber, service string) (string, error) {
		if subscriber != "system" || (service != "svc1" && service != "svc2") {
			return "", errors.New("unexpected service")
		}
		return filepath.Join(root, service), nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	resource := &certificate.Resource{Domain: "example.test", Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})}
	return data, archive, find, resource
}

func TestDeploymentRecoversOnlyUnfinishedService(t *testing.T) {
	data, archive, find, resource := transactionFixture(t)
	calls := map[string]int{}
	reload := func(service Service) error {
		calls[service.Service]++
		if service.Service == "svc2" {
			return errors.New("script failed")
		}
		return nil
	}
	s, err := openDeploymentSession(data, archive, find, reload)
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{filepath.Join(archive, "ABC123"), filepath.Join(filepath.Dir(data), "svc1"), filepath.Join(filepath.Dir(data), "svc2")} {
		if err := os.WriteFile(filepath.Join(dir, "chain.pem"), []byte("obsolete chain"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string][]byte{"example.test.crt": resource.Certificate, "example.test.key": resource.PrivateKey, "example.test.issuer.crt": nil}
	serviceOne, _ := find("system", "svc1")
	if err := os.WriteFile(filepath.Join(serviceOne, "privkey.pem"), []byte("old key"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(serviceOne, "privkey.pem"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := s.Publish("ABC123", resource, files, true); err == nil {
		t.Fatal("expected reload failure")
	}
	s.Close()
	// Pending global marker must also protect against another --path root.
	if other, err := openDeploymentSession(filepath.Join(filepath.Dir(data), "other"), archive, find, reload); err == nil {
		other.Close()
		t.Fatal("another data root ignored pending deployment")
	}
	reload = func(service Service) error { calls[service.Service]++; return nil }
	s, err = openDeploymentSession(data, archive, find, reload)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if resumed, err := s.Recover(); !resumed || err != nil {
		t.Fatalf("Recover = %v, %v", resumed, err)
	}
	if calls["svc1"] != 1 || calls["svc2"] != 2 {
		t.Fatalf("unexpected reloads: %v", calls)
	}
	mode, err := os.Stat(filepath.Join(serviceOne, "privkey.pem"))
	if err != nil || mode.Mode().Perm() != 0640 {
		t.Fatal("existing service permissions were not preserved")
	}
	for _, service := range []string{"svc1", "svc2"} {
		dir, _ := find("system", service)
		got, err := os.ReadFile(filepath.Join(dir, "privkey.pem"))
		if err != nil || string(got) != string(resource.PrivateKey) {
			t.Fatal("private key was not recovered")
		}
		if _, err := os.Stat(filepath.Join(dir, "chain.pem")); !os.IsNotExist(err) {
			t.Fatal("obsolete chain remains")
		}
	}
	if resumed, err := s.Recover(); resumed || err != nil {
		t.Fatalf("finished transaction replayed: %v %v", resumed, err)
	}
}

func TestSharedArchiveLockAcrossDataRoots(t *testing.T) {
	data, archive, find, _ := transactionFixture(t)
	s, err := openDeploymentSession(data, archive, find, func(Service) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if other, err := openDeploymentSession(filepath.Join(filepath.Dir(data), "other"), archive, find, nil); err == nil {
		other.Close()
		t.Fatal("shared archive lock was bypassed")
	}
	s.Close()
	s, err = openDeploymentSession(data, archive, find, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
}

func TestDeploymentRejectsChangedDefaultAndUnsafePaths(t *testing.T) {
	for _, kind := range []string{"default", "symlink", "unsafe-local"} {
		t.Run(kind, func(t *testing.T) {
			data, archive, find, resource := transactionFixture(t)
			s, err := openDeploymentSession(data, archive, find, func(Service) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			files := map[string][]byte{"example.test.crt": resource.Certificate, "example.test.key": resource.PrivateKey}
			if kind == "unsafe-local" {
				files["../../escape.crt"] = resource.Certificate
			}
			if kind == "symlink" {
				if err := os.Symlink(filepath.Join(data, "certificates", "example.test.key"), filepath.Join(archive, "ABC123", "privkey.pem")); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "default" {
				s.store.After = func(at string) error {
					if at == "file-0" {
						return errors.New("interrupted")
					}
					return nil
				}
			}
			if err := s.Publish("ABC123", resource, files, true); err == nil {
				t.Fatal("expected rejection or interruption")
			}
			if kind == "default" {
				if err := os.WriteFile(filepath.Join(archive, "DEFAULT"), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
				s.store.After = nil
				if _, err := s.Recover(); err == nil || !strings.Contains(err.Error(), "external change") {
					t.Fatalf("expected default conflict, got %v", err)
				}
			}
		})
	}
}
