package cmd

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/log"
	"github.com/kernaxis/synolego/internal/recovery"
	"github.com/urfave/cli/v2"
	"golang.org/x/net/idna"
	"software.sslmate.com/src/go-pkcs12"
)

const (
	baseCertificatesFolderName = "certificates"
	baseArchivesFolderName     = "archives"
)

const (
	issuerExt   = ".issuer.crt"
	certExt     = ".crt"
	keyExt      = ".key"
	pemExt      = ".pem"
	pfxExt      = ".pfx"
	resourceExt = ".json"
)

// CertificatesStorage a certificates' storage.
//
// rootPath:
//
//	./.lego/certificates/
//	     │      └── root certificates directory
//	     └── "path" option
//
// archivePath:
//
//	./.lego/archives/
//	     │      └── archived certificates directory
//	     └── "path" option
type CertificatesStorage struct {
	rootPath    string
	archivePath string
	pem         bool
	pfx         bool
	pfxPassword string
	pfxFormat   string
	filename    string // Deprecated
}

// NewCertificatesStorage create a new certificates storage.
func NewCertificatesStorage(ctx *cli.Context) *CertificatesStorage {
	pfxFormat := ctx.String(flgPFXFormat)

	switch pfxFormat {
	case "DES", "RC2", "SHA256":
	default:
		log.Fatalf("Invalid PFX format: %s", pfxFormat)
	}

	return &CertificatesStorage{
		rootPath:    filepath.Join(ctx.String(flgPath), baseCertificatesFolderName),
		archivePath: filepath.Join(ctx.String(flgPath), baseArchivesFolderName),
		pem:         ctx.Bool(flgPEM),
		pfx:         ctx.Bool(flgPFX),
		pfxPassword: ctx.String(flgPFXPass),
		pfxFormat:   pfxFormat,
		filename:    ctx.String(flgFilename),
	}
}

func (s *CertificatesStorage) CreateRootFolder() {
	err := createNonExistingFolder(s.rootPath)
	if err != nil {
		log.Fatalf("Could not check/create path: %v", err)
	}
}

func (s *CertificatesStorage) CreateArchiveFolder() {
	err := createNonExistingFolder(s.archivePath)
	if err != nil {
		log.Fatalf("Could not check/create path: %v", err)
	}
}

func (s *CertificatesStorage) GetRootPath() string {
	return s.rootPath
}

func (s *CertificatesStorage) SaveResource(certRes *certificate.Resource) {
	files, err := s.resourceFiles(certRes)
	if err != nil {
		log.Fatal(err)
	}
	for name, data := range files {
		path := filepath.Join(s.rootPath, name)
		if data == nil {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				log.Fatal(err)
			}
		} else if err := recovery.WritePrivate(path, data); err != nil {
			log.Fatal(err)
		}
	}
}

// resourceFiles has no filesystem effects: failed export encoding cannot damage active files.
func (s *CertificatesStorage) resourceFiles(certRes *certificate.Resource) (map[string][]byte, error) {
	if certRes == nil {
		return nil, fmt.Errorf("missing certificate resource")
	}
	name := sanitizedDomain(certRes.Domain)
	if s.filename != "" {
		name = s.filename
	}
	if filepath.Base(name) != name || name == "." || name == ".." {
		return nil, fmt.Errorf("invalid certificate filename")
	}
	metadata, err := json.MarshalIndent(certRes, "", "\t")
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{name + certExt: certRes.Certificate, name + issuerExt: certRes.IssuerCertificate, name + resourceExt: metadata}
	if len(certRes.PrivateKey) > 0 {
		files[name+keyExt] = certRes.PrivateKey
		if s.pem {
			files[name+pemExt] = bytes.Join([][]byte{certRes.Certificate, certRes.PrivateKey}, nil)
		}
		if s.pfx {
			data, err := s.encodePFX(certRes.Domain, certRes)
			if err != nil {
				return nil, err
			}
			files[name+pfxExt] = data
		}
	} else if s.pem || s.pfx {
		return nil, fmt.Errorf("cannot export PEM or PFX without a private key")
	}
	return files, nil
}

func (s *CertificatesStorage) ReadResource(domain string) certificate.Resource {
	raw, err := s.ReadFile(domain, resourceExt)
	if err != nil {
		log.Fatalf("Error while loading the meta data for domain %s\n\t%v", domain, err)
	}

	var resource certificate.Resource
	if err = json.Unmarshal(raw, &resource); err != nil {
		log.Fatalf("Error while marshaling the meta data for domain %s\n\t%v", domain, err)
	}

	return resource
}

func (s *CertificatesStorage) ExistsFile(domain, extension string) bool {
	filePath := s.GetFileName(domain, extension)

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false
	} else if err != nil {
		log.Fatal(err)
	}
	return true
}

func (s *CertificatesStorage) ReadFile(domain, extension string) ([]byte, error) {
	return os.ReadFile(s.GetFileName(domain, extension))
}

func (s *CertificatesStorage) GetFileName(domain, extension string) string {
	filename := sanitizedDomain(domain) + extension
	return filepath.Join(s.rootPath, filename)
}

func (s *CertificatesStorage) ReadCertificate(domain, extension string) ([]*x509.Certificate, error) {
	content, err := s.ReadFile(domain, extension)
	if err != nil {
		return nil, err
	}

	// The input may be a bundle or a single certificate.
	return certcrypto.ParsePEMBundle(content)
}

func (s *CertificatesStorage) WriteFile(domain, extension string, data []byte) error {
	var baseFileName string
	if s.filename != "" {
		baseFileName = s.filename
	} else {
		baseFileName = sanitizedDomain(domain)
	}

	filePath := filepath.Join(s.rootPath, baseFileName+extension)

	return recovery.WritePrivate(filePath, data)
}

func (s *CertificatesStorage) WriteCertificateFiles(domain string, certRes *certificate.Resource) error {
	err := s.WriteFile(domain, keyExt, certRes.PrivateKey)
	if err != nil {
		return fmt.Errorf("unable to save key file: %w", err)
	}

	if s.pem {
		err = s.WriteFile(domain, pemExt, bytes.Join([][]byte{certRes.Certificate, certRes.PrivateKey}, nil))
		if err != nil {
			return fmt.Errorf("unable to save PEM file: %w", err)
		}
	}

	if s.pfx {
		err = s.WritePFXFile(domain, certRes)
		if err != nil {
			return fmt.Errorf("unable to save PFX file: %w", err)
		}
	}

	return nil
}

func (s *CertificatesStorage) WritePFXFile(domain string, certRes *certificate.Resource) error {
	data, err := s.encodePFX(domain, certRes)
	if err != nil {
		return err
	}
	return s.WriteFile(domain, pfxExt, data)
}

func (s *CertificatesStorage) encodePFX(domain string, certRes *certificate.Resource) ([]byte, error) {
	certPemBlock, _ := pem.Decode(certRes.Certificate)
	if certPemBlock == nil {
		return nil, fmt.Errorf("unable to parse Certificate for domain %s", domain)
	}

	cert, err := x509.ParseCertificate(certPemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to load Certificate for domain %s: %w", domain, err)
	}

	certChain, err := getCertificateChain(certRes)
	if err != nil {
		return nil, fmt.Errorf("unable to get certificate chain for domain %s: %w", domain, err)
	}

	keyPemBlock, _ := pem.Decode(certRes.PrivateKey)
	if keyPemBlock == nil {
		return nil, fmt.Errorf("unable to parse PrivateKey for domain %s", domain)
	}

	var privateKey crypto.Signer
	var keyErr error

	switch keyPemBlock.Type {
	case "RSA PRIVATE KEY":
		privateKey, keyErr = x509.ParsePKCS1PrivateKey(keyPemBlock.Bytes)
		if keyErr != nil {
			return nil, fmt.Errorf("unable to load RSA PrivateKey for domain %s: %w", domain, keyErr)
		}
	case "EC PRIVATE KEY":
		privateKey, keyErr = x509.ParseECPrivateKey(keyPemBlock.Bytes)
		if keyErr != nil {
			return nil, fmt.Errorf("unable to load EC PrivateKey for domain %s: %w", domain, keyErr)
		}
	default:
		return nil, fmt.Errorf("unsupported PrivateKey type '%s' for domain %s", keyPemBlock.Type, domain)
	}

	encoder, err := getPFXEncoder(s.pfxFormat)
	if err != nil {
		return nil, fmt.Errorf("PFX encoder: %w", err)
	}

	pfxBytes, err := encoder.Encode(privateKey, cert, certChain, s.pfxPassword)
	if err != nil {
		return nil, fmt.Errorf("unable to encode PFX data for domain %s: %w", domain, err)
	}

	return pfxBytes, nil
}

func (s *CertificatesStorage) MoveToArchive(domain string) error {
	baseFilename := filepath.Join(s.rootPath, sanitizedDomain(domain))

	matches, err := filepath.Glob(baseFilename + ".*")
	if err != nil {
		return err
	}

	for _, oldFile := range matches {
		if strings.TrimSuffix(oldFile, filepath.Ext(oldFile)) != baseFilename && oldFile != baseFilename+issuerExt {
			continue
		}

		date := strconv.FormatInt(time.Now().Unix(), 10)
		filename := date + "." + filepath.Base(oldFile)
		newFile := filepath.Join(s.archivePath, filename)

		err = os.Rename(oldFile, newFile)
		if err != nil {
			return err
		}
	}

	return nil
}

func getCertificateChain(certRes *certificate.Resource) ([]*x509.Certificate, error) {
	chainCertPemBlock, rest := pem.Decode(certRes.IssuerCertificate)
	if chainCertPemBlock == nil {
		return nil, errors.New("unable to parse Issuer Certificate")
	}

	var certChain []*x509.Certificate
	for chainCertPemBlock != nil {
		chainCert, err := x509.ParseCertificate(chainCertPemBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse Chain Certificate: %w", err)
		}

		certChain = append(certChain, chainCert)
		chainCertPemBlock, rest = pem.Decode(rest) // Try decoding the next pem block
	}

	return certChain, nil
}

func getPFXEncoder(pfxFormat string) (*pkcs12.Encoder, error) {
	var encoder *pkcs12.Encoder
	switch pfxFormat {
	case "SHA256":
		encoder = pkcs12.Modern2023
	case "DES":
		encoder = pkcs12.LegacyDES
	case "RC2":
		encoder = pkcs12.LegacyRC2
	default:
		return nil, fmt.Errorf("invalid PFX format: %s", pfxFormat)
	}

	return encoder, nil
}

// sanitizedDomain Make sure no funny chars are in the cert names (like wildcards ;)).
func sanitizedDomain(domain string) string {
	safe, err := idna.ToASCII(strings.NewReplacer(":", "-", "*", "_").Replace(domain))
	if err != nil {
		log.Fatal(err)
	}
	return safe
}
