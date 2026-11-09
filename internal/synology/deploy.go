package synology

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"path/filepath"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/log"
	"github.com/kernaxis/synolego/internal/recovery"
)

func Deploy(certId string, certRes *certificate.Resource) error {
	// Validate before opening any DSM file: a CSR alone has no private key.
	if certRes == nil || len(certRes.PrivateKey) == 0 {
		return fmt.Errorf("cannot deploy certificate without a private key")
	}
	if _, err := tls.X509KeyPair(certRes.Certificate, certRes.PrivateKey); err != nil {
		return fmt.Errorf("invalid certificate/private key pair: %w", err)
	}

	var (
		privkeyPath   = filepath.Join(ArchivePath, certId, "privkey.pem")
		certPath      = filepath.Join(ArchivePath, certId, "cert.pem")
		chainPath     = filepath.Join(ArchivePath, certId, "chain.pem")
		fullchainPath = filepath.Join(ArchivePath, certId, "fullchain.pem")
	)

	log.Infof("Importing key file to %s", privkeyPath)
	if err := recovery.WritePreserving(privkeyPath, certRes.PrivateKey); err != nil {
		log.Warnf("Unable to save key file to %s: %v", privkeyPath, err)
		return err
	}

	log.Infof("Importing cert file to %s", certPath)
	if err := recovery.WritePreserving(certPath, certRes.Certificate); err != nil {
		log.Warnf("Unable to save cert file to %s: %v", certPath, err)
		return err
	}

	if certRes.IssuerCertificate != nil {
		log.Infof("Importing chain file to %s", chainPath)
		if err := recovery.WritePreserving(chainPath, certRes.IssuerCertificate); err != nil {
			log.Warnf("Unable to save chain file to %s: %v", chainPath, err)
			return err
		}
		log.Infof("Importing fullchain file to %s", fullchainPath)
		if err := recovery.WritePreserving(fullchainPath, bytes.Join([][]byte{certRes.Certificate, certRes.IssuerCertificate}, nil)); err != nil {
			log.Warnf("Unable to save fullchain file to %s: %v", fullchainPath, err)
			return err
		}
	} else {
		log.Infof("Importing fullchain file to %s", fullchainPath)
		if err := recovery.WritePreserving(fullchainPath, certRes.Certificate); err != nil {
			log.Warnf("Unable to save fullchain file to %s: %v", fullchainPath, err)
			return err
		}
	}

	return nil
}

//
