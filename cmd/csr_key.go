package cmd

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/go-acme/lego/v4/certcrypto"
)

// privateKeyForCSR ensures renewal uses the key corresponding to the CSR.
func privateKeyForCSR(csr *x509.CertificateRequest, keyPEM []byte) (crypto.PrivateKey, error) {
	key, err := certcrypto.ParsePEMPrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not support signing")
	}
	keyPublic, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("marshal private key public part: %w", err)
	}
	csrPublic, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal CSR public key: %w", err)
	}
	if !bytes.Equal(keyPublic, csrPublic) {
		return nil, fmt.Errorf("private key does not match CSR")
	}
	return key, nil
}
