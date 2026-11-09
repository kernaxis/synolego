package cmd

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/log"
	"github.com/kernaxis/synolego/synology"
	"github.com/urfave/cli/v2"
)

func openDeployment(ctx *cli.Context) (*synology.DeploymentSession, bool, error) {
	session, err := synology.OpenDeploymentSession(ctx.String(flgPath))
	if err != nil {
		return nil, false, err
	}
	resumed, err := session.Recover()
	if err != nil {
		session.Close()
		return nil, false, fmt.Errorf("resume pending certificate deployment: %w", err)
	}
	if resumed {
		log.Infof("Recovered pending deployment; no new certificate request or user hook executed")
	}
	return session, resumed, nil
}

func publishCertificate(ctx *cli.Context, session *synology.DeploymentSession, storage *CertificatesStorage, resource *certificate.Resource) error {
	if resource == nil {
		return fmt.Errorf("missing certificate resource")
	}
	if _, err := tls.X509KeyPair(resource.Certificate, resource.PrivateKey); err != nil {
		return fmt.Errorf("invalid deployment key pair: %w", err)
	}
	files, err := storage.resourceFiles(resource)
	if err != nil {
		return fmt.Errorf("prepare certificate exports: %w", err)
	}
	if err := os.MkdirAll(storage.GetRootPath(), 0700); err != nil {
		return err
	}
	// Fail before allocating an ID if the shared DSM index cannot be read.
	if _, err := synology.GetCertificatesInfo(); err != nil {
		return fmt.Errorf("read DSM certificate INFO: %w", err)
	}
	var certID string
	if ctx.Bool(flgDefault) {
		certID, err = synology.GetDefaultID()
	} else {
		certID, err = synology.MakeCertId(filepath.Join(storage.GetRootPath(), fmt.Sprintf("%s.certid", resource.Domain)))
	}
	if err != nil {
		return fmt.Errorf("resolve Synology DSM ID for %s: %w", resource.Domain, err)
	}
	if err := session.Publish(certID, resource, files, ctx.Bool(flgDefault)); err != nil {
		return fmt.Errorf("publish certificate for %s to Synology DSM ID %s: %w", resource.Domain, certID, err)
	}
	return nil
}
