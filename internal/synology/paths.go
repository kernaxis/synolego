package synology

import (
	"fmt"
	"os"
	"path/filepath"
)

func FindCertPath(subscriber, service string) (string, error) {
	paths := []string{
		"/usr/local/etc/certificate",
		"/usr/syno/etc/certificate",
	}

	for _, path := range paths {
		dir := filepath.Join(path, subscriber, service)
		if _, err := os.Stat(dir); err == nil {
			return dir, nil
		}
	}
	return "", fmt.Errorf("unable to find certificate path for subscriber %s and service %s", subscriber, service)
}

func FindExecPath(subscriber string) (string, error) {
	paths := []string{
		"/usr/libexec/certificate.d",
		"/usr/local/libexec/certificate.d",
		"/usr/syno/share/certificate.d",
		"/usr/local/share/certificate.d",
	}

	for _, path := range paths {
		script := filepath.Join(path, subscriber)
		if _, err := os.Stat(script); err == nil {
			return script, nil
		}
	}
	return "", fmt.Errorf("unable to find exec path for subscriber %s", subscriber)
}
