package synology

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/go-acme/lego/v4/log"
)

func Reload(certId string) error {
	archivePath := filepath.Join(ArchivePath, certId)

	info, err := GetCertificatesInfo()
	if err != nil {
		return fmt.Errorf("read certificate INFO: %w", err)
	}

	for _, s := range info[certId].Services {
		certPath, err := FindCertPath(s.Subscriber, s.Service)
		if err != nil {
			return fmt.Errorf("find certificate path for subscriber %s and service %s: %w", s.Subscriber, s.Service, err)
		}

		log.Infof("%s : check certificate change", s.Service)

		unchanged := true
		for _, name := range dsmFiles {
			src, dst := filepath.Join(archivePath, name), filepath.Join(certPath, name)
			if name == "chain.pem" {
				if _, err := os.Stat(src); os.IsNotExist(err) {
					if _, err := os.Stat(dst); os.IsNotExist(err) {
						continue
					}
					unchanged = false
					continue
				}
			}
			if !CompareFiles(src, dst) {
				unchanged = false
			}
		}
		if !unchanged {
			for _, name := range dsmFiles {
				src, dst := filepath.Join(archivePath, name), filepath.Join(certPath, name)
				if name == "chain.pem" {
					if _, err := os.Stat(src); os.IsNotExist(err) {
						if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
							return err
						}
						continue
					}
				}
				if _, err := CopyFile(src, dst); err != nil {
					return fmt.Errorf("copy %s for subscriber %s and service %s: %w", name, s.Subscriber, s.Service, err)
				}
			}
		}
		// Identical files do not prove that a previous service reload succeeded.

		if err := reloadService(s); err != nil {
			return err
		}

		log.Infof("%s : done", s.Service)
	}
	return nil
}

func reloadService(s Service) error {
	if profileExecPath, err := FindExecPath(s.Subscriber); err == nil {
		log.Infof("execute profile script: %s %s", profileExecPath, s.Service)
		cmd := exec.Command(profileExecPath, s.Service)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("execute profile script %s for service %s: %w", profileExecPath, s.Service, err)
		}
	}

	profileExecScript := s.Subscriber + ".sh"
	if s.Subscriber == "system" && s.Service == "default" {
		profileExecScript = "dsm.sh"
	}
	profileExecPath := "/usr/libexec/security-profile/tls-profile/" + profileExecScript
	if _, err := os.Stat(profileExecPath); err == nil {
		log.Infof("execute profile script: %s", profileExecPath)
		cmd := exec.Command(profileExecPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("execute profile script %s for service %s: %w", profileExecPath, s.Service, err)
		}
	}
	return nil
}
