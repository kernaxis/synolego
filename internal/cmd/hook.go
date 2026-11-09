package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certificate"
)

const (
	hookEnvAccountEmail      = "LEGO_ACCOUNT_EMAIL"
	hookEnvCertDomain        = "LEGO_CERT_DOMAIN"
	hookEnvCertPath          = "LEGO_CERT_PATH"
	hookEnvCertKeyPath       = "LEGO_CERT_KEY_PATH"
	hookEnvIssuerCertKeyPath = "LEGO_ISSUER_CERT_PATH"
	hookEnvCertPEMPath       = "LEGO_CERT_PEM_PATH"
	hookEnvCertPFXPath       = "LEGO_CERT_PFX_PATH"
)

func launchHook(hook string, timeout time.Duration, meta map[string]string) error {
	if hook == "" {
		return nil
	}

	ctxCmd, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	parts := strings.Fields(hook)

	cmd := exec.CommandContext(ctxCmd, parts[0], parts[1:]...)
	cmd.Env = append(os.Environ(), metaToEnv(meta)...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("create pipe: %w", err)
	}

	cmd.Stderr = cmd.Stdout

	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("start command: %w", err)
	}

	go func() {
		<-ctxCmd.Done()
		if ctxCmd.Err() != nil {
			_ = cmd.Process.Kill()
			_ = stdout.Close()
		}
	}()

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}

	err = cmd.Wait()
	if err != nil {
		if errors.Is(ctxCmd.Err(), context.DeadlineExceeded) {
			return errors.New("hook timed out")
		}

		return fmt.Errorf("wait command: %w", err)
	}

	return nil
}

func metaToEnv(meta map[string]string) []string {
	var envs []string

	for k, v := range meta {
		envs = append(envs, k+"="+v)
	}

	return envs
}

func addPathToMetadata(meta map[string]string, domain string, certRes *certificate.Resource, certsStorage *CertificatesStorage) {
	meta[hookEnvCertDomain] = domain
	meta[hookEnvCertPath] = certsStorage.GetFileName(domain, certExt)
	meta[hookEnvCertKeyPath] = certsStorage.GetFileName(domain, keyExt)

	if certRes.IssuerCertificate != nil {
		meta[hookEnvIssuerCertKeyPath] = certsStorage.GetFileName(domain, issuerExt)
	}

	if certsStorage.pem {
		meta[hookEnvCertPEMPath] = certsStorage.GetFileName(domain, pemExt)
	}

	if certsStorage.pfx {
		meta[hookEnvCertPFXPath] = certsStorage.GetFileName(domain, pfxExt)
	}
}

// const synologyArchivePath = "/usr/syno/etc/certificate/_archive"

// func deploySynology(certId, domain string, certRes *certificate.Resource, certsStorage *CertificatesStorage) {
// 	archivePath := filepath.Join(synologyArchivePath, certId)

// 	privkeyPath := filepath.Join(archivePath, "privkey.pem")
// 	certPath := filepath.Join(archivePath, "cert.pem")
// 	chainPath := filepath.Join(archivePath, "chain.pem")
// 	fullchainPath := filepath.Join(archivePath, "fullchain.pem")

// 	log.Infof("Importing key file to %s", privkeyPath)

// 	if err := os.WriteFile(privkeyPath, certRes.PrivateKey, filePerm); err != nil {
// 		log.Warnf("Unable to save key file to %s: %v", privkeyPath, err)
// 		return
// 	}

// 	log.Infof("Importing cert file to %s", certPath)
// 	if err := os.WriteFile(certPath, certRes.Certificate, filePerm); err != nil {
// 		log.Warnf("Unable to save cert file to %s: %v", certPath, err)
// 		return
// 	}

// 	if certRes.IssuerCertificate != nil {
// 		log.Infof("Importing chain file to %s", chainPath)
// 		if err := os.WriteFile(chainPath, certRes.IssuerCertificate, filePerm); err != nil {
// 			log.Warnf("Unable to save chain file to %s: %v", chainPath, err)
// 			return
// 		}
// 		log.Infof("Importing fullchain file to %s", fullchainPath)
// 		if err := os.WriteFile(fullchainPath, bytes.Join([][]byte{certRes.Certificate, certRes.IssuerCertificate}, nil), filePerm); err != nil {
// 			log.Warnf("Unable to save fullchain file to %s: %v", fullchainPath, err)
// 			return
// 		}
// 	} else {
// 		log.Infof("Importing fullchain file to %s", fullchainPath)
// 		if err := os.WriteFile(fullchainPath, certRes.Certificate, filePerm); err != nil {
// 			log.Warnf("Unable to save fullchain file to %s: %v", fullchainPath, err)
// 			return
// 		}
// 	}
// }

// func reloadSynology(certId, domain string) {
// 	archivePath := filepath.Join(synologyArchivePath, certId)

// 	rawJson, err := os.ReadFile(filepath.Join(synologyArchivePath, "INFO"))
// 	if err != nil {
// 		log.Fatalf("Unable to read INFO file: %v", err)
// 	}

// 	var info synology.Info
// 	err = json.Unmarshal(rawJson, &info)
// 	if err != nil {
// 		log.Fatalf("Unable to unmarshal INFO file: %v", err)
// 	}

// 	for _, s := range info[certId].Services {
// 		certPath, err := synology.FindCertPath(s.Subscriber, s.Service)
// 		if err != nil {
// 			log.Fatalf("Unable to find certificate path for subscriber %s and service %s: %v", s.Subscriber, s.Service, err)
// 		}

// 		log.Infof("%s : check certificate change", s.Service)

// 		if synology.CompareFiles(filepath.Join(archivePath, "cert.pem"), filepath.Join(certPath, "cert.pem")) {
// 			log.Infof("%s : no change", s.Service)
// 			continue
// 		}

// 		log.Infof("%s : copy new certs", s.Service)

// 		synology.CopyFile(filepath.Join(archivePath, "cert.pem"), filepath.Join(certPath, "cert.pem"))
// 		synology.CopyFile(filepath.Join(archivePath, "privkey.pem"), filepath.Join(certPath, "privkey.pem"))
// 		synology.CopyFile(filepath.Join(archivePath, "chain.pem"), filepath.Join(certPath, "chain.pem"))
// 		synology.CopyFile(filepath.Join(archivePath, "fullchain.pem"), filepath.Join(certPath, "fullchain.pem"))

// 		if profileExecPath, err := synology.FindExecPath(s.Subscriber); err == nil {
// 			log.Infof("execute profile script: %s %s", profileExecPath, s.Service)
// 			cmd := exec.Command(profileExecPath, s.Service)
// 			cmd.Stdout = os.Stdout
// 			cmd.Stderr = os.Stderr
// 			cmd.Run()
// 		}

// 		profileExecScript := s.Subscriber + ".sh"
// 		if s.Subscriber == "system" && s.Service == "default" {
// 			profileExecScript = "dsm.sh"
// 		}
// 		profileExecPath := "/usr/libexec/security-profile/tls-profile/" + profileExecScript
// 		if _, err := os.Stat(profileExecPath); err == nil {
// 			log.Infof("execute profile script: %s", profileExecPath)
// 			cmd := exec.Command(profileExecPath)
// 			cmd.Stdout = os.Stdout
// 			cmd.Stderr = os.Stderr
// 			cmd.Run()
// 		}

// 		log.Infof("%s : done", s.Service)
// 	}

// }
