package synology

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/kernaxis/synolego/internal/recovery"
)

// DeploymentSession serializes Synolego writers and retains unfinished deployments.
// DSM and third-party programs do not participate in these locks.
type DeploymentSession struct {
	root    string
	archive string
	locks   []*os.File
	store   recovery.Store
	find    func(string, string) (string, error)
	reload  func(Service) error
}

func OpenDeploymentSession(dataRoot string) (*DeploymentSession, error) {
	return openDeploymentSession(dataRoot, ArchivePath, FindCertPath, reloadService)
}

func openDeploymentSession(dataRoot, archive string, find func(string, string) (string, error), reload func(Service) error) (*DeploymentSession, error) {
	root, err := filepath.Abs(dataRoot)
	if err != nil {
		return nil, err
	}
	s := &DeploymentSession{root: root, archive: archive, find: find, reload: reload}
	global, err := recovery.Lock(filepath.Join(archive, ".synolego.lock"))
	if err != nil {
		return nil, err
	}
	s.locks = append(s.locks, global)
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	if err := recovery.SyncDir(filepath.Dir(root)); err != nil {
		return nil, err
	}
	local, err := recovery.Lock(filepath.Join(root, ".synolego.lock"))
	if err != nil {
		return nil, err
	}
	s.locks = append(s.locks, local)
	s.store = recovery.Store{Dir: filepath.Join(root, ".synolego-transactions"), Validate: s.validate, Reload: s.reloadKey}
	if err := s.checkOwner(); err != nil {
		return nil, err
	}
	ok = true
	return s, nil
}

func (s *DeploymentSession) Close() {
	for i := len(s.locks) - 1; i >= 0; i-- {
		s.locks[i].Close()
	}
	s.locks = nil
}

func (s *DeploymentSession) ownerPath() string { return filepath.Join(s.archive, ".synolego-pending") }

func (s *DeploymentSession) checkOwner() error {
	path := s.ownerPath()
	state, err := recovery.Inspect(path)
	if err != nil {
		return err
	}
	if !state.Exists {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	owner := string(data)
	if !filepath.IsAbs(owner) || filepath.Clean(owner) != owner || len(owner) > 4096 || strings.ContainsAny(owner, "\x00\r\n") {
		return errors.New("invalid DSM deployment owner marker")
	}
	if owner != s.root {
		return fmt.Errorf("unfinished DSM deployment belongs to --path %q; resume it first", owner)
	}
	return nil
}

func (s *DeploymentSession) Recover() (bool, error) {
	if err := s.checkOwner(); err != nil {
		return false, err
	}
	j, err := s.store.Load()
	if err != nil {
		return false, err
	}
	if j == nil {
		if _, err := os.Lstat(s.ownerPath()); err == nil {
			return false, errors.New("DSM deployment marker exists without its recovery journal; manual recovery required")
		} else if !os.IsNotExist(err) {
			return false, err
		}
		return false, nil
	}
	done, err := s.store.Completed()
	if err != nil {
		return true, err
	}
	if err := recovery.WritePrivate(s.ownerPath(), []byte(s.root)); err != nil {
		return true, err
	}
	if !done {
		if _, err := s.store.Replay(); err != nil {
			return true, err
		}
	}
	if err := os.Remove(s.ownerPath()); err != nil {
		return true, err
	}
	if err := recovery.SyncDir(s.archive); err != nil {
		return true, err
	}
	return true, s.store.Finish()
}

func (s *DeploymentSession) readInfo() (Info, error) {
	raw, err := os.ReadFile(filepath.Join(s.archive, "INFO"))
	if err != nil {
		return nil, err
	}
	return decodeInfo(raw)
}

func serviceKey(service Service) string { return service.Subscriber + "/" + service.Service }

func (s *DeploymentSession) reloadKey(key string) error {
	j, err := s.store.Load()
	if err != nil {
		return err
	}
	if j == nil {
		return errors.New("recovery journal disappeared before service reload")
	}
	info, err := s.readInfo()
	if err != nil {
		return err
	}
	for _, service := range info[j.Target].Services {
		if serviceKey(service) == key {
			return s.reload(service)
		}
	}
	return fmt.Errorf("service no longer assigned to deployment: %s", key)
}

var dsmFiles = []string{"privkey.pem", "cert.pem", "chain.pem", "fullchain.pem"}

func (s *DeploymentSession) validate(j *recovery.Journal) error {
	if !validCertID(j.Target) {
		return errors.New("invalid deployment certificate ID")
	}
	info, err := s.readInfo()
	if err != nil {
		return err
	}
	certInfo, ok := info[j.Target]
	if !ok {
		return errors.New("deployment certificate ID is absent from INFO")
	}
	if len(j.Groups) != 2+len(certInfo.Services) || j.Groups[0].Name != "local" || j.Groups[1].Name != "archive" || j.Groups[0].Reload != "" || j.Groups[1].Reload != "" {
		return errors.New("invalid deployment groups")
	}
	allowed := map[string]bool{}
	for _, ext := range []string{".crt", ".issuer.crt", ".key", ".json", ".pem", ".pfx"} {
		allowed[ext] = true
	}
	for _, index := range j.Groups[0].Files {
		if index < 0 || index >= len(j.Files) {
			return errors.New("invalid local file index")
		}
		path := j.Files[index].Path
		name := filepath.Base(path)
		valid := false
		for ext := range allowed {
			if strings.HasSuffix(name, ext) && strings.TrimSuffix(name, ext) != "" {
				valid = true
			}
		}
		if filepath.Dir(path) != filepath.Join(s.root, "certificates") || !valid {
			return errors.New("invalid local deployment path")
		}
	}
	for groupIndex := 1; groupIndex < len(j.Groups); groupIndex++ {
		group := j.Groups[groupIndex]
		dir := filepath.Join(s.archive, j.Target)
		if groupIndex > 1 {
			service := certInfo.Services[groupIndex-2]
			if !safeComponent(service.Subscriber) || !safeComponent(service.Service) || group.Name != serviceKey(service) || group.Reload != serviceKey(service) {
				return errors.New("invalid deployment service")
			}
			dir, err = s.find(service.Subscriber, service.Service)
			if err != nil {
				return err
			}
		}
		if len(group.Files) != len(dsmFiles) {
			return errors.New("incomplete DSM file set")
		}
		for i, index := range group.Files {
			if index < 0 || index >= len(j.Files) || j.Files[index].Path != filepath.Join(dir, dsmFiles[i]) {
				return errors.New("invalid DSM deployment path")
			}
		}
	}
	if len(j.Guards) < 1 || len(j.Guards) > 2 || j.Guards[0].Path != filepath.Join(s.archive, "INFO") {
		return errors.New("invalid deployment guards")
	}
	if len(j.Guards) == 2 && j.Guards[1].Path != filepath.Join(s.archive, "DEFAULT") {
		return errors.New("invalid default certificate guard")
	}
	for _, guard := range j.Guards {
		if !guard.Before.Exists {
			return errors.New("missing deployment configuration guard")
		}
	}
	if len(j.Guards) == 2 {
		value, err := os.ReadFile(j.Guards[1].Path)
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(value)) != j.Target {
			return errors.New("external change to default certificate before deployment")
		}
	}
	return nil
}

func safeComponent(value string) bool {
	return value != "" && value != "." && value != ".." && filepath.Base(value) == value
}
func validCertID(value string) bool {
	return safeComponent(value) && !strings.ContainsAny(value, "\\\x00")
}

// Publish records a complete generation before touching local or DSM certificate files.
func (s *DeploymentSession) Publish(certID string, resource *certificate.Resource, local map[string][]byte, useDefault bool) error {
	if resource == nil {
		return errors.New("missing certificate resource")
	}
	if _, err := tls.X509KeyPair(resource.Certificate, resource.PrivateKey); err != nil {
		return fmt.Errorf("invalid deployment key pair: %w", err)
	}
	if err := s.checkOwner(); err != nil {
		return err
	}
	info, err := s.readInfo()
	if err != nil {
		return err
	}
	if _, ok := info[certID]; !ok {
		return errors.New("unknown deployment certificate ID")
	}
	names := make([]string, 0, len(local))
	for name := range local {
		names = append(names, name)
	}
	sort.Strings(names)
	batch := recovery.Batch{Name: "local"}
	for _, name := range names {
		batch.Files = append(batch.Files, recovery.Content{Path: filepath.Join(s.root, "certificates", name), Data: local[name], Remove: local[name] == nil})
	}
	batches := []recovery.Batch{batch}
	data := [][]byte{resource.PrivateKey, resource.Certificate, resource.IssuerCertificate, bytes.Join([][]byte{resource.Certificate, resource.IssuerCertificate}, nil)}
	dsmBatch := func(name, dir, reload string) recovery.Batch {
		b := recovery.Batch{Name: name, Reload: reload}
		for i, file := range dsmFiles {
			b.Files = append(b.Files, recovery.Content{Path: filepath.Join(dir, file), Data: data[i], Remove: i == 2 && len(data[i]) == 0})
		}
		return b
	}
	batches = append(batches, dsmBatch("archive", filepath.Join(s.archive, certID), ""))
	for _, service := range info[certID].Services {
		dir, err := s.find(service.Subscriber, service.Service)
		if err != nil {
			return err
		}
		batches = append(batches, dsmBatch(serviceKey(service), dir, serviceKey(service)))
	}
	guards := []string{filepath.Join(s.archive, "INFO")}
	if useDefault {
		value, err := os.ReadFile(filepath.Join(s.archive, "DEFAULT"))
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(value)) != certID {
			return errors.New("default certificate changed before deployment preparation")
		}
		guards = append(guards, filepath.Join(s.archive, "DEFAULT"))
	}
	// Claim the shared archive before publishing the local journal, including across --path roots.
	if err := recovery.WritePrivate(s.ownerPath(), []byte(s.root)); err != nil {
		return err
	}
	if err := s.store.Prepare(certID, batches, guards); err != nil {
		if journal, loadErr := s.store.Load(); loadErr == nil && journal == nil {
			if removeErr := os.Remove(s.ownerPath()); removeErr != nil {
				return errors.Join(err, removeErr)
			}
			if syncErr := recovery.SyncDir(s.archive); syncErr != nil {
				return errors.Join(err, syncErr)
			}
		}
		return err
	}
	_, err = s.Recover()
	return err
}
