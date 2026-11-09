package synology

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/kernaxis/synolego/internal/recovery"
)

func GetDefaultID() (string, error) {
	return readDefaultID(filepath.Join(ArchivePath, "DEFAULT"))
}

func readDefaultID(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(data))
	if !validCertID(id) {
		return "", fmt.Errorf("invalid default certificate ID")
	}
	return id, nil
}

func MakeCertId(certIdPath string) (string, error) {
	return makeCertID(ArchivePath, certIdPath)
}

func makeCertID(archivePath, certIDPath string) (string, error) {
	// Validate the shared index before creating directories or changing the mapping.
	raw, err := os.ReadFile(filepath.Join(archivePath, "INFO"))
	if err != nil {
		return "", fmt.Errorf("read certificate INFO: %w", err)
	}
	info, err := decodeInfo(raw)
	if err != nil {
		return "", fmt.Errorf("decode certificate INFO: %w", err)
	}
	state, err := recovery.Inspect(certIDPath)
	if err != nil {
		return "", fmt.Errorf("inspect certificate ID mapping: %w", err)
	}
	var id string
	if state.Exists {
		data, err := os.ReadFile(certIDPath)
		if err != nil {
			return "", fmt.Errorf("read certificate ID mapping: %w", err)
		}
		id = strings.TrimSpace(string(data))
		if !validCertID(id) {
			return "", fmt.Errorf("invalid certificate ID mapping")
		}
		dir := filepath.Join(archivePath, id)
		entry, err := os.Lstat(dir)
		if os.IsNotExist(err) {
			if err := os.Mkdir(dir, 0700); err != nil {
				return "", fmt.Errorf("create certificate directory: %w", err)
			}
			if err := recovery.SyncDir(archivePath); err != nil {
				return "", err
			}
		} else if err != nil {
			return "", fmt.Errorf("inspect certificate directory: %w", err)
		} else if !entry.IsDir() {
			return "", fmt.Errorf("certificate directory is not a regular directory")
		}
	} else {
		id, err = allocateCertID(archivePath, info)
		if err != nil {
			return "", err
		}
	}
	if _, ok := info[id]; !ok {
		info[id] = CertInfo{Services: []Service{}, UserDeletable: true}
		encoded, err := json.MarshalIndent(info, "", "\t")
		if err != nil {
			return "", err
		}
		if err := recovery.WritePreserving(filepath.Join(archivePath, "INFO"), encoded); err != nil {
			// Keep the reserved directory: a failed directory sync may follow a successful rename.
			return "", fmt.Errorf("save certificate INFO: %w", err)
		}
	}
	if !state.Exists {
		if err := recovery.WritePrivate(certIDPath, []byte(id)); err != nil {
			return "", fmt.Errorf("save certificate ID mapping: %w", err)
		}
	}
	return id, nil
}

func allocateCertID(archivePath string, info Info) (string, error) {
	// Keep the six-character DSM/mktemp convention without an external command.
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for attempt := 0; attempt < 32; attempt++ {
		id := make([]byte, 6)
		for i := range id {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
			if err != nil {
				return "", fmt.Errorf("generate certificate ID: %w", err)
			}
			id[i] = alphabet[n.Int64()]
		}
		if _, exists := info[string(id)]; exists {
			continue
		}
		if err := os.Mkdir(filepath.Join(archivePath, string(id)), 0700); err != nil {
			if os.IsExist(err) {
				continue
			}
			return "", fmt.Errorf("reserve certificate directory: %w", err)
		}
		if err := recovery.SyncDir(archivePath); err != nil {
			return "", err
		}
		return string(id), nil
	}
	return "", fmt.Errorf("unable to reserve a unique certificate ID after 32 attempts")
}
