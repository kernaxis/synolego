package synology

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kernaxis/synolego/internal/recovery"
)

const ArchivePath = "/usr/syno/etc/certificate/_archive"
const filePerm os.FileMode = 0o600

type Info map[string]CertInfo

type CertInfo struct {
	Desc          string    `json:"desc"`
	Services      []Service `json:"services"`
	UserDeletable bool      `json:"user_deletable"`
}

type Service struct {
	DisplayName     string `json:"display_name"`
	DisplayNameI18n string `json:"display_name_i18n"`
	IsPkg           bool   `json:"isPkg"`
	Owner           string `json:"owner"`
	Service         string `json:"service"`
	Subscriber      string `json:"subscriber"`
	UserSetable     bool   `json:"user_setable"`
}

func GetCertificatesInfo() (Info, error) {
	rawJson, err := os.ReadFile(filepath.Join(ArchivePath, "INFO"))
	if err != nil {
		return nil, err
	}

	return decodeInfo(rawJson)
}

func decodeInfo(raw []byte) (Info, error) {
	var info Info
	if err := json.Unmarshal(raw, &info); err != nil {
		return nil, err
	}
	if info == nil {
		return nil, fmt.Errorf("certificate INFO must be an object")
	}
	return info, nil
}

func SaveCertificatesInfo(info Info) error {
	jsonBytes, err := json.MarshalIndent(info, "", "\t")
	if err != nil {
		return err
	}

	return recovery.WritePreserving(filepath.Join(ArchivePath, "INFO"), jsonBytes)
}
