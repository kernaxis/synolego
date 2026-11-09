package synology

import (
	"fmt"
	"os"
	"strings"

	"github.com/kernaxis/synolego/internal/recovery"
)

// CompareFiles takes two file paths as parameters and checks if they have the same content.
func CompareFiles(path1, path2 string) bool {
	content1, err := os.ReadFile(path1)
	if err != nil {
		return false
	}

	content2, err := os.ReadFile(path2)
	if err != nil {
		return false
	}

	return string(content1) == string(content2)
}

func CopyFile(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	data, err := os.ReadFile(src)
	if err != nil {
		return 0, err
	}
	if err := recovery.WritePreserving(dst, data); err != nil {
		return 0, err
	}
	return int64(len(data)), nil
}

func GetFileContent(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func SaveFileContent(path, content string) error {
	return recovery.WritePrivate(path, []byte(content))
}
