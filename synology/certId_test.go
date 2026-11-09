package synology

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestMakeCertIDCreatesAndReusesMapping(t *testing.T) {
	archive := t.TempDir()
	mapping := filepath.Join(t.TempDir(), "example.test.certid")
	if err := os.WriteFile(filepath.Join(archive, "INFO"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	id, err := makeCertID(archive, mapping)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9]{6}$`).MatchString(id) {
		t.Fatalf("unexpected ID format: %q", id)
	}
	info, err := os.Stat(filepath.Join(archive, id))
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("invalid certificate directory")
	}
	second, err := makeCertID(archive, mapping)
	if err != nil || second != id {
		t.Fatalf("mapping changed: %q %v", second, err)
	}
	raw, err := os.ReadFile(filepath.Join(archive, "INFO"))
	if err != nil {
		t.Fatal(err)
	}
	index, err := decodeInfo(raw)
	if err != nil || len(index) != 1 || !index[id].UserDeletable {
		t.Fatal("missing INFO entry")
	}
}

func TestMakeCertIDRejectsBadInfoWithoutCreatingMapping(t *testing.T) {
	for _, content := range []string{"missing", "{", "null", "[]"} {
		t.Run(content, func(t *testing.T) {
			archive := t.TempDir()
			mapping := filepath.Join(t.TempDir(), "example.test.certid")
			if content != "missing" {
				if err := os.WriteFile(filepath.Join(archive, "INFO"), []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := makeCertID(archive, mapping); err == nil {
				t.Fatal("expected INFO error")
			}
			if _, err := os.Stat(mapping); !os.IsNotExist(err) {
				t.Fatal("invalid mapping persisted")
			}
			entries, err := os.ReadDir(archive)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if entry.Name() != "INFO" {
					t.Fatal("directory created before validation")
				}
			}
		})
	}
}

func TestMakeCertIDRejectsInvalidMappings(t *testing.T) {
	for _, value := range []string{"", ".", "..", "../escape", "/tmp/escape"} {
		t.Run(value, func(t *testing.T) {
			archive := t.TempDir()
			mapping := filepath.Join(t.TempDir(), "domain.certid")
			if err := os.WriteFile(filepath.Join(archive, "INFO"), []byte(`{}`), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(mapping, []byte(value), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := makeCertID(archive, mapping); err == nil {
				t.Fatal("expected invalid ID error")
			}
			after, err := os.ReadFile(mapping)
			if err != nil || string(after) != value {
				t.Fatal("invalid mapping was overwritten")
			}
		})
	}
}

func TestMakeCertIDRejectsFileInsteadOfDirectory(t *testing.T) {
	archive := t.TempDir()
	mapping := filepath.Join(t.TempDir(), "domain.certid")
	for path, content := range map[string]string{filepath.Join(archive, "INFO"): `{}`, mapping: "ABC123", filepath.Join(archive, "ABC123"): "file"} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := makeCertID(archive, mapping); err == nil {
		t.Fatal("expected directory error")
	}
}

func TestDefaultIDValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "DEFAULT")
	for _, value := range []string{"", ".", "../escape", "ABC123\n"} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		id, err := readDefaultID(path)
		if value == "ABC123\n" {
			if err != nil || id != "ABC123" {
				t.Fatalf("valid default: %q %v", id, err)
			}
		} else if err == nil {
			t.Fatalf("accepted invalid default %q", value)
		}
	}
}
