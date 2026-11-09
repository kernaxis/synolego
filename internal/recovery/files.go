package recovery

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
)

// Snapshot includes metadata so recovery does not silently undo an operator's changes.
type Snapshot struct {
	Exists bool   `json:"exists"`
	Hash   string `json:"hash"`
	Mode   uint32 `json:"mode"`
	UID    int    `json:"uid"`
	GID    int    `json:"gid"`
}

func CheckParents(path string) error {
	dir := filepath.Dir(path)
	for {
		info, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("unsupported directory or symlink: %s", dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

func Inspect(path string) (Snapshot, error) {
	if err := CheckParents(path); err != nil {
		return Snapshot{}, err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return Snapshot{}, nil
	}
	if err != nil {
		return Snapshot{}, err
	}
	if !info.Mode().IsRegular() {
		return Snapshot{}, fmt.Errorf("unsupported file or symlink: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, err
	}
	uid, gid, err := fileOwner(info)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{true, Digest(data), uint32(info.Mode().Perm()), uid, gid}, nil
}

func Digest(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }

func SyncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	err = f.Sync()
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

// AtomicWrite never truncates the active file. Metadata is set before publication.
func AtomicWrite(path string, data []byte, metadata Snapshot) error {
	if _, err := Inspect(path); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".synolego-write-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = f.Chown(metadata.UID, metadata.GID); err != nil {
		return err
	}
	if err = f.Chmod(os.FileMode(metadata.Mode)); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	return SyncDir(filepath.Dir(path))
}

func WritePrivate(path string, data []byte) error {
	return AtomicWrite(path, data, Snapshot{Mode: 0600, UID: os.Geteuid(), GID: os.Getegid()})
}

func WritePreserving(path string, data []byte) error {
	metadata, err := Inspect(path)
	if err != nil {
		return err
	}
	if !metadata.Exists {
		metadata = Snapshot{Mode: 0600, UID: os.Geteuid(), GID: os.Getegid()}
	}
	return AtomicWrite(path, data, metadata)
}

// Lock files are deliberately retained: unlinking them would allow locks on different inodes.
func Lock(path string) (*os.File, error) {
	if _, err := Inspect(path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = tryLock(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("another Synolego process holds %s: %w", path, err)
	}
	return f, nil
}
