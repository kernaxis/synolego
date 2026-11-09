package recovery

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type File struct {
	Path   string   `json:"path"`
	Before Snapshot `json:"before"`
	After  Snapshot `json:"after"`
}

type Guard struct {
	Path   string   `json:"path"`
	Before Snapshot `json:"before"`
}

type Group struct {
	Name   string `json:"name"`
	Files  []int  `json:"files"`
	Reload string `json:"reload,omitempty"`
	Done   bool   `json:"done"`
}

type Journal struct {
	Version    int     `json:"version"`
	Generation string  `json:"generation"`
	Target     string  `json:"target"`
	Files      []File  `json:"files"`
	Groups     []Group `json:"groups"`
	Guards     []Guard `json:"guards"`
}

type Content struct {
	Path   string
	Data   []byte
	Remove bool
}

type Batch struct {
	Name   string
	Files  []Content
	Reload string
}

type Store struct {
	Dir      string
	Validate func(*Journal) error
	Reload   func(string) error
	// After is an optional fault-injection point; production leaves it nil.
	After func(string) error
}

func (s *Store) checkpoint(j *Journal) error {
	data, err := json.Marshal(j)
	if err != nil {
		return err
	}
	return WritePrivate(filepath.Join(s.Dir, "current.json"), data)
}

func structure(j *Journal) error {
	seen := make(map[int]bool)
	paths := make(map[string]bool)
	for _, file := range j.Files {
		if !filepath.IsAbs(file.Path) || filepath.Clean(file.Path) != file.Path || paths[file.Path] {
			return errors.New("invalid deployment destination")
		}
		paths[file.Path] = true
		if file.After.Mode > 0777 || file.After.UID < 0 || file.After.GID < 0 {
			return errors.New("invalid deployment metadata")
		}
	}
	pending := false
	for _, group := range j.Groups {
		if !group.Done {
			pending = true
		} else if pending {
			return errors.New("invalid deployment progress")
		}
		for _, index := range group.Files {
			if index < 0 || index >= len(j.Files) || seen[index] {
				return errors.New("invalid deployment file index")
			}
			seen[index] = true
		}
	}
	if len(seen) != len(j.Files) || len(j.Groups) < 2 {
		return errors.New("incomplete deployment journal")
	}
	return nil
}

func (s *Store) Load() (*Journal, error) {
	path := filepath.Join(s.Dir, "current.json")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if _, err := Inspect(path); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, 8<<20))
	decoder.DisallowUnknownFields()
	var j Journal
	if err = decoder.Decode(&j); err != nil {
		return nil, fmt.Errorf("invalid recovery journal: %w", err)
	}
	var extra any
	if err = decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing recovery journal data")
	}
	if j.Version != 1 || !strings.HasPrefix(j.Generation, "generation-") || filepath.Base(j.Generation) != j.Generation {
		return nil, errors.New("unsupported recovery journal")
	}
	return &j, nil
}

// Prepare publishes the journal only after all immutable file contents are durable.
func (s *Store) Prepare(target string, batches []Batch, guardPaths []string) error {
	if j, err := s.Load(); err != nil {
		return err
	} else if j != nil {
		return errors.New("a deployment is already pending")
	}
	if err := os.MkdirAll(s.Dir, 0700); err != nil {
		return err
	}
	if err := CheckParents(filepath.Join(s.Dir, "current.json")); err != nil {
		return err
	}
	if err := os.Chmod(s.Dir, 0700); err != nil {
		return err
	}
	generation, err := os.MkdirTemp(s.Dir, "generation-")
	if err != nil {
		return err
	}
	// Orphans from an interrupted preparation are harmless: they were never activated.
	j := &Journal{Version: 1, Generation: filepath.Base(generation), Target: target}
	seen := map[string]bool{}
	for _, batch := range batches {
		group := Group{Name: batch.Name, Reload: batch.Reload}
		for _, content := range batch.Files {
			if seen[content.Path] {
				return fmt.Errorf("duplicate deployment destination: %s", content.Path)
			}
			seen[content.Path] = true
			before, err := Inspect(content.Path)
			if err != nil {
				return err
			}
			after := before
			if !before.Exists {
				after = Snapshot{Mode: 0600, UID: os.Geteuid(), GID: os.Getegid()}
			}
			if content.Remove {
				after = Snapshot{}
			} else {
				after.Exists = true
				after.Hash = Digest(content.Data)
			}
			index := len(j.Files)
			if !content.Remove {
				if err := WritePrivate(filepath.Join(generation, fmt.Sprintf("file-%d", index)), content.Data); err != nil {
					return err
				}
			}
			j.Files = append(j.Files, File{content.Path, before, after})
			group.Files = append(group.Files, index)
		}
		j.Groups = append(j.Groups, group)
	}
	for _, path := range guardPaths {
		before, err := Inspect(path)
		if err != nil {
			return err
		}
		j.Guards = append(j.Guards, Guard{path, before})
	}
	if err := structure(j); err != nil {
		return err
	}
	if err := s.Validate(j); err != nil {
		return err
	}
	if err := SyncDir(generation); err != nil {
		return err
	}
	if err := SyncDir(s.Dir); err != nil {
		return err
	}
	if err := SyncDir(filepath.Dir(s.Dir)); err != nil {
		return err
	}
	return s.checkpoint(j)
}

func (s *Store) point(name string) error {
	if s.After != nil {
		return s.After(name)
	}
	return nil
}

// Replay accepts only the recorded old or new state, never an unrelated third state.
func (s *Store) Replay() (bool, error) {
	j, err := s.Load()
	if err != nil || j == nil {
		return false, err
	}
	if err = structure(j); err != nil {
		return true, err
	}
	if err = s.Validate(j); err != nil {
		return true, err
	}
	for _, guard := range j.Guards {
		now, err := Inspect(guard.Path)
		if err != nil {
			return true, err
		}
		if now != guard.Before {
			return true, fmt.Errorf("external change to deployment configuration: %s", guard.Path)
		}
	}
	// Preflight every destination and staged blob before changing any destination.
	completed := map[int]bool{}
	for _, group := range j.Groups {
		if group.Done {
			for _, index := range group.Files {
				completed[index] = true
			}
		}
	}
	for index, file := range j.Files {
		now, err := Inspect(file.Path)
		if err != nil {
			return true, err
		}
		if now != file.Before && now != file.After {
			return true, fmt.Errorf("external change to deployment file: %s", file.Path)
		}
		if completed[index] && now != file.After {
			return true, fmt.Errorf("completed deployment file changed: %s", file.Path)
		}
		if file.After.Exists {
			path := filepath.Join(s.Dir, j.Generation, fmt.Sprintf("file-%d", index))
			blob, err := Inspect(path)
			if err != nil {
				return true, err
			}
			if !blob.Exists || blob.Hash != file.After.Hash {
				return true, fmt.Errorf("damaged staged file %d", index)
			}
		}
	}
	for groupIndex := range j.Groups {
		group := &j.Groups[groupIndex]
		if group.Done {
			continue
		}
		for _, guard := range j.Guards {
			now, err := Inspect(guard.Path)
			if err != nil {
				return true, err
			}
			if now != guard.Before {
				return true, fmt.Errorf("external change to deployment configuration: %s", guard.Path)
			}
		}
		for _, index := range group.Files {
			file := j.Files[index]
			now, err := Inspect(file.Path)
			if err != nil {
				return true, err
			}
			if now != file.Before && now != file.After {
				return true, fmt.Errorf("deployment conflict: %s", file.Path)
			}
			if now != file.After {
				if file.After.Exists {
					data, err := os.ReadFile(filepath.Join(s.Dir, j.Generation, fmt.Sprintf("file-%d", index)))
					if err != nil {
						return true, err
					}
					if err := AtomicWrite(file.Path, data, file.After); err != nil {
						return true, err
					}
				} else {
					if err := os.Remove(file.Path); err != nil {
						return true, err
					}
					if err := SyncDir(filepath.Dir(file.Path)); err != nil {
						return true, err
					}
				}
			} else if err := SyncDir(filepath.Dir(file.Path)); err != nil {
				// A prior rename may have succeeded just before its directory sync failed.
				return true, err
			}
			if err := s.point(fmt.Sprintf("file-%d", index)); err != nil {
				return true, err
			}
		}
		if group.Reload != "" {
			if err := s.Reload(group.Reload); err != nil {
				return true, fmt.Errorf("reload service %s: %w", group.Reload, err)
			}
			if err := s.point("reload-" + group.Reload); err != nil {
				return true, err
			}
		}
		group.Done = true
		if err := s.checkpoint(j); err != nil {
			return true, err
		}
		if err := s.point("group-" + group.Name); err != nil {
			return true, err
		}
	}
	return true, nil
}

func (s *Store) Finish() error {
	j, err := s.Load()
	if err != nil || j == nil {
		return err
	}
	if err := structure(j); err != nil {
		return err
	}
	for _, group := range j.Groups {
		if !group.Done {
			return errors.New("cannot discard an unfinished deployment")
		}
	}
	if err := os.Remove(filepath.Join(s.Dir, "current.json")); err != nil {
		return err
	}
	if err := SyncDir(s.Dir); err != nil {
		return err
	}
	if err := os.RemoveAll(filepath.Join(s.Dir, j.Generation)); err != nil {
		return err
	}
	return SyncDir(s.Dir)
}

func (s *Store) Completed() (bool, error) {
	j, err := s.Load()
	if err != nil || j == nil {
		return false, err
	}
	if err := structure(j); err != nil {
		return false, err
	}
	for _, group := range j.Groups {
		if !group.Done {
			return false, nil
		}
	}
	return true, nil
}
