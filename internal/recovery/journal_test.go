package recovery

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func testStore(t *testing.T) (*Store, string) {
	t.Helper()
	root := t.TempDir()
	s := &Store{Dir: filepath.Join(root, "journal"), Validate: func(*Journal) error { return nil }, Reload: func(string) error { return nil }}
	return s, root
}

func prepareTest(t *testing.T, s *Store, root string) {
	t.Helper()
	for _, name := range []string{"local", "archive", "service"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	var batches []Batch
	for _, name := range []string{"local", "archive", "service"} {
		b := Batch{Name: name}
		if name == "service" {
			b.Reload = "service"
		}
		for _, file := range []string{"cert", "key"} {
			path := filepath.Join(root, name, file)
			if err := os.WriteFile(path, []byte("old-"+file), 0600); err != nil {
				t.Fatal(err)
			}
			b.Files = append(b.Files, Content{Path: path, Data: []byte("new-" + file)})
		}
		batches = append(batches, b)
	}
	if err := s.Prepare("certID", batches, nil); err != nil {
		t.Fatal(err)
	}
}

func assertNew(t *testing.T, root string) {
	t.Helper()
	for _, dir := range []string{"local", "archive", "service"} {
		for _, name := range []string{"cert", "key"} {
			data, err := os.ReadFile(filepath.Join(root, dir, name))
			if err != nil || string(data) != "new-"+name {
				t.Fatalf("%s/%s: %q, %v", dir, name, data, err)
			}
		}
	}
}

func TestReplayAfterEveryBoundary(t *testing.T) {
	points := []string{"file-0", "file-1", "file-2", "file-3", "file-4", "file-5", "group-local", "group-archive", "reload-service", "group-service"}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			s, root := testStore(t)
			prepareTest(t, s, root)
			s.After = func(at string) error {
				if at == point {
					return errors.New("injected interruption")
				}
				return nil
			}
			if _, err := s.Replay(); err == nil {
				t.Fatal("interruption was not reached")
			}
			// A new store represents a new invocation, with no in-memory progress.
			restarted := &Store{Dir: s.Dir, Validate: s.Validate, Reload: s.Reload}
			if _, err := restarted.Replay(); err != nil {
				t.Fatal(err)
			}
			assertNew(t, root)
			if err := restarted.Finish(); err != nil {
				t.Fatal(err)
			}
			if j, err := restarted.Load(); j != nil || err != nil {
				t.Fatalf("journal remains: %v %v", j, err)
			}
		})
	}
}

func TestFailedReloadIsRetriedWithIdenticalFiles(t *testing.T) {
	s, root := testStore(t)
	prepareTest(t, s, root)
	calls := 0
	s.Reload = func(string) error { calls++; return errors.New("script failed") }
	if _, err := s.Replay(); err == nil {
		t.Fatal("expected script error")
	}
	assertNew(t, root)
	s.Reload = func(string) error { calls++; return nil }
	if _, err := s.Replay(); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("reload calls = %d", calls)
	}
}

func TestReplayRejectsExternalChangeBeforeWriting(t *testing.T) {
	for _, kind := range []string{"destination", "stage", "guard"} {
		t.Run(kind, func(t *testing.T) {
			s, root := testStore(t)
			prepareTest(t, s, root)
			switch kind {
			case "destination":
				os.WriteFile(filepath.Join(root, "service", "key"), []byte("external"), 0600)
			case "stage":
				j, _ := s.Load()
				os.WriteFile(filepath.Join(s.Dir, j.Generation, "file-0"), []byte("corrupt"), 0600)
			case "guard":
				path := filepath.Join(root, "INFO")
				os.WriteFile(path, []byte("original"), 0600)
				j, _ := s.Load()
				before, _ := Inspect(path)
				j.Guards = []Guard{{path, before}}
				if err := s.checkpoint(j); err != nil {
					t.Fatal(err)
				}
				os.WriteFile(path, []byte("changed"), 0600)
			}
			if _, err := s.Replay(); err == nil {
				t.Fatal("expected conflict")
			}
			data, _ := os.ReadFile(filepath.Join(root, "local", "cert"))
			if string(data) != "old-cert" {
				t.Fatalf("modified before preflight: %s", data)
			}
		})
	}
}

func TestAtomicWriteFailurePreservesActiveFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "cert")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	// An invalid mode fails before rename; the existing destination must survive.
	before, err := Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	before.UID = -2
	if err := AtomicWrite(path, []byte("new"), before); err == nil {
		t.Fatal("expected ownership failure")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "old" {
		t.Fatalf("active file changed: %s", data)
	}
}

func TestCrashReleasesLockAndReplaysDurableJournal(t *testing.T) {
	s, root := testStore(t)
	prepareTest(t, s, root)
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashHelper$")
	cmd.Env = append(os.Environ(), "SYNOLEGO_TEST_CRASH_ROOT="+root)
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 77 {
		t.Fatalf("child did not reach crash point: %v", err)
	}
	lock, err := Lock(filepath.Join(root, "lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if _, err := s.Replay(); err != nil {
		t.Fatal(err)
	}
	assertNew(t, root)
}

func TestCrashHelper(t *testing.T) {
	root := os.Getenv("SYNOLEGO_TEST_CRASH_ROOT")
	if root == "" {
		return
	}
	lock, err := Lock(filepath.Join(root, "lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	s := &Store{Dir: filepath.Join(root, "journal"), Validate: func(*Journal) error { return nil }, Reload: func(string) error { return nil }}
	s.After = func(at string) error {
		if at == "file-0" {
			os.Exit(77)
		}
		return nil
	}
	_, err = s.Replay()
	t.Fatal(fmt.Errorf("did not exit: %w", err))
}

func TestLockContention(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	first, err := Lock(path)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := Lock(path); err == nil {
		second.Close()
		t.Fatal("second writer acquired lock")
	}
	first.Close()
	last, err := Lock(path)
	if err != nil {
		t.Fatal(err)
	}
	last.Close()
}
