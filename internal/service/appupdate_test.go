package service

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"keyway/internal/appupdate"
	"keyway/internal/core"
	"keyway/internal/engine"
	"keyway/internal/models"
	"keyway/internal/store"
)

// fakeUpdater stands in for GitHub.
type fakeUpdater struct {
	current string
	latest  string
	err     error
	dlErr   error
	calls   atomic.Int32
	gotDir  string
}

func (f *fakeUpdater) Current() string { return f.current }

func (f *fakeUpdater) Latest(context.Context) (appupdate.Release, error) {
	f.calls.Add(1)
	return appupdate.Release{Tag: f.latest}, f.err
}

func (f *fakeUpdater) Download(_ context.Context, r appupdate.Release, dir string, progress func(done, total int64)) (string, error) {
	f.gotDir = dir
	if f.dlErr != nil {
		return "", f.dlErr
	}
	progress(10, 10)
	return filepath.Join(dir, r.DiskImage()), nil
}

func newUpdateService(t *testing.T, u *fakeUpdater) *Service {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	m, err := core.NewManager(filepath.Join(dir, "engines", "xray"), core.XraySource)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{
		Store: st, Engines: []EngineSlot{{Engine: engine.Xray{}, Manager: m}},
		Runner: engine.NewRunner(filepath.Join(dir, "xray.pid")), Dir: dir,
		AppUpdater: u, DownloadsDir: filepath.Join(dir, "Downloads"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCheckAppUpdateReportsANewerRelease(t *testing.T) {
	s := newUpdateService(t, &fakeUpdater{current: "v0.2.1", latest: "v0.2.2"})
	v, err := s.CheckAppUpdate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !v.Available || v.Latest != "v0.2.2" || v.Current != "v0.2.1" || v.NotesURL != "https://github.com/arminsameti/Keyway/releases/tag/v0.2.2" {
		t.Fatalf("got %+v", v)
	}
	if got := s.AppUpdate(); !got.Available || got.CheckedAt.IsZero() {
		t.Fatalf("the result must be remembered: %+v", got)
	}
}

func TestCheckAppUpdateUpToDate(t *testing.T) {
	s := newUpdateService(t, &fakeUpdater{current: "v0.2.1", latest: "v0.2.1"})
	v, _ := s.CheckAppUpdate(context.Background())
	if v.Available {
		t.Fatalf("got %+v", v)
	}
}

func TestCheckAppUpdateKeepsTheLastAnswerOnError(t *testing.T) {
	u := &fakeUpdater{current: "v0.2.1", latest: "v0.2.2"}
	s := newUpdateService(t, u)
	if _, err := s.CheckAppUpdate(context.Background()); err != nil {
		t.Fatal(err)
	}
	u.err = errors.New("offline")
	v, err := s.CheckAppUpdate(context.Background())
	if err == nil || v.Error != "offline" || !v.Available || v.Latest != "v0.2.2" {
		t.Fatalf("got %+v, %v", v, err)
	}
}

func TestBackgroundAppCheckHonoursTheSettingAndTheDailyLimit(t *testing.T) {
	u := &fakeUpdater{current: "v0.2.1", latest: "v0.2.2"}
	s := newUpdateService(t, u)
	set := func(mut func(*models.AppData)) {
		if _, err := s.store.Update(func(d *models.AppData) error { mut(d); return nil }); err != nil {
			t.Fatal(err)
		}
	}

	set(func(d *models.AppData) { d.Settings.AppUpdateCheck = "never" })
	s.maybeCheckApp(context.Background())
	if u.calls.Load() != 0 {
		t.Fatal("the setting is off: nothing may be sent")
	}

	set(func(d *models.AppData) { d.Settings.AppUpdateCheck = "daily" })
	s.maybeCheckApp(context.Background())
	if u.calls.Load() != 1 {
		t.Fatalf("never checked before: want 1 call, got %d", u.calls.Load())
	}
	s.maybeCheckApp(context.Background())
	if u.calls.Load() != 1 {
		t.Fatal("checked a moment ago: must not ask again")
	}

	set(func(d *models.AppData) { d.AppCheck.CheckedAt = time.Now().Add(-25 * time.Hour) })
	s.maybeCheckApp(context.Background())
	if u.calls.Load() != 2 {
		t.Fatalf("a day has passed: want 2 calls, got %d", u.calls.Load())
	}
}

func TestBackgroundAppCheckBacksOffAfterAFailure(t *testing.T) {
	u := &fakeUpdater{current: "v0.2.1", err: errors.New("offline")}
	s := newUpdateService(t, u)
	s.maybeCheckApp(context.Background())
	s.maybeCheckApp(context.Background())
	if u.calls.Load() != 1 {
		t.Fatalf("a failed check must wait before retrying, got %d calls", u.calls.Load())
	}
}

func waitDownload(t *testing.T, s *Service) AppUpdateView {
	t.Helper()
	for i := 0; i < 200; i++ {
		v := s.AppUpdate()
		if v.Download != nil && v.Download.State != "running" {
			return v
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("download did not finish")
	return AppUpdateView{}
}

func TestAppUpdateDownload(t *testing.T) {
	u := &fakeUpdater{current: "v0.2.1", latest: "v0.2.2"}
	s := newUpdateService(t, u)
	if _, err := s.StartAppUpdateDownload(); err == nil {
		t.Fatal("nothing was found yet: there is nothing to download")
	}
	if _, err := s.CheckAppUpdate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartAppUpdateDownload(); err != nil {
		t.Fatal(err)
	}
	v := waitDownload(t, s)
	want := filepath.Join(s.downloadsDir, "Keyway-v0.2.2-macOS.dmg")
	if v.Download.State != "done" || v.Download.Path != want || u.gotDir != s.downloadsDir {
		t.Fatalf("got %+v", v.Download)
	}
}

func TestAppUpdateDownloadFailure(t *testing.T) {
	u := &fakeUpdater{current: "v0.2.1", latest: "v0.2.2", dlErr: errors.New("checksum mismatch")}
	s := newUpdateService(t, u)
	if _, err := s.CheckAppUpdate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartAppUpdateDownload(); err != nil {
		t.Fatal(err)
	}
	v := waitDownload(t, s)
	if v.Download.State != "failed" || v.Download.Error != "checksum mismatch" || v.Download.Path != "" {
		t.Fatalf("got %+v", v.Download)
	}
}
