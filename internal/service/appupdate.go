package service

import (
	"context"
	"errors"
	"sync"
	"time"

	"keyway/internal/appupdate"
	"keyway/internal/models"
)

const (
	appCheckEvery   = 24 * time.Hour
	appCheckTimeout = 30 * time.Second
	appDownloadCap  = 15 * time.Minute
)

// AppUpdater finds and fetches new Keyway releases (appupdate.Checker).
type AppUpdater interface {
	Current() string
	Latest(ctx context.Context) (appupdate.Release, error)
	Download(ctx context.Context, r appupdate.Release, dir string, progress func(done, total int64)) (string, error)
}

// AppDownload is the progress of a disk image download.
type AppDownload struct {
	Version string `json:"version"`
	State   string `json:"state"` // running done failed
	Done    int64  `json:"done"`
	Total   int64  `json:"total"` // -1 when unknown
	Path    string `json:"path,omitempty"`
	Error   string `json:"error,omitempty"`
}

// AppUpdateView describes the app's own update state for the UI.
type AppUpdateView struct {
	Current   string       `json:"current"`
	Latest    string       `json:"latest,omitempty"`
	Available bool         `json:"available"`
	Enabled   bool         `json:"enabled"` // settings.appUpdateCheck is not "never"
	CheckedAt time.Time    `json:"checkedAt,omitempty"`
	Error     string       `json:"error,omitempty"`
	NotesURL  string       `json:"notesUrl,omitempty"`
	Download  *AppDownload `json:"download,omitempty"`
}

type appDownloads struct {
	mu  sync.Mutex
	cur *AppDownload
}

// AppUpdate returns what is known about newer Keyway releases.
func (s *Service) AppUpdate() AppUpdateView {
	d := s.store.Get()
	v := AppUpdateView{
		Enabled:   d.Settings.AppUpdateCheck != "never",
		CheckedAt: d.AppCheck.CheckedAt,
		Error:     d.AppCheck.Error,
		Latest:    d.AppCheck.Latest,
	}
	if s.app != nil {
		v.Current = s.app.Current()
		v.Available = appupdate.Newer(v.Current, v.Latest)
	}
	if v.Available {
		v.NotesURL = "https://github.com/arminsameti/Keyway/releases/tag/" + v.Latest
	}
	s.appDL.mu.Lock()
	if s.appDL.cur != nil {
		c := *s.appDL.cur
		v.Download = &c
	}
	s.appDL.mu.Unlock()
	return v
}

// CheckAppUpdate asks GitHub for the newest release and remembers the answer.
// A failed check keeps the previous answer, so a known update does not vanish
// because the network is down.
func (s *Service) CheckAppUpdate(ctx context.Context) (AppUpdateView, error) {
	if s.app == nil {
		return s.AppUpdate(), errors.New("update checks are not available in this build")
	}
	ctx, cancel := context.WithTimeout(ctx, appCheckTimeout)
	defer cancel()
	r, ferr := s.app.Latest(ctx)
	if _, err := s.store.Update(func(d *models.AppData) error {
		d.AppCheck.CheckedAt = time.Now().UTC()
		d.AppCheck.Error = ""
		if ferr != nil {
			d.AppCheck.Error = ferr.Error()
		} else {
			d.AppCheck.Latest = r.Tag
		}
		return nil
	}); err != nil {
		return s.AppUpdate(), err
	}
	return s.AppUpdate(), ferr
}

// maybeCheckApp is the background check: at most once a day, a failed one is
// retried after a pause, and never when the setting is off.
func (s *Service) maybeCheckApp(ctx context.Context) {
	d := s.store.Get()
	if s.app == nil || d.Settings.AppUpdateCheck == "never" {
		return
	}
	every := appCheckEvery
	if d.AppCheck.Error != "" {
		every = retrySubAfter
	}
	if time.Since(d.AppCheck.CheckedAt) < every {
		return
	}
	if _, err := s.CheckAppUpdate(ctx); err != nil && ctx.Err() == nil {
		s.log.Warn("app update check failed", "err", err)
	}
}

// StartAppUpdateDownload downloads the newest disk image into the Downloads
// folder in the background, verified against the release's SHA256SUMS.txt. If a
// download is already running, that one is reported instead.
func (s *Service) StartAppUpdateDownload() (AppUpdateView, error) {
	if v := s.AppUpdate(); !v.Available {
		return v, errors.New("no newer Keyway release is known; check for updates first")
	}
	s.appDL.mu.Lock()
	if cur := s.appDL.cur; cur != nil && cur.State == "running" {
		s.appDL.mu.Unlock()
		return s.AppUpdate(), nil
	}
	dl := &AppDownload{Version: s.store.Get().AppCheck.Latest, State: "running", Total: -1}
	s.appDL.cur = dl
	s.appDL.mu.Unlock()

	go s.downloadApp(dl)
	return s.AppUpdate(), nil
}

func (s *Service) downloadApp(dl *AppDownload) {
	set := func(f func(*AppDownload)) {
		s.appDL.mu.Lock()
		f(dl)
		s.appDL.mu.Unlock()
	}
	ctx, cancel := context.WithTimeout(context.Background(), appDownloadCap)
	defer cancel()
	// Ask again rather than trusting the remembered tag: the release's asset
	// links are not stored.
	r, err := s.app.Latest(ctx)
	if err == nil {
		set(func(d *AppDownload) { d.Version = r.Tag })
		var path string
		path, err = s.app.Download(ctx, r, s.downloadsDir, func(done, total int64) {
			set(func(d *AppDownload) { d.Done, d.Total = done, total })
		})
		if err == nil {
			set(func(d *AppDownload) { d.State, d.Path = "done", path })
			s.log.Info("downloaded app update", "version", r.Tag, "path", path)
			return
		}
	}
	set(func(d *AppDownload) { d.State, d.Error = "failed", err.Error() })
	s.log.Warn("app update download failed", "err", err)
}
