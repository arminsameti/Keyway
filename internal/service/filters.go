package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"keyway/internal/filters"
	"keyway/internal/models"
)

// Limits (tunable later).
const (
	maxListBytes      = 50 << 20
	maxCatalogBytes   = 8 << 20
	maxMergedDomains  = 2_000_000
	warnMergedDomains = 500_000

	catalogMaxAge      = 24 * time.Hour
	defaultFilterEvery = 24 * time.Hour
)

// FilterListView is a chosen list with its download status.
type FilterListView struct {
	models.FilterList
	Status models.FilterStatus `json:"status"`
	// ApplyOnConnect: new compiled content is waiting for the next connect.
	ApplyOnConnect bool `json:"applyOnConnect"`
}

// FilterView is what the UI shows about the filter lists.
type FilterView struct {
	Lists          []FilterListView  `json:"lists"`
	Domains        int               `json:"domains"` // in the compiled set
	Warn           bool              `json:"warn"`    // the set is big enough to slow connecting
	Widened        []filters.Widened `json:"widened"`
	MergeError     string            `json:"mergeError,omitempty"`
	ApplyOnConnect bool              `json:"applyOnConnect"`
}

// filterFlight is one refresh in progress; later callers for the same list wait on it.
type filterFlight struct {
	done chan struct{}
	err  error
}

func (s *Service) filtersDir() string  { return filepath.Join(s.dir, "filters") }
func (s *Service) compiledDir() string { return filepath.Join(s.filtersDir(), "compiled") }

// rawPath is the downloaded copy of a list; ids that are not plain names are refused.
func (s *Service) rawPath(id string) (string, error) {
	if id == "" || id != filepath.Base(id) || strings.Contains(id, "..") {
		return "", fmt.Errorf("invalid filter list id %q", id)
	}
	return filepath.Join(s.filtersDir(), "raw", id+".txt"), nil
}

func (s *Service) engineRunning() bool {
	if s.running != nil {
		return s.running()
	}
	return s.run.IsRunning()
}

// listProxyAddr is the local SOCKS5 inbound to download through, or "" for a
// direct download (not connected, or no unauthenticated socks inbound).
func (s *Service) listProxyAddr() string {
	if !s.engineRunning() {
		return ""
	}
	for _, ib := range s.store.Get().Settings.Inbounds {
		if ib.Enabled && ib.Protocol == "socks" && ib.Username == "" && ib.Password == "" && ib.Port > 0 {
			return fmt.Sprintf("127.0.0.1:%d", ib.Port)
		}
	}
	return ""
}

// ---- catalog ----

func (s *Service) catalogPath() string { return filepath.Join(s.filtersDir(), "catalog.json") }

func (s *Service) readCatalogCache() (filters.Catalog, bool) {
	b, err := os.ReadFile(s.catalogPath())
	if err != nil {
		return filters.Catalog{}, false
	}
	var c filters.Catalog
	if json.Unmarshal(b, &c) != nil || len(c.Lists) == 0 {
		return filters.Catalog{}, false
	}
	return c, true
}

// FilterCatalog returns the catalog. It reads the cache; with refresh set and
// the cache missing or older than 24h it fetches first. A failed fetch falls
// back to the cache and errors only when there is none.
func (s *Service) FilterCatalog(ctx context.Context, refresh bool) (filters.Catalog, error) {
	s.catalogMu.Lock()
	defer s.catalogMu.Unlock()
	cached, have := s.readCatalogCache()
	if !refresh || (have && time.Since(cached.FetchedAt) < catalogMaxAge) {
		if !have {
			return filters.Catalog{}, errors.New("the filter list catalog has not been downloaded yet")
		}
		return cached, nil
	}
	c, err := s.fetchCatalog(ctx)
	if err != nil {
		if have {
			return cached, nil
		}
		return filters.Catalog{}, err
	}
	return c, nil
}

func (s *Service) fetchCatalog(ctx context.Context) (filters.Catalog, error) {
	r, err := fetchList(ctx, listFetch{URL: s.catalogURL, ProxyAddr: s.listProxyAddr(), MaxBytes: maxCatalogBytes}, s.fetchGuard)
	if err != nil {
		return filters.Catalog{}, fmt.Errorf("download the filter list catalog: %w", err)
	}
	c, err := filters.ParseCatalog(r.Body)
	if err != nil {
		return filters.Catalog{}, err
	}
	c.FetchedAt = time.Now()
	b, err := json.Marshal(c)
	if err != nil {
		return filters.Catalog{}, err
	}
	if err := writeFileAtomic(s.catalogPath(), b); err != nil {
		return filters.Catalog{}, err
	}
	return c, nil
}

// writeFileAtomic writes through a temp file and a rename, so a reader never
// sees a partial file.
func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(data)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		os.Remove(tmp)
		return errors.Join(werr, cerr)
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// ---- refresh ----

// filterDue reports whether a list should be downloaded again: after its own
// UpdateHours, else the catalog's expiry, else 24 hours.
func filterDue(l models.FilterList, st models.FilterStatus, cat filters.Catalog, now time.Time) bool {
	every := defaultFilterEvery
	if l.UpdateHours > 0 {
		every = time.Duration(l.UpdateHours) * time.Hour
	} else if l.CatalogKey != "" {
		if cl, ok := cat.Find(l.CatalogKey); ok && cl.ExpiresSec > 0 {
			every = time.Duration(cl.ExpiresSec) * time.Second
		}
	}
	return now.Sub(st.UpdatedAt) >= every
}

var errNotInCatalog = errors.New("this list is no longer in AdGuard's catalog")

// resolveListURL is where a list downloads from. A catalog list follows the
// cached catalog, then the last URL that worked; FilterList.URL is ignored.
func resolveListURL(l models.FilterList, st models.FilterStatus, cat filters.Catalog, haveCat bool) (string, error) {
	if l.CatalogKey == "" {
		return l.URL, nil
	}
	if haveCat {
		if cl, ok := cat.Find(l.CatalogKey); ok {
			return cl.DownloadURL, nil
		}
	}
	if st.URL != "" {
		return st.URL, nil
	}
	return "", errNotInCatalog
}

// RefreshFilters downloads one enabled list, or every enabled list for id "",
// then recompiles. A failed download keeps the previous copy and records the
// error. It never touches a running engine.
func (s *Service) RefreshFilters(ctx context.Context, id string) error {
	var ids []string
	if id == "" {
		for _, l := range s.store.Get().Settings.EnabledFilterLists() {
			ids = append(ids, l.ID)
		}
	} else {
		ids = []string{id}
	}
	var errs []error
	for _, one := range ids {
		if err := s.refreshOnce(ctx, one); err != nil {
			errs = append(errs, err)
		}
	}
	if _, _, err := s.compileFilters(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// refreshOnce runs refreshList for id; a call while one is running waits for it.
func (s *Service) refreshOnce(ctx context.Context, id string) error {
	s.flightMu.Lock()
	if f, ok := s.flights[id]; ok {
		s.flightMu.Unlock()
		select {
		case <-f.done:
			return f.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f := &filterFlight{done: make(chan struct{})}
	s.flights[id] = f
	s.flightMu.Unlock()

	f.err = s.refreshList(ctx, id)
	s.flightMu.Lock()
	delete(s.flights, id)
	s.flightMu.Unlock()
	close(f.done)
	return f.err
}

func (s *Service) setFilterStatus(id string, fn func(*models.FilterStatus)) {
	if _, err := s.store.Update(func(d *models.AppData) error {
		if _, ok := d.FindFilterList(id); !ok {
			return nil // removed meanwhile: do not resurrect its status
		}
		st := d.FilterStatus[id]
		fn(&st)
		d.FilterStatus[id] = st
		return nil
	}); err != nil {
		s.log.Warn("save filter status", "list", id, "err", err)
	}
}

func (s *Service) refreshList(ctx context.Context, id string) error {
	d := s.store.Get()
	l, ok := d.FindFilterList(id)
	if !ok {
		return fmt.Errorf("filter list %q not found", id)
	}
	fail := func(err error) error {
		s.setFilterStatus(id, func(st *models.FilterStatus) { st.LastError = err.Error() })
		return err
	}
	raw, err := s.rawPath(id)
	if err != nil {
		return err
	}
	st := d.FilterStatus[id]
	cat, haveCat := s.readCatalogCache()
	u, err := resolveListURL(l, st, cat, haveCat)
	if err != nil {
		return fail(err)
	}
	req := listFetch{URL: u, ProxyAddr: s.listProxyAddr(), MaxBytes: maxListBytes}
	if _, statErr := os.Stat(raw); statErr == nil && st.URL == u {
		req.ETag, req.LastModified = st.ETag, st.LastModified // conditional only when there is a copy to keep
	}
	resp, err := fetchList(ctx, req, s.fetchGuard)
	if err != nil {
		return fail(err)
	}
	now := time.Now()
	if resp.NotModified {
		s.setFilterStatus(id, func(st *models.FilterStatus) {
			st.UpdatedAt, st.LastError, st.URL = now, "", u
			if resp.ETag != "" {
				st.ETag = resp.ETag
			}
			if resp.LastModified != "" {
				st.LastModified = resp.LastModified
			}
		})
		return nil
	}
	p, err := filters.Parse(bytes.NewReader(resp.Body))
	if err != nil {
		return fail(fmt.Errorf("this does not look like a filter list: %w", err))
	}
	if err := writeFileAtomic(raw, resp.Body); err != nil {
		return fail(err)
	}
	s.setFilterStatus(id, func(st *models.FilterStatus) {
		*st = models.FilterStatus{
			UpdatedAt: now, ETag: resp.ETag, LastModified: resp.LastModified,
			Domains: len(p.Suffix) + len(p.Exact), Skipped: p.Skipped, URL: u,
		}
	})
	return nil
}

// ---- compile ----

// compileFilters merges the enabled lists' raw files and the allowlist and
// writes the engine files. With nothing to block (Block ads off, no list, or
// no data) it removes the compiled files instead, so an empty set never
// reaches WriteAll. A Merge error leaves compiled/ as it was.
func (s *Service) compileFilters() (filters.Set, []filters.Widened, error) {
	s.compileMu.Lock()
	defer s.compileMu.Unlock()
	set, widened, err := s.compile()
	s.filtersMu.Lock()
	defer s.filtersMu.Unlock()
	if err != nil {
		s.mergeErr = err.Error()
		return filters.Set{}, nil, err
	}
	s.mergeErr = ""
	s.set, s.widened = set, widened
	s.compiledSum = s.sumCompiled(set)
	return set, widened, nil
}

func (s *Service) compile() (filters.Set, []filters.Widened, error) {
	st := s.store.Get().Settings
	var parsed []filters.Parsed
	if st.FiltersActive() {
		for _, l := range st.EnabledFilterLists() {
			raw, err := s.rawPath(l.ID)
			if err != nil {
				continue
			}
			f, err := os.Open(raw)
			if err != nil {
				continue // not downloaded yet
			}
			p, err := filters.Parse(f)
			f.Close()
			if err != nil {
				s.log.Warn("filter list unreadable", "list", l.Name, "err", err)
				continue
			}
			parsed = append(parsed, p)
		}
	}
	if len(parsed) == 0 {
		return filters.Set{}, nil, s.removeCompiled()
	}
	var allowed []string
	for _, line := range strings.Split(st.AllowedSites, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			allowed = append(allowed, line)
		}
	}
	set, widened, err := filters.Merge(parsed, allowed, s.maxMerged)
	if err != nil {
		return filters.Set{}, nil, err
	}
	if set.Len() == 0 {
		return set, widened, s.removeCompiled()
	}
	if err := filters.WriteAll(s.compiledDir(), set); err != nil {
		return filters.Set{}, nil, fmt.Errorf("write compiled filters: %w", err)
	}
	return set, widened, nil
}

var compiledFiles = []string{filters.XrayFile, filters.SingBoxFile, filters.MihomoFile}

func (s *Service) removeCompiled() error {
	for _, f := range compiledFiles {
		if err := os.Remove(filepath.Join(s.compiledDir(), f)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// sumCompiled hashes the compiled files ("" when nothing is compiled).
func (s *Service) sumCompiled(set filters.Set) string {
	if set.Len() == 0 {
		return ""
	}
	h := sha256.New()
	for _, f := range compiledFiles {
		b, err := os.ReadFile(filepath.Join(s.compiledDir(), f))
		if err != nil {
			return ""
		}
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Filters returns the lists with their status and the state of the compiled set.
func (s *Service) Filters() FilterView {
	d := s.store.Get()
	running := s.engineRunning()
	s.filtersMu.Lock()
	v := FilterView{
		Domains: s.set.Len(), Warn: s.set.Len() > warnMergedDomains,
		Widened: append([]filters.Widened{}, s.widened...), MergeError: s.mergeErr,
	}
	v.ApplyOnConnect = running && s.compiledSum != "" && s.compiledSum != s.lastConnectHash
	s.filtersMu.Unlock()
	v.Lists = []FilterListView{}
	for _, l := range d.Settings.FilterLists {
		st := d.FilterStatus[l.ID]
		v.Lists = append(v.Lists, FilterListView{
			FilterList: l, Status: st,
			ApplyOnConnect: v.ApplyOnConnect && l.Enabled && st.Domains > 0,
		})
	}
	return v
}

// ---- settings and loop hooks ----

func enabledIDs(s models.Settings) map[string]models.FilterList {
	m := map[string]models.FilterList{}
	for _, l := range s.EnabledFilterLists() {
		m[l.ID] = l
	}
	return m
}

// filtersChanged runs after a settings save: it drops removed lists' files,
// recompiles when the selection, the allowlist or Block ads changed, and
// refreshes newly enabled lists (or ones whose source changed) in the background.
func (s *Service) filtersChanged(ctx context.Context, old, in models.Settings) {
	oldOn, newOn := enabledIDs(old), enabledIDs(in)
	var gone []string
	kept := map[string]bool{}
	for _, l := range in.FilterLists {
		kept[l.ID] = true
	}
	for _, l := range old.FilterLists {
		if !kept[l.ID] {
			gone = append(gone, l.ID)
		}
	}
	if len(gone) > 0 {
		for _, id := range gone {
			if raw, err := s.rawPath(id); err == nil {
				os.Remove(raw)
			}
		}
		if _, err := s.store.Update(func(d *models.AppData) error {
			for _, id := range gone {
				delete(d.FilterStatus, id)
			}
			return nil
		}); err != nil {
			s.log.Warn("drop filter status", "err", err)
		}
	}
	var fresh []string
	for _, l := range in.FilterLists {
		if o, was := oldOn[l.ID]; newOn[l.ID].ID != "" && (!was || o.URL != l.URL || o.CatalogKey != l.CatalogKey) {
			fresh = append(fresh, l.ID)
		}
	}
	changed := len(gone) > 0 || len(fresh) > 0 || old.AllowedSites != in.AllowedSites || old.BlockAds != in.BlockAds || len(oldOn) != len(newOn)
	if changed {
		if _, _, err := s.compileFilters(); err != nil {
			s.log.Warn("compile filter lists", "err", err)
		}
	}
	if len(fresh) == 0 {
		return
	}
	bg := context.WithoutCancel(ctx)
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		for _, id := range fresh {
			if err := s.filterRefresh(bg, id); err != nil {
				s.log.Warn("filter list refresh failed", "list", id, "err", err)
			}
		}
	}()
}

// refreshDueFilters is the Run-loop step: refresh each enabled list that is
// due, at most once per retrySubAfter.
func (s *Service) refreshDueFilters(ctx context.Context, lastTry map[string]time.Time) {
	d := s.store.Get()
	lists := d.Settings.EnabledFilterLists()
	if len(lists) == 0 {
		return
	}
	cat, _ := s.readCatalogCache()
	for _, l := range lists {
		key := "filter:" + l.ID
		if !filterDue(l, d.FilterStatus[l.ID], cat, time.Now()) || time.Since(lastTry[key]) < retrySubAfter {
			continue
		}
		lastTry[key] = time.Now()
		if err := s.RefreshFilters(ctx, l.ID); err != nil && ctx.Err() == nil {
			s.log.Warn("filter list refresh failed", "list", l.Name, "err", err)
		}
	}
}
