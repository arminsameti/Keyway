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
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"keyway/internal/engine"
	"keyway/internal/filters"
	"keyway/internal/models"
	"keyway/internal/profile"
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
	PlaceError     string            `json:"placeError,omitempty"` // the lists could not be placed at the last connect
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
	set, widened, attr, err := s.compile()
	s.filtersMu.Lock()
	defer s.filtersMu.Unlock()
	if err != nil {
		s.mergeErr = err.Error()
		return filters.Set{}, nil, err
	}
	s.mergeErr = ""
	s.set, s.widened, s.attr = set, widened, attr
	s.compiledSum = s.sumCompiled(set)
	return set, widened, nil
}

func (s *Service) compile() (filters.Set, []filters.Widened, *attribution, error) {
	st := s.store.Get().Settings
	var parsed []filters.Parsed
	var names []string
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
			names = append(names, l.Name)
		}
	}
	if len(parsed) == 0 {
		return filters.Set{}, nil, nil, s.removeCompiled()
	}
	var allowed []string
	for _, line := range strings.Split(st.AllowedSites, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			allowed = append(allowed, line)
		}
	}
	set, widened, err := filters.Merge(parsed, allowed, s.maxMerged)
	if err != nil {
		return filters.Set{}, nil, nil, err
	}
	// the lists' own @@ rules remove entries from every list, as Merge does
	removed := map[string]struct{}{}
	for _, p := range parsed {
		for d := range p.AllowSuffix {
			removed[d] = struct{}{}
		}
		for d := range p.AllowExact {
			removed[d] = struct{}{}
		}
	}
	attr := newAttribution()
	for i, p := range parsed {
		attr.add(names[i], p, removed)
	}
	if set.Len() == 0 {
		// everything is allowlisted: nothing to place, but the tester still
		// says the allowlist let the host through
		return set, widened, attr, s.removeCompiled()
	}
	if err := filters.WriteAll(s.compiledDir(), set); err != nil {
		return filters.Set{}, nil, nil, fmt.Errorf("write compiled filters: %w", err)
	}
	return set, widened, attr, nil
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
		Widened: append([]filters.Widened{}, s.widened...), MergeError: s.mergeErr, PlaceError: s.placeErr,
	}
	// both directions: new content, and lists turned off while the running
	// connection still blocks the old set
	v.ApplyOnConnect = running && s.compiledSum != s.lastConnectHash
	s.filtersMu.Unlock()
	v.Lists = []FilterListView{}
	for _, l := range d.Settings.FilterLists {
		st := d.FilterStatus[l.ID]
		v.Lists = append(v.Lists, FilterListView{
			FilterList: l, Status: st,
			ApplyOnConnect: v.ApplyOnConnect && l.Enabled,
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

// ---- connect-time placement ----

func (s *Service) activeDir() string { return filepath.Join(s.filtersDir(), "active") }

// activeSingBoxPath is where sing-box reads the compiled (binary) rule set
// from. It is an absolute path, also under TUN, where sing-box runs elevated.
func (s *Service) activeSingBoxPath() string {
	return filepath.Join(s.activeDir(), filters.SingBoxBinaryFile)
}

// singBoxCompileTimeout bounds one `sing-box rule-set compile`.
const singBoxCompileTimeout = 60 * time.Second

// compileSingBoxRuleSet turns the compiled JSON source into the binary rule set
// with bin, the sing-box that will read it (a source set of a few hundred
// thousand domains costs sing-box hundreds of MB; the .srs form a fraction). It
// returns the path sing-box should load: the .srs, or, when compiling fails,
// the JSON copy already in the active directory. The .srs is skipped when the
// sidecar says it was built from the current hash by this very binary (path,
// size and mtime: the format a sing-box update changes). compileMu is held,
// filtersMu is not: the exec must not stall the UI's reads.
func (s *Service) compileSingBoxRuleSet(bin, sum string) string {
	srs := s.activeSingBoxPath()
	sumPath := srs + ".sum"
	fallback := filepath.Join(s.activeDir(), filters.SingBoxFile)
	key := sum
	if fi, err := os.Stat(bin); err == nil {
		key = fmt.Sprintf("%s\n%s\n%d\n%d", sum, bin, fi.Size(), fi.ModTime().UnixNano())
	}
	if b, err := os.ReadFile(sumPath); err == nil && string(b) == key {
		if _, err := os.Stat(srs); err == nil {
			return srs
		}
	}
	// a stale .srs must never be mistaken for the current one
	os.Remove(sumPath)
	tmp := srs + ".tmp"
	ctx, cancel := context.WithTimeout(context.Background(), singBoxCompileTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "rule-set", "compile", "--output", tmp,
		filepath.Join(s.compiledDir(), filters.SingBoxFile)).CombinedOutput()
	if err == nil {
		if err = os.Rename(tmp, srs); err == nil {
			err = writeFileAtomic(sumPath, []byte(key))
		}
	}
	if err != nil {
		s.log.Warn("sing-box rule-set compile failed; loading the source rule set", "err", err, "output", strings.TrimSpace(string(out)))
		os.Remove(tmp)
		os.Remove(srs)
		os.Remove(sumPath)
		return fallback
	}
	return srs
}

// previewBlock is the Block a connect would set, without placing anything; nil
// when a connect would add no filter rule.
func (s *Service) previewBlock() *profile.BlockFiles {
	if !s.store.Get().Settings.FiltersActive() {
		return nil
	}
	s.filtersMu.Lock()
	compiled := s.compiledSum != ""
	s.filtersMu.Unlock()
	if !compiled {
		return nil
	}
	return &profile.BlockFiles{SingBoxPath: s.activeSingBoxPath()}
}

// copyFileAtomic copies src into dst through a temp file in dst's directory and
// a rename, so an engine never reads a partial file.
func copyFileAtomic(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return writeFileAtomic(dst, b)
}

// placeFilterFiles copies the compiled files to where each engine of the plan
// reads them (see the Block rules in the engine configs). It returns nil, and
// places nothing, when no filter rule is wanted: Block ads off, no enabled
// list, or nothing compiled (an empty set never becomes a block rule).
//
// A placement problem never breaks connecting: it is logged, kept in
// FilterView.PlaceError and the connect goes on with Block nil, so no config
// references a file that may be missing. hash identifies the compiled set that
// was placed; the caller records it with commitConnectHash once the engine has
// started.
//
// Xray and V2Ray get the .dat in their asset directory at every step, since
// each segment is checked on its own; only the segment that routes references
// it. Mihomo gets the provider file in its home, sing-box an active copy (made
// only when the plan has a sing-box step) compiled to the binary form.
func (s *Service) placeFilterFiles(pl *connPlan) (blk *profile.BlockFiles, hash string) {
	if !s.store.Get().Settings.FiltersActive() {
		s.setPlaceError("")
		return nil, ""
	}
	// compileMu first (as compileFilters does): a compile in progress would
	// otherwise hand us a mix of old and new files.
	// Only compileMu is held across the copies and the sing-box exec; filtersMu
	// is taken briefly so the UI's reads never wait for them.
	s.compileMu.Lock()
	defer s.compileMu.Unlock()
	s.filtersMu.Lock()
	sum := s.compiledSum
	s.filtersMu.Unlock()
	if sum == "" {
		s.setPlaceError("")
		return nil, ""
	}
	sbPath, err := s.placeLocked(pl, sum)
	if err != nil {
		s.log.Warn("filter lists not placed; connecting without them", "err", err)
		s.setPlaceError(err.Error())
		return nil, ""
	}
	s.setPlaceError("")
	return &profile.BlockFiles{SingBoxPath: sbPath}, sum
}

func (s *Service) setPlaceError(msg string) {
	s.filtersMu.Lock()
	s.placeErr = msg
	s.filtersMu.Unlock()
}

// commitConnectHash records the compiled set a started connection uses; ""
// means the connection placed no lists.
func (s *Service) commitConnectHash(hash string) {
	s.filtersMu.Lock()
	s.lastConnectHash = hash
	s.filtersMu.Unlock()
}

// placeLocked does the copies; compileMu is held. It returns the path sing-box
// loads its rule set from.
func (s *Service) placeLocked(pl *connPlan, sum string) (string, error) {
	sbPath := s.activeSingBoxPath()
	src := func(name string) string { return filepath.Join(s.compiledDir(), name) }
	for k, st := range pl.steps {
		if k >= len(pl.installs) {
			break
		}
		var dir, name string
		switch st.Engine.Name() {
		case engine.NameXray, engine.NameV2Ray:
			dir, name = pl.installs[k].AssetDir, filters.XrayFile
		case engine.NameMihomo:
			dir, name = filepath.Join(filepath.Dir(pl.installs[k].AssetDir), "data"), filters.MihomoFile
		case engine.NameSingBox:
			dir, name = s.activeDir(), filters.SingBoxFile
		default:
			continue
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", fmt.Errorf("place the filter lists: %w", err)
		}
		if err := copyFileAtomic(src(name), filepath.Join(dir, name)); err != nil {
			return "", fmt.Errorf("place the filter lists for %s: %w", st.Engine.DisplayName(), err)
		}
		if st.Engine.Name() == engine.NameSingBox {
			sbPath = s.compileSingBoxRuleSet(pl.installs[k].Bin, sum)
		}
	}
	return sbPath, nil
}

// ---- rule tester and custom-URL preview ----

// TestRouteResult is the answer of the rule tester: the route match plus which
// filter list blocked the host, or whether the allowlist let it through.
type TestRouteResult struct {
	models.RouteMatch
	FilterList string `json:"filterList,omitempty"`
	AllowedBy  bool   `json:"allowedBy,omitempty"`
}

// TestRoute answers what happens to a destination, in the order the engines
// decide: filter lists (after the allowlist), BlockedSites, then the routing
// rules (nil means the rules the current routing mode generates).
func (s *Service) TestRoute(host string, port int, rules []models.RouteRule) TestRouteResult {
	st := s.store.Get().Settings
	var res TestRouteResult
	if norm, ok := filters.NormalizeHost(strings.TrimSpace(host)); ok && st.FiltersActive() {
		s.filtersMu.Lock()
		set, attr := s.set, s.attr
		s.filtersMu.Unlock()
		if hostAllowed(st.AllowedSites, norm) {
			if _, found := attr.listFor(norm); found {
				res.AllowedBy = true
			}
		} else if entry, ok := set.Match(norm); ok {
			name, _ := attr.listFor(norm)
			res.RouteMatch = models.RouteMatch{Outbound: "block", Entry: entry}
			res.FilterList = name
			return res
		}
	}
	var chain []models.RouteRule
	for _, l := range models.RouteLists(st) {
		if l.Target == "block" && len(l.Entries) > 0 {
			chain = append(chain, models.RouteRule{ID: l.ID, Enabled: true, Entries: l.Entries, Outbound: "block"})
		}
	}
	if rules == nil {
		rules = models.EffectiveRules(st)
	}
	res.RouteMatch = models.MatchRoute(append(chain, rules...), host, port)
	return res
}

// hostAllowed reports whether the allowlist covers host (the entry or a parent).
// Entries are normalized exactly as compileFilters does, so the tester and the
// engines agree.
func hostAllowed(allowed, host string) bool {
	for _, line := range strings.Split(allowed, "\n") {
		line, ok := filters.NormalizeHost(strings.TrimSpace(line))
		if ok && (host == line || strings.HasSuffix(host, "."+line)) {
			return true
		}
	}
	return false
}

// FilterPreview is what a custom list URL would contribute, without saving it.
type FilterPreview struct {
	Domains int      `json:"domains"`
	Skipped int      `json:"skipped"`
	Sample  []string `json:"sample"`
}

// PreviewFilterURL downloads and parses a custom list URL and reports counts
// and a sample, storing nothing.
func (s *Service) PreviewFilterURL(ctx context.Context, rawURL string) (FilterPreview, error) {
	resp, err := fetchList(ctx, listFetch{URL: strings.TrimSpace(rawURL), MaxBytes: maxListBytes}, s.fetchGuard)
	if err != nil {
		return FilterPreview{}, err
	}
	p, err := filters.Parse(bytes.NewReader(resp.Body))
	if err != nil {
		return FilterPreview{}, &models.ValidationError{Msg: "that URL is not a usable list: " + err.Error()}
	}
	all := make([]string, 0, len(p.Suffix)+len(p.Exact))
	for d := range p.Suffix {
		all = append(all, d)
	}
	for d := range p.Exact {
		all = append(all, d)
	}
	sort.Strings(all)
	prev := FilterPreview{Domains: len(all), Skipped: p.Skipped, Sample: all}
	if len(all) > 5 {
		prev.Sample = all[:5]
	}
	return prev, nil
}
