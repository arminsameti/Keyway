// Package store persists AppData as a JSON file.
//
// Reads return deep copies and writes are copy-on-write: Update mutates a clone,
// persists it, and only then publishes it. Concurrent readers therefore never
// observe partial state, and a failed save leaves memory and disk consistent.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"xray-friendly/internal/models"
)

const fileName = "data.json"

// DefaultDir is ~/.xray-friendly.
func DefaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}
	return filepath.Join(home, ".xray-friendly"), nil
}

// Store is a concurrency-safe JSON document store.
type Store struct {
	mu      sync.RWMutex
	dir     string
	path    string
	data    models.AppData
	warning string
}

// Open loads (or creates) the store in dir.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	s := &Store{dir: dir, path: filepath.Join(dir, fileName), data: models.DefaultAppData()}

	b, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := s.save(s.data); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, fmt.Errorf("read %s: %w", s.path, err)
	case len(b) == 0:
		// treat an empty file like a fresh install
	default:
		// Decode on top of the defaults so fields missing from older files keep sane values.
		d := models.DefaultAppData()
		if err := json.Unmarshal(b, &d); err != nil {
			quarantine := fmt.Sprintf("%s.corrupt-%d", s.path, time.Now().Unix())
			if rerr := os.Rename(s.path, quarantine); rerr != nil {
				return nil, fmt.Errorf("data file is corrupt (%v) and could not be moved aside: %w", err, rerr)
			}
			s.warning = fmt.Sprintf("data file was unreadable (%v); moved to %s and started fresh", err, filepath.Base(quarantine))
		} else {
			s.data = normalize(d)
		}
	}
	return s, nil
}

func normalize(d models.AppData) models.AppData {
	if d.Nodes == nil {
		d.Nodes = []models.Node{}
	}
	if d.Subscriptions == nil {
		d.Subscriptions = []models.Subscription{}
	}
	if d.Engines == nil {
		d.Engines = map[string]string{}
	}
	if d.EngineChecks == nil {
		d.EngineChecks = map[string]models.EngineCheck{}
	}
	if len(d.Settings.Inbounds) == 0 {
		d.Settings.Inbounds = models.DefaultSettings().Inbounds
	}
	d.Settings.Normalize()
	return d
}

// Get returns a deep copy of the current data.
func (s *Store) Get() models.AppData {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Clone()
}

// Update applies fn to a copy of the data, persists the result and publishes it.
// If fn or the save fails nothing changes. It returns a copy of the new state.
func (s *Store) Update(fn func(*models.AppData) error) (models.AppData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.data.Clone()
	if err := fn(&next); err != nil {
		return s.data.Clone(), err
	}
	next = normalize(next)
	if err := s.save(next); err != nil {
		return s.data.Clone(), err
	}
	s.data = next
	return s.data.Clone(), nil
}

// Warning reports a problem found while loading (e.g. a quarantined corrupt file).
func (s *Store) Warning() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.warning
}

// Dir is the data directory.
func (s *Store) Dir() string { return s.dir }

// save writes atomically (tmp + fsync + rename) and keeps the previous file as .bak.
func (s *Store) save(d models.AppData) error {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return fmt.Errorf("encode data: %w", err)
	}
	if prev, err := os.ReadFile(s.path); err == nil && len(prev) > 0 {
		_ = os.WriteFile(s.path+".bak", prev, 0o600)
	}
	tmp, err := os.CreateTemp(s.dir, fileName+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("write data: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("sync data: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		cleanup()
		return fmt.Errorf("replace data file: %w", err)
	}
	return nil
}
