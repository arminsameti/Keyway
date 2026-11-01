package service

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"keyway/internal/core"
)

// Job is a background engine download the UI can follow.
type Job struct {
	ID       string    `json:"id"`
	Engine   string    `json:"engine"`
	Version  string    `json:"version,omitempty"` // set once known
	State    string    `json:"state"`             // running done failed
	Done     int64     `json:"done"`              // bytes downloaded
	Total    int64     `json:"total"`             // -1 when unknown
	Error    string    `json:"error,omitempty"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished,omitempty"`
}

type jobs struct {
	mu   sync.Mutex
	seq  atomic.Int64
	byID map[string]*Job
}

func (j *jobs) snapshot() []Job {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]Job, 0, len(j.byID))
	for _, jb := range j.byID {
		out = append(out, *jb)
	}
	return out
}

// Jobs lists engine downloads that are running or finished in the last hour.
func (s *Service) Jobs() []Job {
	s.jobs.mu.Lock()
	for id, jb := range s.jobs.byID {
		if jb.State != "running" && time.Since(jb.Finished) > time.Hour {
			delete(s.jobs.byID, id)
		}
	}
	s.jobs.mu.Unlock()
	return s.jobs.snapshot()
}

// Job returns one download job.
func (s *Service) Job(id string) (Job, bool) {
	s.jobs.mu.Lock()
	defer s.jobs.mu.Unlock()
	jb, ok := s.jobs.byID[id]
	if !ok {
		return Job{}, false
	}
	return *jb, true
}

// StartEngineDownload downloads an engine in the background and returns the job
// to follow. If that engine is already downloading, its running job is returned.
func (s *Service) StartEngineDownload(name, version string) (Job, error) {
	if _, err := s.mustSlot(name); err != nil {
		return Job{}, err
	}
	s.jobs.mu.Lock()
	if s.jobs.byID == nil {
		s.jobs.byID = map[string]*Job{}
	}
	for _, jb := range s.jobs.byID {
		if jb.Engine == name && jb.State == "running" {
			out := *jb
			s.jobs.mu.Unlock()
			return out, nil
		}
	}
	jb := &Job{ID: strconv.FormatInt(s.jobs.seq.Add(1), 10), Engine: name, State: "running", Total: -1, Started: time.Now().UTC()}
	s.jobs.byID[jb.ID] = jb
	out := *jb
	s.jobs.mu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		ctx = core.WithProgress(ctx, func(done, total int64) {
			s.jobs.mu.Lock()
			jb.Done, jb.Total = done, total
			s.jobs.mu.Unlock()
		})
		v, err := s.DownloadEngine(ctx, name, version)
		for errors.Is(err, ErrBusy) && ctx.Err() == nil { // another engine is downloading: wait our turn
			time.Sleep(time.Second)
			v, err = s.DownloadEngine(ctx, name, version)
		}
		s.jobs.mu.Lock()
		jb.Finished = time.Now().UTC()
		if err != nil {
			jb.State, jb.Error = "failed", err.Error()
			s.log.Warn("engine download failed", "engine", name, "err", err)
		} else {
			jb.State, jb.Version = "done", v
		}
		s.jobs.mu.Unlock()
	}()
	return out, nil
}
