package service

import (
	"context"
	"time"
)

const (
	loopInterval   = time.Minute
	retrySubAfter  = 15 * time.Minute // do not hammer a failing subscription server
	autoConnectCap = 30 * time.Second
)

// Run is the background housekeeping loop: auto-connect at launch, periodic
// auto-pick and subscription refresh. It returns when ctx is cancelled.
func (s *Service) Run(ctx context.Context) {
	s.autoConnect(ctx)

	ticker := time.NewTicker(loopInterval)
	defer ticker.Stop()
	var lastPick time.Time
	lastTry := map[string]time.Time{}   // only touched by this goroutine
	lastCheck := map[string]time.Time{} // engine update checks, same

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		d := s.store.Get()

		interval := time.Duration(d.Settings.AutoPickMin) * time.Minute
		if d.Settings.AutoPick && len(d.Nodes) > 0 && time.Since(lastPick) >= interval {
			lastPick = time.Now()
			if _, err := s.AutoPickOnce(ctx); err != nil && ctx.Err() == nil {
				s.log.Warn("auto-pick failed", "err", err)
			}
		}

		if every := checkInterval(d.Settings.EngineUpdateCheck); every > 0 {
			for _, sl := range s.engines {
				name := sl.Engine.Name()
				if !s.installed(name) || time.Since(d.EngineChecks[name].CheckedAt) < every ||
					time.Since(lastCheck[name]) < retrySubAfter {
					continue
				}
				lastCheck[name] = time.Now()
				if _, err := s.CheckEngine(ctx, name); err != nil && ctx.Err() == nil {
					s.log.Warn("engine update check failed", "engine", name, "err", err)
				}
			}
		}

		s.maybeCheckApp(ctx)

		if d.Settings.SubUpdateHours > 0 {
			for _, sub := range d.Subscriptions {
				if !subscriptionDue(d.Settings.SubUpdateHours, sub.UpdateHours, sub.UpdatedAt) ||
					time.Since(lastTry[sub.ID]) < retrySubAfter {
					continue
				}
				lastTry[sub.ID] = time.Now()
				if _, _, _, err := s.RefreshSubscription(ctx, sub.ID); err != nil && ctx.Err() == nil {
					s.log.Warn("subscription refresh failed", "sub", sub.Name, "err", err)
				}
			}
		}
	}
}

func (s *Service) autoConnect(ctx context.Context) {
	d := s.store.Get()
	if !d.Settings.AutoConnect || d.ActiveNodeID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, autoConnectCap)
	defer cancel()
	if _, err := s.Connect(ctx); err != nil {
		s.log.Warn("auto-connect failed", "err", err)
	}
}

// checkInterval maps the update-check setting to a period (0 = never).
func checkInterval(setting string) time.Duration {
	switch setting {
	case "daily":
		return 24 * time.Hour
	case "weekly":
		return 7 * 24 * time.Hour
	}
	return 0
}
