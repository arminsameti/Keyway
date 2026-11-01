package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"keyway/internal/link"
	"keyway/internal/models"
)

// ImportResult summarises an import.
type ImportResult struct {
	Added  int      `json:"added"`
	Errors []string `json:"errors"`
	Total  int      `json:"total"`
}

func newID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// mergeNodes appends nodes whose ID is not present yet and returns how many were added.
func mergeNodes(d *models.AppData, nodes []models.Node, source string) int {
	exist := make(map[string]bool, len(d.Nodes))
	for _, n := range d.Nodes {
		exist[n.ID] = true
	}
	added := 0
	for _, n := range nodes {
		if exist[n.ID] {
			continue
		}
		n.Source = source
		d.Nodes = append(d.Nodes, n)
		exist[n.ID] = true
		added++
	}
	return added
}

// Import adds share links from text. http(s):// entries are treated as
// subscription URLs (and become persisted subscriptions); a pasted subscription
// link is never mistaken for a proxy node.
func (s *Service) Import(ctx context.Context, text, subURL string) (ImportResult, error) {
	// Same classification as the preview, so what the sheet shows is what is added.
	var urls []string
	var nodes []models.Node
	var errs []string
	for _, it := range link.Classify(text) {
		switch it.Kind {
		case link.KindReady:
			nodes = append(nodes, it.Result.Node)
		case link.KindSubscription:
			urls = append(urls, it.URL)
		default:
			errs = append(errs, skipMessage(it))
		}
	}
	if strings.TrimSpace(subURL) != "" {
		urls = append(urls, strings.TrimSpace(subURL))
	}
	var res ImportResult
	if len(nodes) > 0 {
		if _, err := s.store.Update(func(d *models.AppData) error {
			res.Added += mergeNodes(d, nodes, "")
			return nil
		}); err != nil {
			return res, err
		}
		s.fetchEnginesFor(nodes)
	}
	for _, u := range urls {
		_, added, serrs, err := s.AddSubscription(ctx, "", u)
		if err != nil {
			errs = append(errs, fmt.Sprintf("subscription %s: %v", hostOf(u), err))
			continue
		}
		res.Added += added
		errs = append(errs, serrs...)
	}
	res.Errors = errs
	res.Total = len(s.store.Get().Nodes)
	if res.Errors == nil {
		res.Errors = []string{}
	}
	return res, nil
}

func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return "url"
}

// AddSubscription registers a subscription URL and fetches its nodes once.
func (s *Service) AddSubscription(ctx context.Context, name, rawURL string) (models.Subscription, int, []string, error) {
	u, err := ValidateURL(rawURL)
	if err != nil {
		return models.Subscription{}, 0, nil, err
	}
	rawURL = u.String()
	for _, sub := range s.store.Get().Subscriptions {
		if sub.URL == rawURL {
			added, _, errs, err := s.RefreshSubscription(ctx, sub.ID)
			return sub, added, errs, err
		}
	}
	if strings.TrimSpace(name) == "" {
		name = u.Host
	}
	sub := models.Subscription{ID: newID(), Name: strings.TrimSpace(name), URL: rawURL}
	if _, err := s.store.Update(func(d *models.AppData) error {
		d.Subscriptions = append(d.Subscriptions, sub)
		return nil
	}); err != nil {
		return sub, 0, nil, err
	}
	added, _, errs, err := s.RefreshSubscription(ctx, sub.ID)
	if err != nil {
		// Keep the subscription (the user can retry) but report the failure.
		return sub, 0, errs, err
	}
	sub, _ = s.findSub(sub.ID)
	return sub, added, errs, nil
}

func (s *Service) findSub(id string) (models.Subscription, bool) {
	for _, sub := range s.store.Get().Subscriptions {
		if sub.ID == id {
			return sub, true
		}
	}
	return models.Subscription{}, false
}

// RefreshSubscription re-downloads one subscription and reconciles its nodes:
// new links are added, vanished ones removed, surviving ones keep their latency.
func (s *Service) RefreshSubscription(ctx context.Context, id string) (added, removed int, errs []string, err error) {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	sub, ok := s.findSub(id)
	if !ok {
		return 0, 0, nil, ErrNodeNotFound
	}

	var format string
	record := func(msg string, n int) {
		_, _ = s.store.Update(func(d *models.AppData) error {
			for i := range d.Subscriptions {
				if d.Subscriptions[i].ID == id {
					d.Subscriptions[i].LastError = msg
					if msg == "" {
						d.Subscriptions[i].UpdatedAt = time.Now().UTC()
						d.Subscriptions[i].NodeCount = n
						d.Subscriptions[i].Format = format
					}
				}
			}
			return nil
		})
	}

	body, err := s.fetch(ctx, sub.URL)
	if err != nil {
		record(err.Error(), 0)
		return 0, 0, nil, err
	}
	format = link.DetectFormat(body)
	var nodes []models.Node
	var perrs []string
	for _, it := range link.Classify(body) {
		switch it.Kind {
		case link.KindReady:
			nodes = append(nodes, it.Result.Node)
		case link.KindSkipped:
			perrs = append(perrs, skipMessage(it))
		}
	}
	if len(nodes) == 0 {
		err = errors.New("no usable nodes found in the subscription")
		if len(perrs) > 0 {
			err = fmt.Errorf("%w (%s)", err, perrs[0])
		}
		record(err.Error(), 0)
		return 0, 0, perrs, err
	}

	fresh := make(map[string]models.Node, len(nodes))
	for _, n := range nodes {
		fresh[n.ID] = n
	}
	_, err = s.store.Update(func(d *models.AppData) error {
		kept := make([]models.Node, 0, len(d.Nodes))
		have := map[string]bool{}
		for _, n := range d.Nodes {
			if n.Source == id {
				f, still := fresh[n.ID]
				if !still {
					removed++
					continue
				}
				n.Name, n.Server, n.Port = f.Name, f.Server, f.Port // follow server-side renames
			}
			have[n.ID] = true
			kept = append(kept, n)
		}
		d.Nodes = kept
		for _, n := range nodes {
			if have[n.ID] {
				continue
			}
			n.Source = id
			d.Nodes = append(d.Nodes, n)
			added++
		}
		if _, ok := d.FindNode(d.ActiveNodeID); !ok {
			d.ActiveNodeID = ""
		}
		return nil
	})
	if err != nil {
		return 0, 0, perrs, err
	}
	record("", len(nodes))
	s.fetchEnginesFor(nodes)
	return added, removed, perrs, nil
}

// RemoveSubscription deletes a subscription together with the nodes it provided.
func (s *Service) RemoveSubscription(id string) error {
	if _, ok := s.findSub(id); !ok {
		return ErrNodeNotFound
	}
	_, err := s.store.Update(func(d *models.AppData) error {
		subs := d.Subscriptions[:0]
		for _, sub := range d.Subscriptions {
			if sub.ID != id {
				subs = append(subs, sub)
			}
		}
		d.Subscriptions = subs
		keep := d.Nodes[:0]
		for _, n := range d.Nodes {
			if n.Source != id {
				keep = append(keep, n)
			}
		}
		d.Nodes = keep
		if _, ok := d.FindNode(d.ActiveNodeID); !ok {
			d.ActiveNodeID = ""
		}
		return nil
	})
	return err
}

// RefreshAllSubscriptions refreshes every subscription, collecting per-subscription failures.
func (s *Service) RefreshAllSubscriptions(ctx context.Context) (added, removed int, errs []string) {
	for _, sub := range s.store.Get().Subscriptions {
		a, r, perrs, err := s.RefreshSubscription(ctx, sub.ID)
		added += a
		removed += r
		errs = append(errs, perrs...)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", sub.Name, err))
		}
	}
	return added, removed, errs
}

// skipMessage names a skipped entry without echoing the link itself.
func skipMessage(it link.Item) string {
	if it.Label != "" {
		return it.Label + ": " + it.Reason
	}
	return fmt.Sprintf("line %d: %s", it.Line, it.Reason)
}
