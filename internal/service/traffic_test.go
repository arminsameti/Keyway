package service

import "testing"

func TestParseXrayStatsSumsEveryOutboundButTheAPI(t *testing.T) {
	up, down, err := parseXrayStats([]byte(`{"stat":[
		{"name":"outbound>>>proxy>>>traffic>>>uplink","value":"100"},
		{"name":"outbound>>>proxy>>>traffic>>>downlink","value":2000},
		{"name":"outbound>>>direct>>>traffic>>>downlink","value":"5"},
		{"name":"outbound>>>api>>>traffic>>>uplink","value":"999"},
		{"name":"inbound>>>x>>>traffic>>>uplink","value":"7"}]}`))
	if err != nil || up != 100 || down != 2005 {
		t.Fatalf("up=%d down=%d err=%v", up, down, err)
	}
	if up, down, err := parseXrayStats([]byte(`{}`)); err != nil || up != 0 || down != 0 {
		t.Errorf("empty stats: %d %d %v", up, down, err)
	}
}

func TestParseSingBoxConnections(t *testing.T) {
	up, down, err := parseSingBoxConnections([]byte(`{"downloadTotal":42,"uploadTotal":7,"connections":[]}`))
	if err != nil || up != 7 || down != 42 {
		t.Fatalf("up=%d down=%d err=%v", up, down, err)
	}
}

func TestMeterComputesSpeedFromCounterDeltas(t *testing.T) {
	m := &trafficMeter{}
	m.record(100, 1000) // first sample only primes the counters
	if m.snapshot().UpBps != 0 {
		t.Error("no speed from a single sample")
	}
	m.record(150, 1800)
	s := m.snapshot()
	if s.UpBps != 50 || s.DownBps != 800 || s.UpTotal != 150 || !s.Available || len(s.History) != 1 {
		t.Errorf("snapshot = %+v", s)
	}
	m.record(10, 10) // engine restarted: counters went backwards, no negative speed
	if m.snapshot().UpBps != 50 {
		t.Errorf("a counter reset must not produce a sample: %+v", m.snapshot())
	}
}
