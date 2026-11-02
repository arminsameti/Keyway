package service

import "testing"

func TestParseStatsV2RayOutput(t *testing.T) {
	const out = `{"stat":[{"name":"outbound>>>direct>>>traffic>>>uplink"},{"name":"outbound>>>proxy>>>traffic>>>uplink","value":"584"},{"name":"outbound>>>proxy>>>traffic>>>downlink","value":"647"},{"name":"outbound>>>hop-1>>>traffic>>>uplink","value":"1104"},{"name":"outbound>>>hop-1>>>traffic>>>downlink","value":"813"}]}`
	up, down, err := parseXrayStats([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if up != 1688 || down != 1460 {
		t.Fatalf("up %d down %d", up, down)
	}
}
