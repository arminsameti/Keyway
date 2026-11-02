package v2ray

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"keyway/internal/models"
	"keyway/internal/profile"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// golden compares got with testdata/<name>.json. The files pin the generated
// configuration of settings that never touched the DNS controls: a change here
// means every existing user's config changed.
func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name+".json")
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(got) {
		t.Errorf("%s changed.\nwant:\n%s\ngot:\n%s", path, want, got)
	}
}

func TestGoldenDefaultConfigs(t *testing.T) {
	global := models.DefaultSettings()
	global.RoutingMode = "global"
	one := profile.Single(vless())
	stats := one
	stats.Stats = &profile.StatsAPI{Port: 20000}
	chain := profile.Segment{Hops: []profile.Profile{vmess("tcp"), vless()}}

	cases := []struct {
		name string
		seg  profile.Segment
		s    models.Settings
	}{
		{"default", one, models.DefaultSettings()},
		{"default-stats", stats, models.DefaultSettings()},
		{"default-chain", chain, models.DefaultSettings()},
		{"routing-global", one, global},
	}
	for _, c := range cases {
		b, err := BuildConfig(c.seg, c.s)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		golden(t, "v2ray-"+c.name, append(b, '\n'))
	}
	b, err := ProbeConfig(one, 20003)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "v2ray-probe", append(b, '\n'))
}
