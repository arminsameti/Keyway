package engine

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"keyway/internal/models"
	"keyway/internal/profile"
)

func withMihomo() []Engine { return []Engine{Xray{}, &SingBox{}, V2Ray{}, Mihomo{}} }

func withoutMihomo() []Engine { return []Engine{Xray{}, &SingBox{}, V2Ray{}} }

func anyTLSHop() profile.Profile {
	return profile.Profile{Protocol: profile.AnyTLS, Server: "t.example", Port: 443, Password: "p",
		Security: profile.Security{Kind: "tls", SNI: "t.example"}}
}

func vlessTLSHop() profile.Profile {
	return profile.Profile{Protocol: profile.VLESS, Server: "v.example", Port: 443, UUID: testUUID,
		Transport: profile.Transport{Type: "tcp"}, Security: profile.Security{Kind: "tls", SNI: "v.example"}}
}

func hy2Hop() profile.Profile {
	return profile.Profile{Protocol: profile.Hysteria2, Server: "h.example", Port: 443, Password: "p"}
}

func plan(t *testing.T, hops []profile.Profile, pref string, engines []Engine, installed func(string) bool, final string) ([]string, error) {
	t.Helper()
	steps, err := PlanSegments(hops, pref, engines, installed, final)
	var out []string
	for _, s := range steps {
		out = append(out, s.Engine.Name()+":"+string(rune('0'+s.From))+"-"+string(rune('0'+s.To)))
	}
	return out, err
}

// Existing users must see no change: with any preference but mihomo, adding the
// engine to the list changes no plan, whichever engines are installed.
func TestMihomoNeverChangesADefaultPlan(t *testing.T) {
	chains := map[string][]profile.Profile{
		"vmess":              {vmessHop()},
		"reality":            {realityHop()},
		"hysteria2":          {hy2Hop()},
		"anytls":             {anyTLSHop()},
		"vless+anytls":       {vlessTLSHop(), anyTLSHop()},
		"vmess+vless":        {vmessHop(), vlessTLSHop()},
		"vmess+reality":      {vmessHop(), realityHop()},
		"anytls+vless":       {anyTLSHop(), vlessTLSHop()},
		"vless+anytls+vless": {vlessTLSHop(), anyTLSHop(), vlessTLSHop()},
	}
	installs := map[string]func(string) bool{
		"everything":       everyInstalled,
		"only mihomo+xray": func(n string) bool { return n == NameMihomo || n == NameXray },
		"only mihomo":      func(n string) bool { return n == NameMihomo },
		"nothing":          func(string) bool { return false },
	}
	for _, pref := range []string{NameXray, NameSingBox, NameV2Ray} {
		for cname, hops := range chains {
			for iname, inst := range installs {
				want, werr := plan(t, hops, pref, withoutMihomo(), inst, "")
				got, gerr := plan(t, hops, pref, withMihomo(), inst, "")
				if !reflect.DeepEqual(got, want) || (gerr == nil) != (werr == nil) {
					t.Errorf("pref=%s chain=%s installed=%s: plan %v (%v), was %v (%v)", pref, cname, iname, got, gerr, want, werr)
				}
				for _, s := range got {
					if strings.HasPrefix(s, NameMihomo) {
						t.Errorf("pref=%s chain=%s installed=%s: ran on Mihomo: %v", pref, cname, iname, got)
					}
				}
			}
		}
	}
}

func TestMihomoPreferencePicksSupportedServers(t *testing.T) {
	got, err := plan(t, []profile.Profile{vmessHop()}, NameMihomo, withMihomo(), everyInstalled, "")
	if err != nil || !reflect.DeepEqual(got, []string{"mihomo:0-1"}) {
		t.Fatalf("vmess: %v, %v", got, err)
	}
	// a TCP chain Mihomo cannot run whole (AnyTLS inside a chain) is not split in Mihomo's favour
	got, err = plan(t, []profile.Profile{vlessTLSHop(), anyTLSHop()}, NameMihomo, withMihomo(), everyInstalled, "")
	if err != nil || len(got) != 1 {
		t.Fatalf("tcp chain: %v, %v", got, err)
	}
	// a server Mihomo cannot run keeps its usual engine
	bad := vlessTLSHop()
	bad.Flow = "xtls-rprx-vision-udp443"
	got, err = plan(t, []profile.Profile{bad}, NameMihomo, withMihomo(), everyInstalled, "")
	if err != nil || got[0] != "xray:0-1" {
		t.Fatalf("unsupported on mihomo: %v, %v", got, err)
	}
}

func TestMihomoPreferenceWithoutTheBinaryFallsBack(t *testing.T) {
	installed := func(n string) bool { return n != NameMihomo }
	got, err := plan(t, []profile.Profile{vmessHop()}, NameMihomo, withMihomo(), installed, "")
	if err != nil {
		t.Fatal(err)
	}
	// the planner still prefers an installed engine in a tie
	if got[0] == "mihomo:0-1" {
		t.Fatalf("planned an engine that is not installed: %v", got)
	}
}

func TestMihomoThenSingBoxRelayForTUN(t *testing.T) {
	got, err := plan(t, []profile.Profile{vmessHop()}, NameMihomo, withMihomo(), everyInstalled, NameSingBox)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"mihomo:0-1", "sing-box:1-1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("plan = %v, want %v", got, want)
	}
}

func TestSelectNeverReturnsMihomoUnlessChosen(t *testing.T) {
	onlyMihomo := func(n string) bool { return n == NameMihomo }
	e, err := Select(vmessHop(), NameXray, withMihomo(), onlyMihomo)
	if e.Name() == NameMihomo {
		t.Fatalf("Select picked Mihomo under the Xray preference (err %v)", err)
	}
	e, err = Select(vmessHop(), NameMihomo, withMihomo(), everyInstalled)
	if err != nil || e.Name() != NameMihomo {
		t.Fatalf("Select = %v, %v", e, err)
	}
}

func TestMihomoIsOptInAndNeedsNoRelay(t *testing.T) {
	var m Engine = Mihomo{}
	if o, ok := m.(OptIn); !ok || !o.OptIn() {
		t.Fatal("Mihomo must be opt-in")
	}
	if _, ok := m.(RelayRequired); ok {
		t.Fatal("Mihomo serves the user's apps itself")
	}
	if m.Name() != "mihomo" || m.DisplayName() != "Mihomo" {
		t.Fatalf("names: %s / %s", m.Name(), m.DisplayName())
	}
}

func TestMihomoLaunchAndCheckUseTheSharedHomeDirectory(t *testing.T) {
	dir := t.TempDir()
	in := Install{Version: "v1.19.33", Bin: filepath.Join(dir, "v1.19.33", "mihomo"), AssetDir: filepath.Join(dir, "v1.19.33")}
	l := Mihomo{}.Launch(in, "/x/config.json")
	home := filepath.Join(dir, "data")
	want := []string{"-d", home, "-f", "/x/config.json"}
	if l.Binary != in.Bin || !reflect.DeepEqual(l.Args, want) {
		t.Fatalf("launch = %+v", l)
	}
	if got := mihomoCheckArgs(in, "/x/config.json"); !reflect.DeepEqual(got, []string{"-t", "-d", home, "-f", "/x/config.json"}) {
		t.Fatalf("check args = %v", got)
	}
}

func TestMihomoNeedsGeoData(t *testing.T) {
	var m Engine = Mihomo{}
	gd, ok := m.(GeoDataUser)
	if !ok {
		t.Fatal("Mihomo must report the geodata it needs")
	}
	if got := gd.GeoData(models.DefaultSettings()); !reflect.DeepEqual(got, []string{"GeoSite.dat"}) {
		t.Fatalf("geodata = %v", got)
	}
}
