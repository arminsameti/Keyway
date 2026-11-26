package filters

import (
	"strings"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	const (
		none = ""
		sfx  = "suffix"
		exa  = "exact"
		asfx = "allowSuffix"
		aexa = "allowExact"
		skip = "skipped"
	)
	cases := []struct {
		line, bucket, value string
	}{
		{"||ads.example.com^", sfx, "ads.example.com"},
		{"||ads.example.com^$important", sfx, "ads.example.com"},
		{"||ads.example.com^$third-party", skip, ""},
		{"|ads.example.com^", exa, "ads.example.com"},
		{"@@||cdn.example.com^", asfx, "cdn.example.com"},
		{"@@|cdn.example.com^", aexa, "cdn.example.com"},
		{"0.0.0.0 track.example.com", exa, "track.example.com"},
		{"127.0.0.1 track.example.com # c", exa, "track.example.com"},
		{":: track.example.com", exa, "track.example.com"},
		{"0.0.0.0 localhost", skip, ""},
		{"0.0.0.0 1.2.3.4", skip, ""},
		{"plain.example.com", sfx, "plain.example.com"},
		{"Plain.Example.COM.", sfx, "plain.example.com"},
		{"bücher.de", sfx, "xn--bcher-kva.de"},
		{"! comment", none, ""},
		{"# comment", none, ""},
		{"   ", none, ""},
		{"", none, ""},
		{`/ads[0-9]+\./`, skip, ""},
		{"||*.example.com^", skip, ""},
		{"example.com##.banner", skip, ""},
		{"||example.com/path", skip, ""},
		{"|piwik.", skip, ""},
		{"com", skip, ""},
		{"||com^", skip, ""},
		{"@@||com^", skip, ""},
		{"-events-collector.spot.im^", skip, ""},
		{"ads-.example.com", skip, ""},
		{"a-b.example.com", sfx, "a-b.example.com"},
	}
	for _, c := range cases {
		t.Run(c.line, func(t *testing.T) {
			// A usable sentinel keeps Parse from failing on zero rules.
			p, err := Parse(strings.NewReader("sentinel.test\n" + c.line + "\n"))
			if err != nil {
				t.Fatal(err)
			}
			delete(p.Suffix, "sentinel.test")
			buckets := map[string]map[string]struct{}{
				sfx: p.Suffix, exa: p.Exact, asfx: p.AllowSuffix, aexa: p.AllowExact,
			}
			total := 0
			for name, m := range buckets {
				total += len(m)
				if name == c.bucket {
					if _, ok := m[c.value]; !ok || len(m) != 1 {
						t.Errorf("%s = %v, want only %q", name, m, c.value)
					}
				}
			}
			switch c.bucket {
			case none:
				if total != 0 || p.Skipped != 0 {
					t.Errorf("want ignored, got total=%d skipped=%d", total, p.Skipped)
				}
			case skip:
				if total != 0 || p.Skipped != 1 {
					t.Errorf("want skipped, got total=%d skipped=%d", total, p.Skipped)
				}
			default:
				if total != 1 || p.Skipped != 0 {
					t.Errorf("want one entry, got total=%d skipped=%d", total, p.Skipped)
				}
			}
		})
	}
}

func TestParseHTMLPage(t *testing.T) {
	page := "<!doctype html><html><head><title>Not Found</title></head>\n<body><h1>404</h1></body></html>\n"
	_, err := Parse(strings.NewReader(page))
	if err == nil || !strings.Contains(err.Error(), "no domains found") {
		t.Fatalf("err = %v, want no domains found", err)
	}
}

func TestParseSkippedCount(t *testing.T) {
	in := "||a.example.com^\n||b.example.com^$third-party\n/re/\nexample.com##.x\n! c\n\n"
	p, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if p.Skipped != 3 || len(p.Suffix) != 1 {
		t.Errorf("Skipped=%d suffix=%v, want 3 and 1 entry", p.Skipped, p.Suffix)
	}
}

func TestNormalizeHost(t *testing.T) {
	long := strings.Repeat("a", 64)
	ok := map[string]string{
		"Example.COM.":       "example.com",
		"bücher.de":          "xn--bcher-kva.de",
		"他们为什么不说中文.example":  "xn--ihqwcrb4cv8a8dqg056pqjye.example",
		"_dmarc.example.com": "_dmarc.example.com",
		"a-b.example":        "a-b.example",
	}
	for in, want := range ok {
		if got, good := NormalizeHost(in); !good || got != want {
			t.Errorf("NormalizeHost(%q) = %q,%v want %q", in, got, good, want)
		}
	}
	for _, in := range []string{
		"", ".", "1.2.3.4", "::1", "[::1]", "a..b", ".a.com", "a.com/x", "a b.com",
		"*.a.com", "a.com:80", "com", "piwik", "-a.example.com", "a-.example.com", "a.-b.com", long + ".com", strings.Repeat("a.", 130) + "com",
	} {
		if got, good := NormalizeHost(in); good {
			t.Errorf("NormalizeHost(%q) = %q, want rejection", in, got)
		}
	}
}

func TestPunycodeRFC3492(t *testing.T) {
	// Sample strings from RFC 3492 section 7.1.
	cases := map[string]string{
		"bücher":            "bcher-kva",
		"他们为什么不说中文":         "ihqwcrb4cv8a8dqg056pqjye",
		"ليهمابتكلموشعربي؟": "egbpdaj6bu4bxfgehfvwxn",
	}
	for in, want := range cases {
		if got := punycodeEncode(in); got != want {
			t.Errorf("punycodeEncode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeHostHostileLongLabel(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 100000; i++ {
		b.WriteRune(rune(0x4e00 + i%20000))
	}
	start := time.Now()
	if got, ok := NormalizeHost(b.String()); ok {
		t.Errorf("accepted a 100k-rune label: %q", got[:20])
	}
	if _, ok := NormalizeHost("a." + b.String()[:200]); ok {
		t.Error("accepted a 200-rune label")
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("took %v, want fast rejection", d)
	}
}
