package filters

import (
	"reflect"
	"strings"
	"testing"
)

func ps(suffix, exact, allowSuffix, allowExact []string) Parsed {
	m := func(l []string) map[string]struct{} {
		r := map[string]struct{}{}
		for _, s := range l {
			r[s] = struct{}{}
		}
		return r
	}
	return Parsed{Suffix: m(suffix), Exact: m(exact), AllowSuffix: m(allowSuffix), AllowExact: m(allowExact)}
}

func TestMergeDedup(t *testing.T) {
	s, w, err := Merge([]Parsed{ps([]string{"a.com", "b.a.com"}, []string{"x.a.com"}, nil, nil)}, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.Suffix, []string{"a.com"}) || len(s.Exact) != 0 || len(w) != 0 {
		t.Fatalf("got %+v %+v", s, w)
	}
}

func TestMergeListExceptionsExactOnly(t *testing.T) {
	s, _, err := Merge([]Parsed{
		ps([]string{"x.com"}, nil, nil, nil),
		ps(nil, nil, []string{"cdn.x.com"}, nil),
	}, nil, 100)
	if err != nil || !reflect.DeepEqual(s.Suffix, []string{"x.com"}) {
		t.Fatalf("broader suffix must stay: %+v %v", s, err)
	}
	s, _, _ = Merge([]Parsed{ps(nil, []string{"cdn.x.com"}, nil, []string{"cdn.x.com"})}, nil, 100)
	if s.Len() != 0 {
		t.Fatalf("exact not removed: %+v", s)
	}
	s, _, _ = Merge([]Parsed{ps([]string{"cdn.x.com"}, nil, []string{"cdn.x.com"}, nil)}, nil, 100)
	if s.Len() != 0 {
		t.Fatalf("suffix not removed: %+v", s)
	}
	// entries under the excepted name stay
	s, _, _ = Merge([]Parsed{ps([]string{"a.cdn.x.com"}, nil, []string{"cdn.x.com"}, nil)}, nil, 100)
	if !reflect.DeepEqual(s.Suffix, []string{"a.cdn.x.com"}) {
		t.Fatalf("child removed: %+v", s)
	}
}

func TestMergeAllowlistWidens(t *testing.T) {
	s, w, err := Merge([]Parsed{ps([]string{"x.com"}, nil, nil, nil)}, []string{"CDN.x.com.", "bad host"}, 100)
	if err != nil || s.Len() != 0 {
		t.Fatalf("got %+v %v", s, err)
	}
	if !reflect.DeepEqual(w, []Widened{{Allowed: "cdn.x.com", Unblocked: "x.com"}}) {
		t.Fatalf("widened %+v", w)
	}
	s, w, _ = Merge([]Parsed{ps([]string{"y.com", "z.com"}, []string{"a.y.com", "q.org"}, nil, nil)}, []string{"y.com"}, 100)
	if !reflect.DeepEqual(s.Suffix, []string{"z.com"}) || !reflect.DeepEqual(s.Exact, []string{"q.org"}) || len(w) != 0 {
		t.Fatalf("got %+v %+v", s, w)
	}
}

func TestMergeLimit(t *testing.T) {
	_, _, err := Merge([]Parsed{ps([]string{"a.com", "b.com", "c.com"}, nil, nil, nil)}, nil, 2)
	want := "the chosen lists have 3 domains, more than the 2 Keyway can load; turn some off"
	if err == nil || err.Error() != want {
		t.Fatalf("got %v", err)
	}
	var sb []string
	for i := 0; i < 2001; i++ {
		sb = append(sb, "d"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+string(rune('a'+i/26%26))+string(rune('a'+i/676))+".com")
	}
	_, _, err = Merge([]Parsed{ps(sb, nil, nil, nil)}, nil, 2000)
	if err == nil || !strings.Contains(err.Error(), "2,000") {
		t.Fatalf("got %v", err)
	}
}

func TestSetMatch(t *testing.T) {
	s := Set{Suffix: []string{"x.com"}, Exact: []string{"e.org"}}
	if e, ok := s.Match("ads.x.com"); !ok || e != "domain:x.com" {
		t.Fatal(e, ok)
	}
	if e, ok := s.Match("x.com"); !ok || e != "domain:x.com" {
		t.Fatal(e, ok)
	}
	if _, ok := s.Match("x.com.evil.org"); ok {
		t.Fatal("matched")
	}
	if e, ok := s.Match("e.org"); !ok || e != "full:e.org" {
		t.Fatal(e, ok)
	}
	if _, ok := s.Match("a.e.org"); ok {
		t.Fatal("exact matched subdomain")
	}
}

func TestMergeWidenedEveryEntry(t *testing.T) {
	for i := 0; i < 20; i++ {
		_, w, _ := Merge([]Parsed{ps([]string{"x.com"}, nil, nil, nil)}, []string{"b.x.com", "a.x.com"}, 100)
		want := []Widened{{"a.x.com", "x.com"}, {"b.x.com", "x.com"}}
		if !reflect.DeepEqual(w, want) {
			t.Fatalf("got %+v", w)
		}
	}
}

func TestGroupDigits(t *testing.T) {
	for n, want := range map[int]string{0: "0", 999: "999", 1000: "1,000", 2000000: "2,000,000", -1234: "-1,234"} {
		if got := groupDigits(n); got != want {
			t.Errorf("%d: got %q want %q", n, got, want)
		}
	}
}
