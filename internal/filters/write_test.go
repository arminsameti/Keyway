package filters

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func readVarint(t *testing.T, b []byte) (uint64, []byte) {
	t.Helper()
	var v uint64
	for i := 0; i < len(b); i++ {
		v |= uint64(b[i]&0x7f) << (7 * uint(i))
		if b[i] < 0x80 {
			return v, b[i+1:]
		}
	}
	t.Fatal("truncated varint")
	return 0, nil
}

// fields decodes one protobuf message level into (field, varint, bytes).
func fields(t *testing.T, b []byte, fn func(num uint64, v uint64, data []byte)) {
	t.Helper()
	for len(b) > 0 {
		var tag uint64
		tag, b = readVarint(t, b)
		switch tag & 7 {
		case 0:
			var v uint64
			v, b = readVarint(t, b)
			fn(tag>>3, v, nil)
		case 2:
			var n uint64
			n, b = readVarint(t, b)
			if uint64(len(b)) < n {
				t.Fatal("truncated field")
			}
			fn(tag>>3, 0, b[:n])
			b = b[n:]
		default:
			t.Fatalf("unexpected wire type %d", tag&7)
		}
	}
}

type dom struct {
	Type  uint64
	Value string
}

func TestGeoSiteEncoding(t *testing.T) {
	s := Set{Suffix: []string{"a.com"}, Exact: []string{"x.b.com"}}
	var codes []string
	var doms []dom
	fields(t, encodeGeoSite("BLOCK", s), func(num, _ uint64, site []byte) {
		if num != 1 {
			t.Fatalf("GeoSiteList field %d", num)
		}
		fields(t, site, func(num, _ uint64, data []byte) {
			switch num {
			case 1:
				codes = append(codes, string(data))
			case 2:
				var d dom
				fields(t, data, func(num, v uint64, data []byte) {
					if num == 1 {
						d.Type = v
					} else if num == 2 {
						d.Value = string(data)
					}
				})
				doms = append(doms, d)
			}
		})
	})
	if !reflect.DeepEqual(codes, []string{"BLOCK"}) {
		t.Fatalf("codes = %v", codes)
	}
	want := []dom{{2, "a.com"}, {3, "x.b.com"}}
	if !reflect.DeepEqual(doms, want) {
		t.Fatalf("domains = %v, want %v", doms, want)
	}
}

func TestGeoSiteLongValueUsesMultiByteLength(t *testing.T) {
	long := strings.Repeat("a", 60) + ".com"
	s := Set{Suffix: []string{long}}
	for i := 0; i < 5; i++ {
		s.Suffix = append(s.Suffix, long+string(rune('a'+i)))
	}
	n := 0
	fields(t, encodeGeoSite("BLOCK", s), func(_ uint64, _ uint64, site []byte) {
		fields(t, site, func(num, _ uint64, _ []byte) {
			if num == 2 {
				n++
			}
		})
	})
	if n != 6 {
		t.Fatalf("decoded %d domains, want 6", n)
	}
}

func writeTestSet(t *testing.T) (string, Set) {
	t.Helper()
	dir := t.TempDir()
	s := Set{Suffix: []string{"a.com"}, Exact: []string{"x.b.com"}}
	if err := WriteAll(dir, s); err != nil {
		t.Fatal(err)
	}
	return dir, s
}

func TestSingBoxSource(t *testing.T) {
	dir, _ := writeTestSet(t)
	got, err := os.ReadFile(filepath.Join(dir, SingBoxFile))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"version":1,"rules":[{"domain":["x.b.com"],"domain_suffix":["a.com"]}]}`
	if strings.TrimSpace(string(got)) != want {
		t.Fatalf("got %s", got)
	}
}

func TestMihomoText(t *testing.T) {
	dir, _ := writeTestSet(t)
	got, err := os.ReadFile(filepath.Join(dir, MihomoFile))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "+.a.com\nx.b.com\n" {
		t.Fatalf("got %q", got)
	}
}

func TestWriteAllAtomic(t *testing.T) {
	dir, _ := writeTestSet(t)
	// overwrite once more to exercise rename-over-existing
	if err := WriteAll(dir, Set{Suffix: []string{"c.com"}}); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(dir)
	names := map[string]bool{}
	for _, e := range ents {
		names[e.Name()] = true
		if strings.Contains(e.Name(), ".tmp") {
			t.Fatalf("leftover temp file %s", e.Name())
		}
	}
	for _, n := range []string{XrayFile, SingBoxFile, MihomoFile} {
		if !names[n] {
			t.Fatalf("missing %s", n)
		}
	}
}
