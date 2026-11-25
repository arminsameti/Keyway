package filters

import (
	"os"
	"strings"
	"testing"
)

func loadCatalogFixture(t *testing.T) Catalog {
	t.Helper()
	b, err := os.ReadFile("testdata/catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseCatalog(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestParseCatalog(t *testing.T) {
	c := loadCatalogFixture(t)
	var names []string
	for _, g := range c.Groups {
		names = append(names, g.Name)
	}
	if got := strings.Join(names, ","); got != "General,Other,Regional,Security" {
		t.Fatalf("groups = %s", got)
	}
	if len(c.Lists) != 6 {
		t.Fatalf("lists = %d", len(c.Lists))
	}
	dep, ok := c.Find("deprecated_example_list")
	if !ok || !dep.Deprecated {
		t.Fatalf("deprecated entry = %+v, %v", dep, ok)
	}
	prob, ok := c.Find("hagezi_ultimate")
	if !ok || !prob.Problematic {
		t.Fatalf("problematic entry = %+v, %v", prob, ok)
	}
	dns, ok := c.Find("adguard_dns_filter")
	if !ok || !strings.HasSuffix(dns.DownloadURL, "filter_1.txt") || dns.ExpiresSec == 0 || dns.Key != "adguard_dns_filter" {
		t.Fatalf("dns filter = %+v, %v", dns, ok)
	}
	reg, _ := c.Find("NOR_dandelion_sprouts_anti_malware_list")
	if len(reg.Languages) != 1 || reg.Languages[0] != "no" {
		t.Fatalf("languages = %v", reg.Languages)
	}
	if _, ok := c.Find("nope"); ok {
		t.Fatal("Find returned a missing key")
	}
	// Lists sort by group order: General (1) first, adguard_dns_filter has displayNumber 1.
	if c.Lists[0].Key != "adguard_dns_filter" || c.Lists[1].Key != "hagezi_ultimate" {
		t.Fatalf("order = %s, %s", c.Lists[0].Key, c.Lists[1].Key)
	}
	if c.Lists[0].Group != c.Groups[0].ID {
		t.Fatalf("first list group = %d", c.Lists[0].Group)
	}
}

func TestParseCatalogRejectsGarbage(t *testing.T) {
	for _, in := range []string{"<html>", `{"filters":[],"tags":[],"groups":[]}`,
		`{"filters":[{"filterKey":"a","downloadUrl":"http://x/y.txt"}],"tags":[],"groups":[]}`} {
		if _, err := ParseCatalog([]byte(in)); err == nil {
			t.Fatalf("expected error for %q", in)
		}
	}
}
