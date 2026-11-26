package models

import (
	"reflect"
	"testing"
)

func TestSplitSites(t *testing.T) {
	got := SplitSites(" a.com, b.com\r\n\n c.com ,,")
	if want := []string{"a.com", "b.com", "c.com"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestRouteListsOrderAndDefaults(t *testing.T) {
	lists := RouteLists(Settings{RoutingMode: "bypass-private", BlockAds: true})
	var got []string
	for _, l := range lists {
		got = append(got, l.Target+":"+l.ID)
	}
	want := []string{"block:blocked-sites", "direct:mode-direct-private", "direct:mode-direct"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if lists[0].Entries[0] != "geosite:category-ads-all" || lists[2].Entries[1] != "geosite:cn" {
		t.Fatalf("defaults: %v", lists)
	}
	if n := len(RouteLists(Settings{RoutingMode: "global"})); n != 0 {
		t.Fatalf("global without ads has %d lists", n)
	}
}
