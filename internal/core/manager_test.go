package core

import "testing"

func TestParseSHA256V2RayDgst(t *testing.T) {
	const dgst = `MD5= ca74cedf54eeb7dbdf16fa16e9174d24
SHA1= 4d0275ac1103071f8745622fb3dd66c55fbb6351
SHA2-256= 75d0b4bf571b33aff8fb3eacb4a7ff16061a2d227503d75c5247852ef0958b15
SHA2-512= 743b2ac14225520c3fbe69d755453d24f7d8ce7fc11cdba28dbf4140fb0d7e69a090dd7819bb02bdfa97ba8e66d927c155d9cb036cb27606ab3791b23136ebda
`
	got, err := parseSHA256(dgst)
	if err != nil {
		t.Fatal(err)
	}
	if want := "75d0b4bf571b33aff8fb3eacb4a7ff16061a2d227503d75c5247852ef0958b15"; got != want {
		t.Fatalf("got %s", got)
	}
}

func TestV2RaySourceFiles(t *testing.T) {
	if len(V2RaySource.Files) != 3 {
		t.Fatalf("files = %v", V2RaySource.Files)
	}
	for _, name := range []string{"v2ray", "geoip.dat", "geosite.dat"} {
		if _, ok := V2RaySource.Files[name]; !ok {
			t.Errorf("missing %s", name)
		}
	}
}
