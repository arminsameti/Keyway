package filters

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// Engine-facing names for the compiled set.
const (
	XrayFile    = "keyway-block.dat"
	XrayCode    = "block"
	SingBoxFile = "keyway-block.json"
	MihomoFile  = "keyway-block.txt"
	Tag         = "keyway-block"

	// geositeCode is the country code stored in the .dat; engines match it
	// case-insensitively and geosite.dat stores codes upper-case.
	geositeCode = "BLOCK"

	// singBoxRuleSetVersion is the sing-box headless rule-set format version.
	singBoxRuleSetVersion = 1
)

// WriteAll writes the Xray/V2Ray geosite file, the sing-box source rule set and
// the Mihomo provider file into dir. Each file is written to a temp file and
// renamed into place, so a reader never sees a partial file.
func WriteAll(dir string, s Set) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	sb, err := singBoxSource(s)
	if err != nil {
		return err
	}
	files := []struct {
		name string
		data []byte
	}{
		{XrayFile, encodeGeoSite(geositeCode, s)},
		{SingBoxFile, sb},
		{MihomoFile, mihomoText(s)},
	}
	for _, f := range files {
		if err := writeAtomic(filepath.Join(dir, f.name), f.data); err != nil {
			return err
		}
	}
	return nil
}

func singBoxSource(s Set) ([]byte, error) {
	type rule struct {
		Domain       []string `json:"domain,omitempty"`
		DomainSuffix []string `json:"domain_suffix,omitempty"`
	}
	return json.Marshal(struct {
		Version int    `json:"version"`
		Rules   []rule `json:"rules"`
	}{singBoxRuleSetVersion, []rule{{Domain: s.Exact, DomainSuffix: s.Suffix}}})
}

func mihomoText(s Set) []byte {
	var b strings.Builder
	for _, d := range s.Suffix {
		b.WriteString("+." + d + "\n")
	}
	for _, d := range s.Exact {
		b.WriteString(d + "\n")
	}
	return []byte(b.String())
}

func writeAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(data)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		os.Remove(tmp)
		if werr != nil {
			return werr
		}
		return cerr
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
