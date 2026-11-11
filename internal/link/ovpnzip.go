package link

import (
	"archive/zip"
	"bytes"
	"fmt"
	"path"
	"strings"
)

// Limits for OpenVPN zip bundles.
const (
	ovpnZipMaxRaw      = 10 << 20 // 10 MB zipped
	ovpnZipMaxFiles    = 200
	ovpnZipMaxTotal    = 20 << 20 // 20 MB uncompressed total
	ovpnZipMaxFile     = 1 << 20  // 1 MB per file
	ovpnZipMaxProfiles = 50
)

// ParseOVPNZip reads a zip bundle of OpenVPN profiles whose certificates live
// in sibling files (ca.crt, client.key, ta.key, ...). It returns one Item per
// .ovpn file found: ready when the profile (with its external files resolved)
// parses, skipped otherwise. A zip-level failure (not a zip, empty, too big)
// is an error.
func ParseOVPNZip(data []byte) ([]Item, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("the zip file is empty")
	}
	if len(data) > ovpnZipMaxRaw {
		return nil, fmt.Errorf("the zip file is too large (max %d MB)", ovpnZipMaxRaw>>20)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("not a zip file: %v", err)
	}
	if len(zr.File) > ovpnZipMaxFiles {
		return nil, fmt.Errorf("the zip has too many files (max %d)", ovpnZipMaxFiles)
	}

	type txtFile struct {
		name    string // zip path
		content string
	}
	var texts []txtFile
	var total int
	byFull := map[string]string{} // normalized lower path -> content
	byBase := map[string]string{} // lower basename -> content (first wins)
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := path.Clean("/" + f.Name)
		base := path.Base(name)
		if strings.HasPrefix(base, ".") || strings.HasPrefix(strings.ToLower(name), "/__macosx/") {
			continue
		}
		if f.UncompressedSize64 > ovpnZipMaxFile {
			continue // too big to be a config or PEM; skip
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		buf := make([]byte, 0, minInt(int(f.UncompressedSize64), ovpnZipMaxFile))
		tmp := make([]byte, 32*1024)
		var n int
		for {
			m, rerr := rc.Read(tmp)
			if m > 0 {
				n += m
				if n > ovpnZipMaxFile {
					break
				}
				buf = append(buf, tmp[:m]...)
			}
			if rerr != nil {
				break
			}
		}
		rc.Close()
		if n > ovpnZipMaxFile {
			continue
		}
		total += len(buf)
		if total > ovpnZipMaxTotal {
			return nil, fmt.Errorf("the zip uncompresses to too much data")
		}
		s := string(buf)
		if !isText(s) {
			continue
		}
		lowerFull := strings.ToLower(strings.TrimPrefix(name, "/"))
		lowerBase := strings.ToLower(base)
		if _, ok := byFull[lowerFull]; !ok {
			byFull[lowerFull] = s
		}
		if _, ok := byBase[lowerBase]; !ok {
			byBase[lowerBase] = s
		}
		texts = append(texts, txtFile{name: strings.TrimPrefix(name, "/"), content: s})
	}

	// Find .ovpn candidates: by extension first, then by content sniffing.
	var ovpns []txtFile
	for _, t := range texts {
		ext := strings.ToLower(path.Ext(t.name))
		if ext == ".ovpn" || ext == ".openvpn" {
			ovpns = append(ovpns, t)
		}
	}
	if len(ovpns) == 0 {
		for _, t := range texts {
			ext := strings.ToLower(path.Ext(t.name))
			if (ext == ".conf" || ext == ".txt" || ext == "") && LooksLikeOVPN(t.content) {
				ovpns = append(ovpns, t)
			}
		}
	}
	if len(ovpns) == 0 {
		return nil, fmt.Errorf("no .ovpn profile found in the zip")
	}
	if len(ovpns) > ovpnZipMaxProfiles {
		return nil, fmt.Errorf("the zip has too many profiles (max %d)", ovpnZipMaxProfiles)
	}

	lookup := func(ovpnPath, ref string) (string, bool) {
		ref = strings.Trim(ref, `"'`)
		if ref == "" || ref == "[inline]" {
			return "", false
		}
		// Same directory first, then basename anywhere.
		dir := path.Dir(ovpnPath)
		candidates := []string{
			strings.ToLower(path.Clean(dir + "/" + ref)),
			strings.ToLower(path.Base(ref)),
		}
		// Also try the ref as a full zip path.
		candidates = append(candidates, strings.ToLower(strings.TrimPrefix(path.Clean("/"+ref), "/")))
		for _, c := range candidates {
			if s, ok := byFull[c]; ok {
				return s, true
			}
			if s, ok := byBase[path.Base(c)]; ok {
				return s, true
			}
		}
		return "", false
	}

	var items []Item
	for i, o := range ovpns {
		it := Item{Line: i + 1, Scheme: "openvpn", Label: path.Base(o.name), Name: strings.TrimSuffix(path.Base(o.name), path.Ext(o.name))}
		augmented := resolveOVPNExternalRefs(o.content, func(ref string) (string, bool) {
			return lookup(o.name, ref)
		})
		res, err := ParseOVPN(augmented, it.Name)
		if err != nil {
			it.Kind, it.Reason = KindSkipped, capitalize(err.Error())
		} else {
			it.Kind, it.Result = KindReady, res
		}
		items = append(items, it)
	}
	return dedupe(items), nil
}

// resolveOVPNExternalRefs injects <ca>, <cert>, <key>, <tls-auth>,
// <tls-crypt>, <tls-crypt-v2> and <auth-user-pass> blocks from sibling files
// when the .ovpn text only references them by file name. Text that already
// embeds a block is left alone. lookup maps the referenced file name to its
// content.
func resolveOVPNExternalRefs(text string, lookup func(ref string) (string, bool)) string {
	lower := strings.ToLower(text)
	hasBlock := func(name string) bool {
		return strings.Contains(lower, "<"+name+">")
	}
	// Collect file references per directive without a full parse.
	refs := map[string]string{} // directive -> file
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' || line[0] == '<' {
			continue
		}
		args := ovpnArgs(line)
		if len(args) == 0 {
			continue
		}
		name := strings.ToLower(args[0])
		switch name {
		case "ca", "cert", "key", "tls-crypt", "tls-crypt-v2", "tls-auth", "auth-user-pass":
			if len(args) >= 2 && args[1] != "" && args[1] != "[inline]" {
				if _, ok := refs[name]; !ok {
					refs[name] = args[1]
				}
			}
		}
	}
	var extra strings.Builder
	for _, name := range []string{"ca", "cert", "key", "tls-crypt-v2", "tls-crypt", "tls-auth", "auth-user-pass"} {
		if hasBlock(name) {
			continue
		}
		ref, ok := refs[name]
		if !ok {
			continue
		}
		content, found := lookup(ref)
		if !found {
			continue // leave the original error to ParseOVPNProfile
		}
		content = strings.Trim(content, "\r\n")
		if content == "" {
			continue
		}
		extra.WriteString("\n<" + name + ">\n" + content + "\n</" + name + ">\n")
	}
	if extra.Len() == 0 {
		return text
	}
	return text + extra.String()
}

// isText reports whether s looks like text (no NUL bytes, mostly printable).
func isText(s string) bool {
	if strings.ContainsRune(s, 0) {
		return false
	}
	// Sample the first 8KB: allow mostly printable, whitespace and PEM base64.
	n := len(s)
	if n > 8192 {
		n = 8192
	}
	if n == 0 {
		return true
	}
	bad := 0
	for i := 0; i < n; i++ {
		c := s[i]
		if c < 32 && c != '\n' && c != '\r' && c != '\t' {
			bad++
		}
	}
	return bad*8 < n // less than ~12% control bytes
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
