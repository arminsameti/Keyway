// Package privileged is the root side of TUN mode: the checks and the process
// supervision of the small helper that runs sing-box with administrator rights.
//
// The helper executes what the user's app hands it, so it treats the config as
// untrusted: with one-time authorization any program running as the user can ask
// for it. It therefore refuses every config feature that reads or writes files
// as root, and it only runs a sing-box that root owns.
package privileged

import (
	"encoding/json"
	"fmt"
	"strings"
)

// maxConfigBytes bounds the config the helper reads.
const maxConfigBytes = 2 << 20

// forbiddenKeys name config options that make sing-box touch the file system.
var forbiddenKeys = map[string]string{
	"output":                     "writing logs to a file",
	"cache_file":                 "a cache file",
	"private_key_path":           "reading a private key file",
	"key_path":                   "reading a key file",
	"certificate_path":           "reading a certificate file",
	"certificate_directory_path": "reading a certificate directory",
	"external_ui":                "serving files from a directory",
	"external_ui_download_url":   "downloading files",
	"ech_config_path":            "reading a file",
	"config_path":                "reading a file",
}

// ValidateConfig refuses a sing-box config that would do more than route
// traffic: file access, remote rule sets, anything unexpected in the inbounds.
func ValidateConfig(raw []byte) error {
	if len(raw) > maxConfigBytes {
		return fmt.Errorf("the config is larger than %d MB", maxConfigBytes>>20)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("the config is not valid JSON: %w", err)
	}
	if err := walk(doc, ""); err != nil {
		return err
	}
	ins, _ := doc["inbounds"].([]any)
	tun := false
	for _, in := range ins {
		m, _ := in.(map[string]any)
		switch m["type"] {
		case "tun":
			tun = true
		case "socks", "http", "mixed":
			if l, _ := m["listen"].(string); l != "127.0.0.1" && l != "::1" {
				return fmt.Errorf("the %s inbound must listen on a loopback address, not %q", m["type"], l)
			}
		default:
			return fmt.Errorf("inbound type %v is not allowed", m["type"])
		}
	}
	if !tun {
		return fmt.Errorf("the config has no tun inbound")
	}
	if route, _ := doc["route"].(map[string]any); route != nil {
		sets, _ := route["rule_set"].([]any)
		for _, rs := range sets {
			if m, _ := rs.(map[string]any); m["type"] != "local" {
				return fmt.Errorf("only local rule sets are allowed")
			}
		}
	}
	return nil
}

func walk(v any, path string) error {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if why, bad := forbiddenKeys[k]; bad {
				// "output" and "path" inside a transport are harmless, but a path to a file is not
				if s, isStr := e.(string); isStr && s == "" {
					continue
				}
				if k == "output" && path != ".log" {
					continue
				}
				return fmt.Errorf("%s: %s is not allowed", strings.TrimPrefix(path+"."+k, "."), why)
			}
			if err := walk(e, path+"."+k); err != nil {
				return err
			}
		}
	case []any:
		for _, e := range x {
			if err := walk(e, path); err != nil {
				return err
			}
		}
	}
	return nil
}
