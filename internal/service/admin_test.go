package service

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestTouchIDForSudo(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"enabled in sudo_local", map[string]string{"/etc/pam.d/sudo_local": "# local\nauth       sufficient     pam_tid.so\n"}, true},
		{"commented out", map[string]string{"/etc/pam.d/sudo_local": "# auth       sufficient     pam_tid.so\n"}, false},
		{"enabled in the older sudo file", map[string]string{"/etc/pam.d/sudo": "auth       sufficient     pam_tid.so\nauth required pam_opendirectory.so\n"}, true},
		{"not mentioned", map[string]string{"/etc/pam.d/sudo": "auth required pam_opendirectory.so\n"}, false},
		{"no files", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			read := func(p string) ([]byte, error) {
				if s, ok := c.files[p]; ok {
					return []byte(s), nil
				}
				return nil, os.ErrNotExist
			}
			if got := touchIDForSudo(read); got != c.want {
				t.Errorf("touchIDForSudo = %v, want %v", got, c.want)
			}
		})
	}
}

func TestAdminCommandUsesSudoWhenTouchIDIsSetUp(t *testing.T) {
	args := []string{"/path/helper", "run-copy", "--bin", "/x y/sing-box"}
	primary, fallback := adminCommandFor(true, args, "Keyway needs to start TUN")
	if !reflect.DeepEqual(primary, append([]string{"/usr/bin/sudo", "--"}, args...)) {
		t.Errorf("primary = %v", primary)
	}
	if len(fallback) != 3 || fallback[0] != "/usr/bin/osascript" || !strings.Contains(fallback[2], "with administrator privileges") {
		t.Errorf("fallback = %v, want the password dialog", fallback)
	}

	primary, fallback = adminCommandFor(false, args, "Keyway needs to start TUN")
	if primary[0] != "/usr/bin/osascript" || fallback != nil {
		t.Errorf("without Touch ID: primary %v fallback %v", primary, fallback)
	}
	if !strings.Contains(primary[2], `with prompt "Keyway needs to start TUN"`) {
		t.Errorf("the dialog should say why it asks: %s", primary[2])
	}
}
