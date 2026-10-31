// Command xf-tun-helper runs sing-box with administrator rights for TUN mode.
// It is started by the Xray Friendly backend, either after the user approved a
// system password dialog ("run-copy") or through a one-time sudoers rule
// ("run-pinned").
package main

import (
	"flag"
	"fmt"
	"os"

	"xray-friendly/internal/privileged"
)

func main() {
	if len(os.Args) < 2 {
		fail("usage: xf-tun-helper run-copy|run-pinned|install|uninstall ...")
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	switch cmd {
	case "run-copy", "run-pinned":
		var o privileged.RunOptions
		fs.StringVar(&o.Binary, "bin", "", "sing-box to copy and run (run-copy only)")
		fs.StringVar(&o.ConfigPath, "config", "", "sing-box config")
		fs.IntVar(&o.ParentPID, "parent", 0, "exit when this process is gone")
		fs.IntVar(&o.UID, "uid", 0, "user the log and status files belong to")
		fs.StringVar(&o.LogFile, "log", "", "log file")
		fs.StringVar(&o.StopFile, "stop", "", "stop when this file exists")
		fs.StringVar(&o.ReadyFile, "ready", "", "created when sing-box is running")
		fs.StringVar(&o.PIDFile, "pid", "", "helper pid file")
		_ = fs.Parse(args)
		if cmd == "run-pinned" {
			o.Binary, o.Pinned = privileged.PinnedBinary, true
		}
		if err := privileged.Run(o); err != nil {
			fail(err.Error())
		}
	case "install":
		var singbox, user string
		fs.StringVar(&singbox, "bin", "", "sing-box to install")
		fs.StringVar(&user, "user", "", "user allowed to run run-pinned")
		_ = fs.Parse(args)
		self, err := os.Executable()
		if err != nil {
			fail(err.Error())
		}
		if err := privileged.Install(self, singbox, user); err != nil {
			fail(err.Error())
		}
	case "uninstall":
		if err := privileged.Uninstall(); err != nil {
			fail(err.Error())
		}
	default:
		fail("unknown command " + cmd)
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "xf-tun-helper:", msg)
	os.Exit(1)
}
