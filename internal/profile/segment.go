package profile

// Bridge is a password-protected SOCKS5 listener on 127.0.0.1 that joins two
// engine processes of one chain. Another local program cannot use it without
// the per-connection credentials.
type Bridge struct {
	Port int    `json:"port"`
	User string `json:"user"`
	Pass string `json:"pass"`
}

// Segment is a run of consecutive chain hops that one engine process runs.
// Hops are ordered entry first, exit last; each hop dials through the one
// before it.
//
//   - Upstream, when set, is the bridge of the previous segment: the first hop
//     dials through it instead of directly.
//   - Listen, when set, makes this a middle segment: instead of the user's
//     inbounds and routing rules it exposes its exit on that bridge for the
//     next segment.
type Segment struct {
	Hops     []Profile
	Upstream *Bridge
	Listen   *Bridge
}

// Single is the one-hop segment of an ordinary server.
func Single(p Profile) Segment { return Segment{Hops: []Profile{p}} }
