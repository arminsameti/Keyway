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
//   - Stats, when set on the segment that serves the user, makes the engine
//     expose its traffic counters on a loopback port.
type Segment struct {
	Hops     []Profile
	Upstream *Bridge
	Listen   *Bridge
	Stats    *StatsAPI
	TUN      *TUNOptions
}

// TUNOptions asks the segment that serves the user to capture all traffic
// through a virtual interface (sing-box only).
type TUNOptions struct {
	Stack  string
	MTU    int
	Strict bool
	// ExcludePaths are the engine programs of the other processes of the
	// connection; their own traffic must leave directly, or it would loop back
	// into the tunnel.
	ExcludePaths []string
}

// StatsAPI is the loopback endpoint an engine reports its traffic on. Secret
// protects it from other local programs where the engine supports one.
type StatsAPI struct {
	Port   int
	Secret string
}

// Single is the one-hop segment of an ordinary server.
func Single(p Profile) Segment { return Segment{Hops: []Profile{p}} }
