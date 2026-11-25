package filters

import "strings"

// Punycode (RFC 3492) encoder, hand-written because golang.org/x/net/idna
// would be a new dependency. Encode only; lists never need decoding.
const (
	pcBase        = 36
	pcTMin        = 1
	pcTMax        = 26
	pcSkew        = 38
	pcDamp        = 700
	pcInitialBias = 72
	pcInitialN    = 128
)

func pcDigit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}

func pcAdapt(delta, numPoints int, first bool) int {
	if first {
		delta /= pcDamp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := 0
	for delta > ((pcBase-pcTMin)*pcTMax)/2 {
		delta /= pcBase - pcTMin
		k += pcBase
	}
	return k + (pcBase-pcTMin+1)*delta/(delta+pcSkew)
}

// punycodeEncode returns the RFC 3492 encoding of s (without the "xn--"
// prefix). Callers lowercase first.
func punycodeEncode(s string) string {
	runes := []rune(s)
	var out strings.Builder
	for _, r := range runes {
		if r < pcInitialN {
			out.WriteRune(r)
		}
	}
	b := out.Len()
	h := b
	if b > 0 {
		out.WriteByte('-')
	}
	n, delta, bias := pcInitialN, 0, pcInitialBias
	for h < len(runes) {
		m := int(^uint32(0) >> 1)
		for _, r := range runes {
			if int(r) >= n && int(r) < m {
				m = int(r)
			}
		}
		delta += (m - n) * (h + 1)
		n = m
		for _, r := range runes {
			if int(r) < n {
				delta++
			}
			if int(r) != n {
				continue
			}
			q := delta
			for k := pcBase; ; k += pcBase {
				t := k - bias
				if t < pcTMin {
					t = pcTMin
				} else if t > pcTMax {
					t = pcTMax
				}
				if q < t {
					break
				}
				out.WriteByte(pcDigit(t + (q-t)%(pcBase-t)))
				q = (q - t) / (pcBase - t)
			}
			out.WriteByte(pcDigit(q))
			bias = pcAdapt(delta, h+1, h == b)
			delta = 0
			h++
		}
		delta++
		n++
	}
	return out.String()
}
