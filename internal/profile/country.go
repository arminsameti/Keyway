package profile

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// iso3166 lists ISO 3166-1 alpha-2 codes, so a leading word like "OK" or "HQ"
// is not mistaken for a country.
const iso3166 = "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ " +
	"CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR " +
	"GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP " +
	"KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT " +
	"MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW " +
	"SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG " +
	"UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW UK"

func isCountry(cc string) bool {
	return len(cc) == 2 && strings.Contains(" "+iso3166+" ", " "+cc+" ")
}

// SplitCountry takes a country code from the start of a node name: a flag emoji
// ("🇩🇪 Frankfurt") or an upper-case ISO code followed by a separator
// ("DE Frankfurt", "[DE] Frankfurt", "DE-Frankfurt"). It returns the code and
// the name without the flag. The UI shows no emoji, so a flag is always removed
// even when it is not a known country; a plain-text code is left in the name.
func SplitCountry(name string) (cc, display string) {
	s := strings.TrimSpace(name)
	if a, n1 := utf8.DecodeRuneInString(s); isRegional(a) {
		b, n2 := utf8.DecodeRuneInString(s[n1:])
		if isRegional(b) {
			code := string([]rune{'A' + (a - 0x1F1E6), 'A' + (b - 0x1F1E6)})
			rest := strings.TrimLeft(s[n1+n2:], " \t-_|·:")
			if !isCountry(code) {
				code = ""
			}
			if code == "GB" || code == "UK" {
				code = "GB"
			}
			if strings.TrimSpace(rest) == "" {
				rest = orDefault(code, "Server") // a bare flag: never show the emoji itself
			}
			return code, rest
		}
	}
	t := strings.TrimPrefix(s, "[")
	if len(t) >= 3 && isUpper(t[0]) && isUpper(t[1]) {
		sep := t[2]
		if sep == ' ' || sep == '-' || sep == '_' || sep == '|' || sep == ']' || sep == '.' {
			code := t[:2]
			if isCountry(code) {
				if code == "UK" {
					code = "GB"
				}
				return code, s
			}
		}
	}
	return "", s
}

func isRegional(r rune) bool { return r >= 0x1F1E6 && r <= 0x1F1FF }
func isUpper(b byte) bool    { return b < utf8.RuneSelf && unicode.IsUpper(rune(b)) }

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
