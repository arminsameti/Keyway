package filters

import "encoding/binary"

// Domain types in the geosite protobuf (v2fly/xray router.proto).
const (
	geoDomainRoot = 2 // RootDomain: the domain and its subdomains
	geoDomainFull = 3 // Full: exactly this host
)

// encodeGeoSite returns a GeoSiteList with a single GeoSite entry:
//
//	GeoSiteList{1: repeated GeoSite}
//	GeoSite{1: country_code, 2: repeated Domain}
//	Domain{1: type (varint), 2: value}
func encodeGeoSite(code string, s Set) []byte {
	var site []byte
	site = appendBytes(site, 1, []byte(code))
	for _, d := range s.Suffix {
		site = appendBytes(site, 2, encodeDomain(geoDomainRoot, d))
	}
	for _, d := range s.Exact {
		site = appendBytes(site, 2, encodeDomain(geoDomainFull, d))
	}
	return appendBytes(nil, 1, site)
}

func encodeDomain(typ uint64, value string) []byte {
	b := binary.AppendUvarint(nil, 1<<3) // field 1, varint
	b = binary.AppendUvarint(b, typ)
	return appendBytes(b, 2, []byte(value))
}

// appendBytes appends a length-delimited field (wire type 2).
func appendBytes(b []byte, field uint64, data []byte) []byte {
	b = binary.AppendUvarint(b, field<<3|2)
	b = binary.AppendUvarint(b, uint64(len(data)))
	return append(b, data...)
}
