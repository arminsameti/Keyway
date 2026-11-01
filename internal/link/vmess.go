package link

import (
	"encoding/json"
	"fmt"
	"strings"

	"keyway/internal/profile"
)

type vmessJSON struct {
	Ps   string `json:"ps"`
	Add  string `json:"add"`
	Port any    `json:"port"`
	ID   string `json:"id"`
	Aid  any    `json:"aid"`
	Scy  string `json:"scy"`
	Net  string `json:"net"`
	Type string `json:"type"` // header type (tcp/kcp), or grpc mode
	Host string `json:"host"`
	Path string `json:"path"`
	TLS  string `json:"tls"`
	SNI  string `json:"sni"`
	Alpn string `json:"alpn"`
	Fp   string `json:"fp"`
}

func parseVMess(raw string) (Result, error) {
	b, err := decodeB64Flexible(raw[len("vmess://"):])
	if err != nil {
		return Result{}, fmt.Errorf("vmess: invalid base64")
	}
	var v vmessJSON
	if err := json.Unmarshal(b, &v); err != nil {
		return Result{}, fmt.Errorf("vmess: invalid JSON payload")
	}
	port := anyToInt(v.Port, 443)
	if err := checkEndpoint(v.Add, port); err != nil {
		return Result{}, fmt.Errorf("vmess: %w", err)
	}
	if strings.TrimSpace(v.ID) == "" {
		return Result{}, fmt.Errorf("vmess: missing user id")
	}

	p := streamParams{
		Network:  normalizeNetwork(v.Net),
		Security: strings.ToLower(v.TLS),
		Host:     v.Host,
		Path:     v.Path,
		SNI:      v.SNI,
		ALPN:     v.Alpn,
		FP:       v.Fp,
	}
	switch p.Network {
	case "grpc":
		p.ServiceName = v.Path
		if v.Type == "multi" {
			p.Mode = "multi"
		}
	default:
		p.HeaderType = v.Type
	}
	pr := profile.Profile{
		Protocol: profile.VMess, Server: v.Add, Port: port,
		UUID: v.ID, AlterID: anyToInt(v.Aid, 0), Cipher: orDefault(v.Scy, "auto"),
	}
	if err := applyStream(&pr, p); err != nil {
		return Result{}, fmt.Errorf("vmess: %w", err)
	}
	name := orDefault(v.Ps, fmt.Sprintf("vmess-%s:%d", v.Add, port))
	return Result{Node: newNode(name, profile.VMess, v.Add, port, raw), Profile: pr}, nil
}
