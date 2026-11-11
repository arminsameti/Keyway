package api

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"keyway/internal/models"
	"keyway/internal/service"
)

// decodeZipBody reads {"data": "<base64 zip>"} and returns the raw zip bytes
// plus any import-time credentials.
func decodeZipBody(r *http.Request) ([]byte, service.Credentials, error) {
	var b struct {
		Data     string `json:"data"`
		Filename string `json:"filename"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &b, false); err != nil {
		return nil, service.Credentials{}, err
	}
	creds, err := service.ValidateCredentials(b.Username, b.Password)
	if err != nil {
		return nil, service.Credentials{}, err
	}
	s := strings.TrimSpace(b.Data)
	if s == "" {
		return nil, service.Credentials{}, &models.ValidationError{Msg: "no zip data provided"}
	}
	// Allow data-URL form ("data:application/zip;base64,...").
	if i := strings.Index(s, ","); strings.HasPrefix(s, "data:") && i >= 0 {
		s = s[i+1:]
	}
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s)
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		// Try raw (unpadded) encoding as well.
		var err2 error
		data, err2 = base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
		if err2 != nil {
			return nil, service.Credentials{}, &models.ValidationError{Msg: fmt.Sprintf("invalid zip data: %v", err)}
		}
	}
	if len(data) == 0 {
		return nil, service.Credentials{}, &models.ValidationError{Msg: "the zip file is empty"}
	}
	return data, creds, nil
}
