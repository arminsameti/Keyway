package api

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"keyway/internal/models"
)

// decodeZipBody reads {"data": "<base64 zip>"} and returns the raw zip bytes.
func decodeZipBody(r *http.Request) ([]byte, error) {
	var b struct {
		Data     string `json:"data"`
		Filename string `json:"filename"`
	}
	if err := decode(r, &b, false); err != nil {
		return nil, err
	}
	s := strings.TrimSpace(b.Data)
	if s == "" {
		return nil, &models.ValidationError{Msg: "no zip data provided"}
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
			return nil, &models.ValidationError{Msg: fmt.Sprintf("invalid zip data: %v", err)}
		}
	}
	if len(data) == 0 {
		return nil, &models.ValidationError{Msg: "the zip file is empty"}
	}
	return data, nil
}
