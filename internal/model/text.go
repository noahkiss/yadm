package model

import (
	"encoding/base64"
	"time"
)

// Duration is a time.Duration written as a Go duration string ("2h", "30s")
// in TOML and JSON.
type Duration time.Duration

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// UnmarshalText parses a Go duration string.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// MarshalText writes a Go duration string.
func (d Duration) MarshalText() ([]byte, error) { return []byte(time.Duration(d).String()), nil }

// Base64 is a byte string written as standard base64 in TOML and JSON.
type Base64 []byte

// UnmarshalText decodes standard base64.
func (b *Base64) UnmarshalText(t []byte) error {
	v, err := base64.StdEncoding.DecodeString(string(t))
	if err != nil {
		return err
	}
	*b = v
	return nil
}

// MarshalText encodes standard base64.
func (b Base64) MarshalText() ([]byte, error) {
	return []byte(base64.StdEncoding.EncodeToString(b)), nil
}
