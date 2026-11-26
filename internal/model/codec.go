// SPDX-License-Identifier: GPL-3.0-or-later

package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// File format.
//
// Every layer is a small JSON object with a "version" key:
//
//	{
//	  "version": 1,
//	  "mode": "proxy",
//	  "php_version": "ea-php83"
//	}
//
// The server file nests the defaults and the access table:
//
//	{
//	  "version": 1,
//	  "defaults": {"mode": "nginx"},
//	  "access": {"cache": "client"}
//	}
//
// Parsing is strict (N-6): unknown keys, keys that differ from the field
// name only in case, duplicate keys, null values, trailing data, invalid
// values and files over MaxFileSize are rejected.
const (
	FormatVersion = 1
	MaxFileSize   = 64 << 10
	maxDepth      = 16
	maxKeyLen     = 64
)

type settingsFile struct {
	Version int `json:"version"`
	Settings
}

type serverFile struct {
	Version int `json:"version"`
	Server
}

// ParseSettings parses a user or domain layer file.
func ParseSettings(data []byte) (Settings, error) {
	var f settingsFile
	if err := decodeStrict(data, &f); err != nil {
		return Settings{}, err
	}
	if err := checkVersion(f.Version); err != nil {
		return Settings{}, err
	}
	if err := f.Validate(); err != nil {
		return Settings{}, err
	}
	return f.Settings, nil
}

// MarshalSettings validates s and encodes it as a layer file.
func MarshalSettings(s Settings) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return encode(settingsFile{Version: FormatVersion, Settings: s})
}

// ParseServer parses the server layer file.
func ParseServer(data []byte) (Server, error) {
	var f serverFile
	if err := decodeStrict(data, &f); err != nil {
		return Server{}, err
	}
	if err := checkVersion(f.Version); err != nil {
		return Server{}, err
	}
	if err := f.Validate(); err != nil {
		return Server{}, err
	}
	return f.Server, nil
}

// MarshalServer validates s and encodes it as the server layer file.
func MarshalServer(s Server) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return encode(serverFile{Version: FormatVersion, Server: s})
}

func checkVersion(v int) error {
	if v != FormatVersion {
		return fmt.Errorf("%w: format version %d, want %d", ErrInvalid, v, FormatVersion)
	}
	return nil
}

func encode(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// decodeStrict decodes a single JSON object into v. Beyond
// DisallowUnknownFields it rejects what encoding/json silently accepts:
// duplicate keys (last one wins), case-insensitive key matching, null
// (leaves a pointer unset) and trailing data.
func decodeStrict(data []byte, v any) error {
	if len(data) > MaxFileSize {
		return fmt.Errorf("%w: file larger than %d bytes", ErrInvalid, MaxFileSize)
	}
	if err := checkStructure(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return nil
}

// checkStructure walks the token stream. Keys are limited to lower-case
// ASCII letters, digits and '_': all field names are lower case, so the
// case-insensitive matching of encoding/json can then only match a field
// by its exact name.
func checkStructure(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("%w: top level must be a JSON object", ErrInvalid)
	}
	if err := walkObject(dec, 1); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing data after the JSON object", ErrInvalid)
	}
	return nil
}

func walkObject(dec *json.Decoder, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("%w: nesting deeper than %d", ErrInvalid, maxDepth)
	}
	seen := make(map[string]struct{})
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInvalid, err)
		}
		key, ok := tok.(string)
		if !ok {
			return fmt.Errorf("%w: object key is not a string", ErrInvalid)
		}
		if err := checkKey(key); err != nil {
			return err
		}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("%w: duplicate key %s", ErrInvalid, quote(key))
		}
		seen[key] = struct{}{}
		if err := walkValue(dec, depth); err != nil {
			return err
		}
	}
	return closeDelim(dec)
}

func walkArray(dec *json.Decoder, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("%w: nesting deeper than %d", ErrInvalid, maxDepth)
	}
	for dec.More() {
		if err := walkValue(dec, depth); err != nil {
			return err
		}
	}
	return closeDelim(dec)
}

func closeDelim(dec *json.Decoder) error {
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return nil
}

func walkValue(dec *json.Decoder, depth int) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	switch t := tok.(type) {
	case nil:
		return fmt.Errorf("%w: null is not allowed; omit the key to inherit", ErrInvalid)
	case json.Delim:
		switch t {
		case '{':
			return walkObject(dec, depth+1)
		case '[':
			return walkArray(dec, depth+1)
		}
		return fmt.Errorf("%w: unexpected %q", ErrInvalid, rune(t))
	}
	return nil
}

func checkKey(k string) error {
	if k == "" || len(k) > maxKeyLen {
		return fmt.Errorf("%w: key %s: bad length", ErrInvalid, quote(k))
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if !isLower(c) && !isDigit(c) && c != '_' {
			return fmt.Errorf("%w: key %s: only a-z, 0-9 and '_' allowed", ErrInvalid, quote(k))
		}
	}
	return nil
}
