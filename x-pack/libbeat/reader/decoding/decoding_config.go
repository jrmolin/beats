// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package decoding

import (
	"errors"
	"fmt"
	"unicode/utf8"
)

// decoderConfig contains the configuration options for instantiating a decoder.
type DecoderConfig struct {
	Codec *CodecConfig `config:"codec"`
}

// CodecConfig contains the configuration options for different codecs used by a decoder.
type CodecConfig struct {
	Parquet *ParquetCodecConfig `config:"parquet"`
	CSV     *CSVCodecConfig     `config:"csv"`
}

func (c *CodecConfig) Validate() error {
	if c.Parquet != nil && c.CSV != nil {
		return errors.New("more than one decoder configured")
	}
	return nil
}

// CSVCodecConfig contains the configuration options for the CSV codec.
type CSVCodecConfig struct {
	Enabled bool `config:"enabled"`

	// Fields is the set of field names. If it is present
	// it is used to specify the object names of returned
	// values and the FieldsPerRecord field in the csv.Reader.
	// Otherwise, names are obtained from the first
	// line of the CSV data.
	Fields []string `config:"fields_names"`

	// The fields below have the same meaning as the
	// fields of the same name in csv.Reader.
	Comma            *configRune `config:"comma"`
	Comment          configRune  `config:"comment"`
	LazyQuotes       bool        `config:"lazy_quotes"`
	TrimLeadingSpace bool        `config:"trim_leading_space"`
}

type configRune rune

func (r *configRune) Unpack(s string) error {
	if s == "" {
		return nil
	}
	n := utf8.RuneCountInString(s)
	if n != 1 {
		return fmt.Errorf("single character option given more than one character: %q", s)
	}
	_r, _ := utf8.DecodeRuneInString(s)
	*r = configRune(_r)
	return nil
}

// ParquetCodecConfig contains the configuration options for the parquet codec.
type ParquetCodecConfig struct {
	Enabled         bool `config:"enabled"`
	ProcessParallel bool `config:"process_parallel"`
	BatchSize       int  `config:"batch_size" default:"1"`
}
