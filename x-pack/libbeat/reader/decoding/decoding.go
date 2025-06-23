// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package decoding

import (
	"fmt"
	"io"
)

// decoder is an interface for decoding data from an io.Reader.
type Decoder interface {
	// Decode reads and decodes data from an io reader based on the codec type.
	// It returns the decoded data and an error if the data cannot be decoded.
	Decode() ([]byte, error)
	// Next advances the decoder to the next data item and returns true if there is more data to be decoded.
	Next() bool
	// Close closes the decoder and releases any resources associated with it.
	// It returns an error if the decoder cannot be closed.
	Close() error
}

// ValueDecoder is a decoder that can decode directly to a JSON serialisable value.
type ValueDecoder interface {
	Decoder

	// decodeValue returns the current value, and its offset
	// in the stream. If the receiver is unable to provide
	// a unique offset for the value, offset will be negative.
	DecodeValue() (offset int64, val any, _ error)
}

// NewDecoder creates a new decoder based on the codec type.
// It returns a decoder type and an error if the codec type is not supported.
// If the reader config codec option is not set, it returns a nil decoder and nil error.
func NewDecoder(config DecoderConfig, r io.Reader) (Decoder, error) {
	switch {
	case config.Codec == nil:
		return nil, nil
	case config.Codec.Parquet != nil:
		return newParquetDecoder(config, r)
	case config.Codec.CSV != nil:
		return newCSVDecoder(config, r)
	default:
		return nil, fmt.Errorf("unsupported config value: %v", config)
	}
}
