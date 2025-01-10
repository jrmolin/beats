// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package ipfix

import (
	"bytes"
	"fmt"
	"io"

	"github.com/elastic/beats/v7/libbeat/beat"

	"github.com/elastic/elastic-agent-libs/logp"

	nf_config "github.com/elastic/beats/v7/x-pack/filebeat/input/netflow/decoder/config"
	"github.com/elastic/beats/v7/x-pack/filebeat/input/netflow/decoder/convert"
	v9 "github.com/elastic/beats/v7/x-pack/filebeat/input/netflow/decoder/v9"
)

// BufferedReader parses ipfix inputs from io streams.
type BufferedReader struct {
	// need a decoder, too
	protocol *v9.NetflowV9Protocol
	rdr      *bytes.Buffer
	offset   int
	cfg      *Config
	logger   *logp.Logger
}

// NewBufferedReader creates a new reader that can decode parquet data from an io.Reader.
// It will return an error if the parquet data stream cannot be read.
// Note: As io.ReadAll is used, the entire data stream would be read into memory, so very large data streams
// may cause memory bottleneck issues.
func NewBufferedReader(r io.Reader, cfg *Config) (*BufferedReader, error) {
	logger := logp.L().Named("reader.ipfix")

	// figure out how to choose between zipped file and raw file

	logger.Debugw("creating ipfix reader", "internal_networks", cfg.InternalNetworks)
	logger.Debugw("creating ipfix reader", "custom_definitions", cfg.CustomDefinitions)

	logger.Debugw("creating pcap reader from stream reader")

	// create a new ipfix reader from the data
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read data from reader: %w", err)
	}

	logger.Debugw("created ipfix reader")

	logger.Debugw("supposedly created ipfix flow reader and read %r bytes", len(data))

	logger.Debugw("initialization process completed")

	// make a decoder to pass into the protocol creator
	v9Decoder := v9.DecoderV9{Logger: logger, Fields: cfg.Fields()}

	// make a new netflow config object to pass into the protocol creator
	nfConfig := nf_config.Config{}

	return &BufferedReader{
		protocol: v9.NewProtocolWithDecoder(v9Decoder, nfConfig, logger),
		rdr:      bytes.NewBuffer(data),
		offset:   0,
		cfg:      cfg,
		logger:   logger,
	}, nil
}

// Next advances the pointer to point to the next record and returns true if the next record exists.
// It will return false if there are no more records to read.
func (sr *BufferedReader) Next() bool {
	// basically, if there is something left in the file, then Next is true
	// the ipfix header is 20 bytes long
	if sr.rdr.Len() < 20 {
		sr.logger.Debugw("no more records to read")
		return false
	}
	return true
}

type DummyAddr struct {
	NetworkValue string
	StringValue  string
}

func (d DummyAddr) Network() string {
	return d.NetworkValue
}
func (d DummyAddr) String() string {
	return d.StringValue
}

func NewDummyAddr() DummyAddr {
	return DummyAddr{NetworkValue: "tcp", StringValue: "100::"}
}

// Record reads the current record from the current file and returns it as a JSON marshaled byte slice.
// If no more records are available, the []byte slice will be nil and io.EOF will be returned as an error.
// A JSON marshal error will be returned if the record cannot be marshalled.
func (sr *BufferedReader) Record() ([]beat.Event, error) {
	// call the OnPacket() from v9.go / NetflowV9Protocol
	// create metadata exporter
	// loop over flows and update the exporter, etc
	// return
	// read the next packet

	source := NewDummyAddr()

	// track how much data is left, to know how big this flow packet was
	beforeLength := sr.rdr.Len()

	// if beforeLength is not positive, then we are done
	if beforeLength < 0 {
		return nil, fmt.Errorf("No more data to read")
	}

	flows, err := sr.protocol.OnPacket(sr.rdr, source)
	if err != nil {
		return nil, err
	}

	// get the new offset
	afterLength := sr.rdr.Len()

	// make sure the before and after are not negative (>= 0)
	if afterLength >= beforeLength {
		return nil, fmt.Errorf("No more data to read")
	}

	length := beforeLength - afterLength
	if length < 0 {
		sr.logger.Infof("No data read.")
		sr.offset += length
	}

	sr.logger.Infof("Read a record of length [%v]; new offset is [%v]", length, sr.offset)

	// from here, we get an array of flows
	// we need to convert each to an event
	// we then need to marshal each event to a json blob
	// we return the json blobs

	fLen := len(flows)
	if fLen != 0 {
		evs := make([]beat.Event, fLen)
		for flowIdx, flow := range flows {
			evs[flowIdx] = convert.RecordToBeatEvent(flow, sr.cfg.InternalNetworks)
		}
		return evs, nil
	}
	return nil, nil
}

// Close closes the stream reader and releases all resources.
// It will return an error if the fileReader fails to close.
func (sr *BufferedReader) Close() error {
	return nil
}
