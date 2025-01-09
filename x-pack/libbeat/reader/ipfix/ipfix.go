// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package ipfix

import (
	"bufio"
	"fmt"
	"io"
	"log"

	"github.com/google/gopacket/pcapgo"

	"github.com/elastic/elastic-agent-libs/logp"

	nf_config "github.com/elastic/beats/v7/x-pack/filebeat/input/netflow/decoder/config"
	v9 "github.com/elastic/beats/v7/x-pack/filebeat/input/netflow/decoder/v9"
)

// BufferedReader parses ipfix inputs from io streams.
type BufferedReader struct {
	// need a decoder, too
	decoder      v9.Decoder
	data         []byte
	offset       int
	rdr          *bufio.Reader
	cfg          *Config
	logger       *logp.Logger
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

	return &BufferedReader{
		decoder:      v9.DecoderV9{Logger: logger, Fields: cfg.Fields()},
		data:         data,
		offset:       0,
		cfg:          cfg,
		logger:       logger,
	}, nil
}

// Next advances the pointer to point to the next record and returns true if the next record exists.
// It will return false if there are no more records to read.
func (sr *BufferedReader) Next() bool {
	// basically, if there is something left in the file, then Next is true
	// the ipfix header is 20 bytes long
	if sr.offset + 20 > len(sr.data) {
		sr.logger.Debugw("no more records to read")
		return false
	}
	return true
}

// Record reads the current record from the current file and returns it as a JSON marshaled byte slice.
// If no more records are available, the []byte slice will be nil and io.EOF will be returned as an error.
// A JSON marshal error will be returned if the record cannot be marshalled.
func (sr *BufferedReader) Record() ([]byte, error) {
	// call the OnPacket() from v9.go / NetflowV9Protocol
	// or just copy all that into here
	// read the header
	// make session key
	// check reset
	// loop over flow sets
	//    read set header
	//    create a new buffer for the flow set
	//    append the flows we have captured to our output
	// create metadata exporter
	// loop over flows and update the exporter, etc
	// return
	// read the next packet


	header, payload, numFlowSets, err := sr.decoder.ReadPacketHeader(sr.data[sr.offset:])
	if err != nil {
		sr.logger.Debugw("Unable to read V9 header: %v", err)
		return nil, fmt.Errorf("error reading header: %w", err)
	}
	buf := payload

	sessionKey := v9.MakeSessionKey(source, header.SourceID, false)

	session := sr.Session.GetOrCreate(sessionKey)
	remote := source.String()

	sr.logger.Printf("Packet from:%s src:%d seq:%d", remote, header.SourceID, header.SequenceNo)
	if sr.detectReset {
		if prev, reset := session.CheckReset(header.SequenceNo); reset {
			sr.logger.Printf("Session %s reset (sequence=%d last=%d)", remote, header.SequenceNo, prev)
		}
	}

	for ; numFlowSets > 0; numFlowSets-- {
		set, err := sr.decoder.ReadSetHeader(buf)
		if err != nil || set.IsPadding() {
			break
		}
		if buf.Len() < set.BodyLength() {
			sr.logger.Printf("FlowSet ID %+v overflows packet from %s", set, source)
			break
		}
		body := bytes.NewBuffer(buf.Next(set.BodyLength()))
		sr.logger.Printf("FlowSet ID %d length %d", set.SetID, set.BodyLength())

		f, err := sr.parseSet(set.SetID, sessionKey, session, body)
		if err != nil {
			sr.logger.Printf("Error parsing set %d: %v", set.SetID, err)
			return nil, fmt.Errorf("error parsing set: %w", err)
		}
		flows = append(flows, f...)
	}
	metadata := header.ExporterMetadata(source)
	for idx := range flows {
		flows[idx].Exporter = metadata
		flows[idx].Timestamp = header.UnixSecs
	}
	return flows, nil



	rec, ci, err := sr.rdr.ReadPacketData()
	if rec == nil {
		sr.logger.Debugw("reached the end of the record reader", "record_reader", rec)
		return nil, io.EOF
	}
	sr.logger.Debugw("we got a packet with capture info: %w", ci)
	if err != nil {
		return nil, fmt.Errorf("failed to read packet: %w", err)
	}

	return nil, nil
}

// Close closes the stream reader and releases all resources.
// It will return an error if the fileReader fails to close.
func (sr *BufferedReader) Close() error {
	return nil
}

