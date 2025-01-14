// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package ipfix

import (
	"fmt"
	"os"
	"testing"

	"github.com/elastic/elastic-agent-libs/logp"
)

// all test files are read from/stored within the "testdata" directory
const testDataPath = "testdata"

func TestIpfixWithRandomData(t *testing.T) {
	testCases := []struct {
		path    string
	}{
		{
			path: "do-not-commit.ipfix",
		},
	}

	logp.TestingSetup()
	for _, tc := range testCases {
		name := fmt.Sprintf("Test ipfix files with name=%s", tc.path)
		t.Run(name, func(t *testing.T) {
			fName := fmt.Sprintf("./%s", tc.path)
			file, err := os.Open(fName)
			if err != nil {
				t.Fatalf("Failed to open ipfix test file: %v", err)
			}
			defer file.Close()

			t.Logf("Processing file %v", fName)

			cfg := &Config{
				// we set ProcessParallel to true as this always has the best performance
				InternalNetworks: nil,
				// batch size is set to 1 because we need to compare individual records one by one
				CustomDefinitions: nil,
			}
			rows := readAndValidateIpfixFile(t, cfg, file)
			// asserts of number of rows read is the same as the number of rows written
			t.Logf("This file had [%v] rows", rows)
			//assert.Equal(t, rows, tc.rows)
		})
	}
}


func readAndValidateIpfixFile(t *testing.T, cfg *Config, file *os.File) int {
	sReader, err := NewBufferedReader(file, cfg)
	if err != nil {
		t.Fatalf("failed to init stream reader: %v", err)
	}

	rowCount := 0
	for sReader.Next() {
		val, err := sReader.Record()
		if err != nil {
			t.Fatalf("failed to read stream: %v", err)
		}
		t.Logf("Got flows information [%v]", val)
		if val != nil {
			rowCount++
		}
	}
	return rowCount
}
