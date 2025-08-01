// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build mage

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"

	"go.uber.org/multierr"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"

	devtools "github.com/elastic/beats/v7/dev-tools/mage"
	"github.com/elastic/beats/v7/dev-tools/mage/target/build"
	metricbeat "github.com/elastic/beats/v7/metricbeat/scripts/mage"

	//mage:import
	"github.com/elastic/beats/v7/dev-tools/mage/target/common"
	//mage:import
	"github.com/elastic/beats/v7/dev-tools/mage/target/test"
	//mage:import
	_ "github.com/elastic/beats/v7/metricbeat/scripts/mage/target/metricset"
	//mage:import
	_ "github.com/elastic/beats/v7/dev-tools/mage/target/integtest/docker"
)

func init() {
	common.RegisterCheckDeps(Update)
	test.RegisterDeps(IntegTest)

	devtools.BeatDescription = "Metricbeat is a lightweight shipper for metrics."
	devtools.BeatLicense = "Elastic License"
}

// Build builds the Beat binary.
func Build() error {
	args := devtools.DefaultBuildArgs()
	// On Windows 7 32-bit we run out of memory if we enable DWARF
	if isWindows32bitRunner() {
		args.LDFlags = append(args.LDFlags, "-w")
	}
	return devtools.Build(args)
}

// BuildOTel builds the Beat binary with OTel sub command
func BuildOTel() error {
	return devtools.BuildOTel()
}

// GolangCrossBuild build the Beat binary inside of the golang-builder.
// Do not use directly, use crossBuild instead.
func GolangCrossBuild() error {
	args := devtools.DefaultGolangCrossBuildArgs()
	// On Windows 7 32-bit we run out of memory if we enable DWARF
	if isWindows32bitRunner() {
		args.LDFlags = append(args.LDFlags, "-w")
	}
	return multierr.Combine(
		devtools.GolangCrossBuild(args),
		devtools.TestLinuxForCentosGLIBC(),
	)
}

// CrossBuild cross-builds the beat for all target platforms.
func CrossBuild() error {
	return devtools.CrossBuild()
}

// UnitTest executes the unit tests (Go and Python).
func UnitTest() {
	mg.SerialDeps(GoUnitTest, PythonUnitTest)
}

// GoUnitTest executes the Go unit tests.
// Use TEST_COVERAGE=true to enable code coverage profiling.
// Use RACE_DETECTOR=true to enable the race detector.
func GoUnitTest(ctx context.Context) error {
	args := devtools.DefaultGoTestUnitArgs()
	// On Windows 7 32-bit we run out of memory if we enable DWARF
	if isWindows32bitRunner() {
		args.ExtraFlags = append(args.ExtraFlags, "-ldflags=-w")
	}
	return devtools.GoTest(ctx, args)
}

// GoFIPSOnlyUnitTest sets GODEBUG=fips140=only when running unit tests
func GoFIPSOnlyUnitTest() error {
	ctx := context.Background()

	fipsArgs := devtools.DefaultGoFIPSOnlyTestArgs()
	if isWindows32bitRunner() {
		fipsArgs.ExtraFlags = append(fipsArgs.ExtraFlags, "-ldflags=-w")
	}
	return devtools.GoTest(ctx, fipsArgs)
}

// PythonUnitTest executes the python system tests.
func PythonUnitTest() error {
	mg.SerialDeps(Fields)
	mg.Deps(BuildSystemTestBinary)

	args := devtools.DefaultPythonTestUnitArgs()
	// On Windows 32-bit converage is not enabled.
	if isWindows32bitRunner() {
		args.Env["TEST_COVERAGE"] = "false"
	}
	return devtools.PythonTest(args)
}

// BuildSystemTestBinary build a system test binary depending on the runner.
func BuildSystemTestBinary() error {
	binArgs := devtools.DefaultTestBinaryArgs()
	args := []string{
		"test", "-c",
		"-o", binArgs.Name + ".test",
	}

	// On Windows 7 32-bit we run out of memory if we enable coverage and DWARF
	isWin32Runner := isWindows32bitRunner()
	if isWin32Runner {
		args = append(args, "-ldflags=-w")
	}
	if devtools.TestCoverage && !isWin32Runner {
		args = append(args, "-coverpkg", "./...")
	}

	if len(binArgs.InputFiles) > 0 {
		args = append(args, binArgs.InputFiles...)
	}

	start := time.Now()
	defer func() {
		log.Printf("BuildSystemTestGoBinary (go %v) took %v.", strings.Join(args, " "), time.Since(start))
	}()
	return sh.RunV("go", args...)
}

// AssembleDarwinUniversal merges the darwin/amd64 and darwin/arm64 into a single
// universal binary using `lipo`. It assumes the darwin/amd64 and darwin/arm64
// were built and only performs the merge.
func AssembleDarwinUniversal() error {
	return build.AssembleDarwinUniversal()
}

// Package packages the Beat for distribution.
// Use SNAPSHOT=true to build snapshots.
// Use PLATFORMS to control the target platforms.
// Use BEAT_VERSION_QUALIFIER to control the version qualifier.
func Package() {
	start := time.Now()
	defer func() { fmt.Println("package ran for", time.Since(start)) }()

	if v, found := os.LookupEnv("AGENT_PACKAGING"); found && v != "" {
		devtools.UseElasticBeatXPackReducedPackaging()
	} else {
		devtools.UseElasticBeatXPackPackaging()
	}

	metricbeat.CustomizePackaging()
	devtools.PackageKibanaDashboardsFromBuildDir()

	mg.Deps(Update, metricbeat.PrepareModulePackagingXPack)
	mg.Deps(CrossBuild)
	mg.SerialDeps(devtools.Package, TestPackages)
}

// Package packages the Beat for IronBank distribution.
//
// Use SNAPSHOT=true to build snapshots.
func Ironbank() error {
	start := time.Now()
	defer func() { fmt.Println("ironbank ran for", time.Since(start)) }()
	return devtools.Ironbank()
}

// TestPackages tests the generated packages (i.e. file modes, owners, groups).
func TestPackages() error {
	return devtools.TestPackages(
		devtools.WithModulesD(),
		devtools.WithModules(),

		// To be increased or removed when more light modules are added
		devtools.MinModules(5),
	)
}

// Fields generates a fields.yml and fields.go for each module.
func Fields() {
	mg.Deps(fieldsYML, moduleFieldsGo)
}

func moduleFieldsGo() error {
	return devtools.GenerateModuleFieldsGo("module")
}

// fieldsYML generates a fields.yml based on metricbeat + x-pack/metricbeat/modules.
func fieldsYML() error {
	return devtools.GenerateFieldsYAML(devtools.OSSBeatDir("module"), "module")
}

// Dashboards collects all the dashboards and generates index patterns.
func Dashboards() error {
	return devtools.KibanaDashboards(devtools.OSSBeatDir("module"), "module")
}

// Config generates both the short and reference configs.
func Config() {
	mg.Deps(configYML, devtools.GenerateDirModulesD)
}

func configYML() error {
	return devtools.Config(devtools.AllConfigTypes, metricbeat.XPackConfigFileParams(), ".")
}

// Update is an alias for running fields, dashboards, config.
func Update() {
	mg.SerialDeps(Fields, Dashboards, Config,
		metricbeat.PrepareModulePackagingXPack,
		devtools.GenerateModuleIncludeListGo)
}

// IntegTest executes integration tests (it uses Docker to run the tests).
func IntegTest() {
	mg.SerialDeps(GoIntegTest, PythonIntegTest)
}

// GoIntegTest executes the Go integration tests.
// Use TEST_COVERAGE=true to enable code coverage profiling if not running on Windows 7 32bit.
// Use RACE_DETECTOR=true to enable the race detector.
// Use TEST_TAGS=tag1,tag2 to add additional build tags.
// Use MODULE=module to run only tests for `module`.
func GoIntegTest(ctx context.Context) error {

	// define modules
	if os.Getenv("CI") == "true" {
		mg.Deps(devtools.DefineModules)
	}

	if !devtools.IsInIntegTestEnv() {
		// build integration test binary with otel sub command
		devtools.BuildSystemTestOTelBinary()
		args := devtools.DefaultGoTestIntegrationFromHostArgs()
		// ES_USER must be admin in order for the Go Integration tests to function because they require
		// indices:data/read/search
		args.Env["ES_USER"] = args.Env["ES_SUPERUSER_USER"]
		args.Env["ES_PASS"] = args.Env["ES_SUPERUSER_PASS"]
		// run integration test from home directory
		args.Packages = []string{"./tests/integration/"}
		err := devtools.GoIntegTestFromHost(ctx, args)
		if err != nil {
			return err
		}

		mg.SerialDeps(Fields, Dashboards)
	}

	return devtools.GoTestIntegrationForModule(ctx)
}

// GoFIPSOnlyIntegTest executes the Go integration tests.
// Sets GODEBUG=fips140=only.
// Use TEST_COVERAGE=true to enable code coverage profiling if not running on Windows 7 32bit.
// Use RACE_DETECTOR=true to enable the race detector.
// Use TEST_TAGS=tag1,tag2 to add additional build tags.
// Use MODULE=module to run only tests for `module`.
func GoFIPSOnlyIntegTest(ctx context.Context) error {
	os.Setenv("GODEBUG", "fips140=only")
	return GoIntegTest(ctx)
}

// PythonIntegTest executes the python system tests in the integration
// environment (Docker).
// Use MODULE=module to run only tests for `module`.
// Use PYTEST_ADDOPTS="-k pattern" to only run tests matching the specified pattern.
// Use any other PYTEST_* environment variable to influence the behavior of pytest.
func PythonIntegTest(ctx context.Context) error {
	if os.Getenv("CI") == "true" {
		mg.Deps(devtools.DefineModules)
	}

	if !devtools.IsInIntegTestEnv() {
		mg.SerialDeps(Fields, Dashboards)
	}
	runner, err := devtools.NewDockerIntegrationRunner(devtools.ListMatchingEnvVars("PYTEST_")...)
	if err != nil {
		return err
	}
	return runner.Test("pythonIntegTest", func() error {
		mg.Deps(BuildSystemTestBinary)
		args := devtools.DefaultPythonTestIntegrationArgs()
		// Always create a fresh virtual environment when running tests in a container, until we get
		// get the requirements installed as part of the container build.
		args.ForceCreateVenv = true
		// On Windows 32-bit converage is not enabled.
		if isWindows32bitRunner() {
			args.Env["TEST_COVERAGE"] = "false"
		}
		return devtools.PythonTestForModule(args)
	})
}

func isWindows32bitRunner() bool {
	return runtime.GOOS == "windows" && runtime.GOARCH == "386"
}

// FipsECHTest runs a smoke test using a FIPS enabled binary targetting an ECH deployment.
func FipsECHTest(ctx context.Context) error {
	return devtools.GoTest(ctx, devtools.DefaultECHTestArgs())
}
