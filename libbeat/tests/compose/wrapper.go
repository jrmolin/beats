// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//go:build linux || darwin || windows

package compose

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"

	"github.com/elastic/elastic-agent-autodiscover/docker"
	"github.com/elastic/elastic-agent-libs/logp"
)

const (
	labelComposeService = "com.docker.compose.service"
	labelComposeProject = "com.docker.compose.project"
)

type wrapperDriver struct {
	Name  string
	Files []string

	Environment []string

	client *client.Client
	logger *logp.Logger
}

func newWrapperDriver(logger *logp.Logger) (*wrapperDriver, error) {
	c, err := docker.NewClient(client.DefaultDockerHost, nil, nil, logger)
	if err != nil {
		return nil, err
	}
	return &wrapperDriver{client: c, logger: logger}, nil
}

type wrapperContainer struct {
	info container.Summary
}

func (c *wrapperContainer) ServiceName() string {
	return c.info.Labels[labelComposeService]
}

func (c *wrapperContainer) Healthy() bool {
	return strings.Contains(c.info.Status, "(healthy)")
}

func (c *wrapperContainer) Running() bool {
	return c.info.State == "running"
}

var statusOldRe = regexp.MustCompile(`(\d+) (minute|hour)s?`)

// Old returns true when info.Status indicates that container is more than
// 3 minutes old.
// Else, it returns false even when status is not in the expected format.
func (c *wrapperContainer) Old() bool {
	match := statusOldRe.FindStringSubmatch(c.info.Status)
	if len(match) < 3 {
		return false
	}
	n, _ := strconv.Atoi(match[1])
	unit := match[2]
	switch unit {
	case "minute":
		return n > 3
	default:
		return true
	}
}

// privateHost returns the address of the container, it should be reachable
// from the host if docker is being run natively. To be used when the tests
// are run from another container in the same network. It also works when
// running from the hoist network if the docker daemon runs natively.
func (c *wrapperContainer) privateHost(port int) string {
	var ip string
	var shortPort uint16
	for _, net := range c.info.NetworkSettings.Networks {
		if len(net.IPAddress) > 0 {
			ip = net.IPAddress
			break
		}
	}
	if len(ip) == 0 {
		return ""
	}

	if port >= 0 && port <= math.MaxUint16 {
		shortPort = uint16(port)
	} else {
		return ""
	}
	for _, info := range c.info.Ports {
		if info.PublicPort != uint16(0) && (port == 0 || info.PrivatePort == shortPort) {
			return net.JoinHostPort(ip, strconv.Itoa(int(info.PrivatePort)))
		}
	}
	return ""
}

// exposedHost returns the exposed address in the host, can be used when the
// test is run from the host network. Recommended when using docker machines.
func (c *wrapperContainer) exposedHost(port int) string {
	var shortPort uint16

	if port >= 0 && port <= math.MaxUint16 {
		shortPort = uint16(port)
	} else {
		return ""
	}
	for _, info := range c.info.Ports {
		if info.PublicPort != uint16(0) && (port == 0 || info.PrivatePort == shortPort) {
			return net.JoinHostPort("localhost", strconv.Itoa(int(info.PublicPort)))
		}
	}
	return ""
}

func (c *wrapperContainer) Host() string {
	return c.HostForPort(0)
}

func (c *wrapperContainer) HostForPort(port int) string {
	if runtime.GOOS == "linux" {
		return c.privateHost(port)
	}
	// We can use `exposedHost()` in all platforms when we can use host
	// network in the metricbeat container
	return c.exposedHost(port)
}

func (d *wrapperDriver) LockFile() string {
	return d.Files[0] + ".lock"
}

func (d *wrapperDriver) Close() error {
	err := d.client.Close()
	if err != nil {
		return fmt.Errorf("failed to close wrapper driver: %w", err)
	}
	return nil
}

func (d *wrapperDriver) cmd(ctx context.Context, command string, arg ...string) *exec.Cmd {
	args := make([]string, 0, 4+len(d.Files)+len(arg)) // preallocate as much as possible
	args = append(args, "--ansi", "never", "--project-name", d.Name)
	for _, f := range d.Files {
		args = append(args, "--file", f)
	}
	args = append(args, command)
	args = append(args, arg...)
	cmd := exec.CommandContext(ctx, "docker-compose", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if len(d.Environment) > 0 {
		cmd.Env = append(os.Environ(), d.Environment...)
	}
	return cmd
}

func (d *wrapperDriver) Up(ctx context.Context, opts UpOptions, service string) error {
	var args []string

	args = append(args, "-d")

	if opts.Create.Build {
		args = append(args, "--build")
	}

	if opts.Create.ForceRecreate {
		args = append(args, "--force-recreate")
	}

	if service != "" {
		args = append(args, service)
	}

	// Try to pull the image before building it
	var stderr bytes.Buffer
	pull := d.cmd(ctx, "pull", "--ignore-pull-failures", service)
	pull.Stdout = nil
	pull.Stderr = &stderr
	if err := pull.Run(); err != nil {
		return fmt.Errorf("failed to pull images using docker-compose: %s: %w", stderr.String(), err)
	}

	err := d.cmd(ctx, "up", args...).Run()
	if err != nil {
		return err
	}
	if opts.SetupAdvertisedHostEnvFile {
		return d.setupAdvertisedHost(ctx, service, opts.SetupAdvertisedHostEnvFilePort)
	}
	return nil
}

func writeToContainer(ctx context.Context, cli *client.Client, id, filename, content string) error {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	now := time.Now()
	err := tw.WriteHeader(&tar.Header{
		Typeflag:   tar.TypeReg,
		Name:       filepath.Base(filename),
		Mode:       0100644,
		Size:       int64(len(content)),
		ModTime:    now,
		AccessTime: now,
		ChangeTime: now,
	})
	if err != nil {
		return fmt.Errorf("failed to write tar header: %w", err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		return fmt.Errorf("failed to write tar file: %w", err)
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("failed to close tar: %w", err)
	}

	opts := container.CopyToContainerOptions{}
	err = cli.CopyToContainer(ctx, id, filepath.Dir(filename), bytes.NewReader(buf.Bytes()), opts)
	if err != nil {
		return fmt.Errorf("failed to copy environment to container %s: %w", id, err)
	}
	return nil
}

// setupAdvertisedHost adds a file to a container with its address, this can
// be used in services that need to configure an address to be advertised to
// clients.
func (d *wrapperDriver) setupAdvertisedHost(ctx context.Context, service string, port int) error {
	containers, err := d.containers(ctx, Filter{State: AnyState}, service)
	if err != nil {
		return fmt.Errorf("setupAdvertisedHost: %w", err)
	}
	if len(containers) == 0 {
		return fmt.Errorf("no containers for service %s", service)
	}

	for _, c := range containers {
		w := &wrapperContainer{info: c}
		content := fmt.Sprintf("SERVICE_HOST=%s", w.HostForPort(port))

		err := writeToContainer(ctx, d.client, c.ID, "/run/compose_env", content)
		if err != nil {
			return err
		}
	}
	return nil
}

// Kill force stops the service containers based on the SIGNAL provided.
// If SIGKILL is used, then termination happens immediately whereas SIGTERM
// is used for graceful termination.
// See: https://docs.docker.com/engine/reference/commandline/compose_kill/
func (d *wrapperDriver) Kill(ctx context.Context, signal string, service string) error {
	var args []string

	if signal != "" {
		args = append(args, "-s", signal)
	}

	if service != "" {
		args = append(args, service)
	}

	return d.cmd(ctx, "kill", args...).Run()
}

// Remove removes the stopped service containers. Removal of the containers can be forced as
// well where no confirmation of removal is required.
// See: https://docs.docker.com/engine/reference/commandline/compose_rm/
func (d *wrapperDriver) Remove(ctx context.Context, service string, force bool) error {
	var args []string

	if force {
		args = append(args, "-f")
	}

	if service != "" {
		args = append(args, service)
	}

	return d.cmd(ctx, "rm", args...).Run()
}

func (d *wrapperDriver) Ps(ctx context.Context, filter ...string) ([]ContainerStatus, error) {
	containers, err := d.containers(ctx, Filter{State: AnyState}, filter...)
	if err != nil {
		return nil, fmt.Errorf("ps: %w", err)
	}

	ps := make([]ContainerStatus, len(containers))
	for i, c := range containers {
		ps[i] = &wrapperContainer{info: c}
	}
	return ps, nil
}

func (d *wrapperDriver) Containers(ctx context.Context, projectFilter Filter, filter ...string) ([]string, error) {
	containers, err := d.containers(ctx, projectFilter, filter...)
	if err != nil {
		return nil, fmt.Errorf("containers: %w", err)
	}

	ids := make([]string, len(containers))
	for i := range containers {
		ids[i] = containers[i].ID
	}
	return ids, nil
}

func (d *wrapperDriver) containers(ctx context.Context, projectFilter Filter, filter ...string) ([]container.Summary, error) {
	var serviceFilters []filters.Args
	if len(filter) == 0 {
		f := makeFilter(d.Name, "", projectFilter)
		serviceFilters = append(serviceFilters, f)
	} else {
		for _, service := range filter {
			f := makeFilter(d.Name, service, projectFilter)
			serviceFilters = append(serviceFilters, f)
		}
	}

	serviceNames, err := d.serviceNames(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get container list: %w", err)
	}

	var containers []container.Summary
	for _, f := range serviceFilters {
		list, err := d.client.ContainerList(ctx, container.ListOptions{
			All:     true,
			Filters: f,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to get container list: %w", err)
		}
		for _, container := range list {
			serviceName, ok := container.Labels[labelComposeService]
			if !ok || !contains(serviceNames, serviceName) {
				// Service is not defined in current docker compose file, ignore it
				continue
			}
			containers = append(containers, container)
		}
	}

	return containers, nil
}

// KillOld is a workaround for issues in CI with heavy load caused by having too many
// running containers.
// It kills and removes all containers except the excluded services in 'except'.
func (d *wrapperDriver) KillOld(ctx context.Context, except []string) error {
	list, err := d.client.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return fmt.Errorf("listing containers to be killed: %w", err)
	}

	rmOpts := container.RemoveOptions{
		RemoveVolumes: true,
		Force:         true,
		RemoveLinks:   true,
	}

	for _, container := range list {
		container := wrapperContainer{info: container}
		serviceName, ok := container.info.Labels[labelComposeService]
		if !ok || contains(except, serviceName) {
			continue
		}

		if container.Running() && container.Old() {
			err = d.client.ContainerRemove(ctx, container.info.ID, rmOpts)
			if err != nil {
				d.logger.Errorf("container remove: %v", err)
			}
		}
	}

	return nil
}

func (d *wrapperDriver) serviceNames(ctx context.Context) ([]string, error) {
	var stdout bytes.Buffer
	cmd := d.cmd(ctx, "config", "--services")
	cmd.Stdout = &stdout
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to get list of service names: %w", err)
	}
	return strings.Fields(stdout.String()), nil
}

// Inspect a container.
func (d *wrapperDriver) Inspect(ctx context.Context, serviceName string) (string, error) {
	list, err := d.client.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return "", fmt.Errorf("listing containers to be inspected: %w", err)
	}

	var found bool
	var c container.Summary
	for _, container := range list {
		aServiceName, ok := container.Labels[labelComposeService]
		if ok && serviceName == aServiceName {
			c = container
			found = true
			break
		}
	}

	if !found {
		return "", fmt.Errorf("container not found for service '%s'", serviceName)
	}

	inspect, err := d.client.ContainerInspect(ctx, c.ID)
	if err != nil {
		return "", fmt.Errorf("container failed inspection: %w", err)
	} else if inspect.State == nil {
		return "empty container state", nil
	}

	state, err := json.Marshal(inspect.State)
	if err != nil {
		return "", fmt.Errorf("container inspection failed: %w", err)
	}

	return string(state), nil
}

func makeFilter(project, service string, projectFilter Filter) filters.Args {
	f := filters.NewArgs()
	f.Add("label", fmt.Sprintf("%s=%s", labelComposeProject, project))

	if service != "" {
		f.Add("label", fmt.Sprintf("%s=%s", labelComposeService, service))
	}

	switch projectFilter.State {
	case AnyState:
		// No filter
	case RunningState:
		f.Add("status", "running")
	case StoppedState:
		f.Add("status", "exited")
	}

	return f
}
