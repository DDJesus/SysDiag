//go:build linux
// +build linux

package software

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

func (p *Probe) collect(ctx context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	apps := collectLinuxPackages(ctx)
	runtimes := collectLinuxRuntimes(ctx)
	hotfixes := collectLinuxUpdates(ctx)

	metrics := &models.SoftwareMetrics{
		TotalInstalledApps: len(apps),
		Applications:       apps,
		Runtimes:           runtimes,
		HotFixes:           hotfixes,
	}

	return metrics, collector.StatusSuccess, nil
}

func collectLinuxPackages(ctx context.Context) []models.InstalledApp {
	var apps []models.InstalledApp

	// Try dpkg-query (Ubuntu / Debian)
	if dpkgPath, err := exec.LookPath("dpkg-query"); err == nil {
		cmd := exec.CommandContext(ctx, dpkgPath, "-W", "-f=${Package}\t${Version}\t${Architecture}\t${Maintainer}\n")
		if out, err := cmd.Output(); err == nil {
			scanner := bufio.NewScanner(strings.NewReader(string(out)))
			for scanner.Scan() {
				fields := strings.Split(scanner.Text(), "\t")
				if len(fields) >= 2 {
					name := strings.TrimSpace(fields[0])
					ver := strings.TrimSpace(fields[1])
					pub := ""
					if len(fields) >= 4 {
						pub = strings.TrimSpace(fields[3])
					}
					apps = append(apps, models.InstalledApp{
						Name:      name,
						Version:   ver,
						Publisher: pub,
						Scope:     "System",
					})
				}
			}
			return apps
		}
	}

	// Try rpm (RHEL / CentOS / Fedora)
	if rpmPath, err := exec.LookPath("rpm"); err == nil {
		cmd := exec.CommandContext(ctx, rpmPath, "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{VENDOR}\n")
		if out, err := cmd.Output(); err == nil {
			scanner := bufio.NewScanner(strings.NewReader(string(out)))
			for scanner.Scan() {
				fields := strings.Split(scanner.Text(), "\t")
				if len(fields) >= 2 {
					name := strings.TrimSpace(fields[0])
					ver := strings.TrimSpace(fields[1])
					pub := ""
					if len(fields) >= 4 {
						pub = strings.TrimSpace(fields[3])
					}
					apps = append(apps, models.InstalledApp{
						Name:      name,
						Version:   ver,
						Publisher: pub,
						Scope:     "System",
					})
				}
			}
			return apps
		}
	}

	return apps
}

func collectLinuxRuntimes(ctx context.Context) []models.RuntimeInfo {
	var runtimes []models.RuntimeInfo

	checkList := []struct {
		name string
		bin  string
		args []string
	}{
		{"Go", "go", []string{"version"}},
		{"Python", "python3", []string{"--version"}},
		{"Node.js", "node", []string{"--version"}},
		{"Java", "java", []string{"-version"}},
		{"Rust", "rustc", []string{"--version"}},
		{"Docker", "docker", []string{"--version"}},
		{"GCC", "gcc", []string{"--version"}},
		{".NET", "dotnet", []string{"--version"}},
	}

	for _, item := range checkList {
		binPath, err := exec.LookPath(item.bin)
		if err != nil {
			continue
		}

		cmd := exec.CommandContext(ctx, binPath, item.args...)
		out, err := cmd.CombinedOutput()
		if err != nil && len(out) == 0 {
			continue
		}

		verStr := strings.TrimSpace(strings.Split(string(out), "\n")[0])
		runtimes = append(runtimes, models.RuntimeInfo{
			Name:    item.name,
			Version: verStr,
			Path:    binPath,
		})
	}

	return runtimes
}

func collectLinuxUpdates(ctx context.Context) []models.HotFixInfo {
	var hotfixes []models.HotFixInfo

	// Check Ubuntu update-notifier file
	updateNotifierPath := "/var/lib/update-notifier/updates-available"
	if data, err := os.ReadFile(updateNotifierPath); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.Contains(line, "packages can be updated") || strings.Contains(line, "updates are security updates") {
				hotfixes = append(hotfixes, models.HotFixInfo{
					HotFixID:    "APT-UPDATE-NOTIFIER",
					Description: line,
				})
			}
		}
	}

	return hotfixes
}
