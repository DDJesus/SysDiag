package models

// InstalledApp represents an application discovered in the registry or package database.
type InstalledApp struct {
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Publisher   string `json:"publisher,omitempty"`
	InstallDate string `json:"install_date,omitempty"`
	Scope       string `json:"scope"` // "System" (64-bit/32-bit HKLM) or "User" (HKCU)
}

// HotFixInfo represents an installed OS update, patch, or knowledge base update.
type HotFixInfo struct {
	HotFixID    string `json:"hotfix_id"`
	Description string `json:"description,omitempty"`
	InstalledOn string `json:"installed_on,omitempty"`
}

// RuntimeInfo describes a developer or system runtime environment.
type RuntimeInfo struct {
	Name    string `json:"name"` // e.g. ".NET Framework", ".NET Core / .NET Runtime", "Go", "Python", "Java"
	Version string `json:"version"`
	Path    string `json:"path,omitempty"`
}

// SoftwareMetrics aggregates installed software, updates, and major runtimes.
type SoftwareMetrics struct {
	TotalInstalledApps int            `json:"total_installed_apps"`
	Applications       []InstalledApp `json:"applications,omitempty"` // Listed in deep profile or inventory filter
	HotFixes           []HotFixInfo   `json:"hotfixes,omitempty"`
	Runtimes           []RuntimeInfo  `json:"runtimes,omitempty"`
}
