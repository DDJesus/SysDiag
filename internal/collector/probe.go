package collector

import (
	"context"
	"time"
)

// PrivilegeLevel denotes the minimal privilege needed to execute a probe.
type PrivilegeLevel string

const (
	PrivilegeUser  PrivilegeLevel = "User"
	PrivilegeAdmin PrivilegeLevel = "Administrator"
)

// ProbeStatus specifies the execution outcome of an individual probe.
type ProbeStatus string

const (
	StatusSuccess       ProbeStatus = "Success"
	StatusPartial       ProbeStatus = "Partial"
	StatusRequiresAdmin ProbeStatus = "Requires Administrator"
	StatusUnsupported   ProbeStatus = "Unsupported"
	StatusFailed        ProbeStatus = "Failed"
	StatusTimeout       ProbeStatus = "Timeout"
	StatusCanceled      ProbeStatus = "Canceled"
	StatusSkipped       ProbeStatus = "Skipped"
)

// ProbeCategory classifies probes by target subsystem.
type ProbeCategory string

const (
	CategorySystem      ProbeCategory = "system"
	CategoryCPU         ProbeCategory = "cpu"
	CategoryMemory      ProbeCategory = "memory"
	CategoryStorage     ProbeCategory = "storage"
	CategoryNetwork     ProbeCategory = "network"
	CategoryProcesses   ProbeCategory = "processes"
	CategoryServices    ProbeCategory = "services"
	CategoryReliability ProbeCategory = "reliability"
	CategorySoftware    ProbeCategory = "software"
)

// Probe defines the contract for all diagnostic metric collectors.
type Probe interface {
	ID() string
	Name() string
	Category() ProbeCategory
	RequiredPrivilege() PrivilegeLevel
	SupportedProfiles() []string
	Run(ctx context.Context, sampleDuration time.Duration) (interface{}, ProbeStatus, error)
}

// ProbeResult encapsulates probe output and execution metadata.
type ProbeResult struct {
	ProbeID           string
	Name              string
	Category          ProbeCategory
	RequiredPrivilege PrivilegeLevel
	Status            ProbeStatus
	Data              interface{}
	Err               error
	Duration          time.Duration
}
