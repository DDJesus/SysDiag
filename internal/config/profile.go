package config

import "time"

const (
	ProfileQuick = "quick"
	ProfileDeep  = "deep"
)

// ProfileConfig holds execution parameters specific to a profile.
type ProfileConfig struct {
	Name           string
	SampleDuration time.Duration
	ProbeTimeout   time.Duration
}

// GetProfileConfig returns configuration tuned for the chosen profile.
func GetProfileConfig(profile string) ProfileConfig {
	switch profile {
	case ProfileDeep:
		return ProfileConfig{
			Name:           ProfileDeep,
			SampleDuration: 2 * time.Second,
			ProbeTimeout:   15 * time.Second,
		}
	case ProfileQuick:
		fallthrough
	default:
		return ProfileConfig{
			Name:           ProfileQuick,
			SampleDuration: 300 * time.Millisecond,
			ProbeTimeout:   5 * time.Second,
		}
	}
}
