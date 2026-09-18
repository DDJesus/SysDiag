package models

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityWarning  Severity = "WARNING"
	SeverityInfo     Severity = "INFO"
)

type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

// Finding captures an evidence-based diagnostic conclusion.
type Finding struct {
	ID              string                 `json:"id"`
	Category        string                 `json:"category"`
	Severity        Severity               `json:"severity"`
	Title           string                 `json:"title"`
	Observation     string                 `json:"observation"`      // Direct metric observation
	Evidence        map[string]interface{} `json:"evidence"`         // Concrete key-value measurements
	Interpretation  string                 `json:"interpretation"`   // Diagnostic interpretation
	PotentialImpact string                 `json:"potential_impact"` // System impact description
	Recommendation  string                 `json:"recommendation"`   // Concrete remedy
	Confidence      Confidence             `json:"confidence"`       // HIGH, MEDIUM, LOW
}

// CollectionLimitation records probe execution degradation or permission gates.
type CollectionLimitation struct {
	ProbeID           string `json:"probe_id"`
	Category          string `json:"category"`
	Reason            string `json:"reason"`
	PrivilegeRequired string `json:"privilege_required,omitempty"`
}
