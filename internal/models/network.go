package models

// NetworkAdapterMetrics captures physical/logical network adapter state and counters.
type NetworkAdapterMetrics struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Description   string   `json:"description,omitempty"`
	MACAddress    string   `json:"mac_address,omitempty"`
	Status        string   `json:"status"` // "Up", "Down", "Testing", "Unknown"
	IfType        string   `json:"if_type,omitempty"`
	SpeedMbps     *uint64  `json:"speed_mbps"`
	IPv4Addresses []string `json:"ipv4_addresses"`
	IPv6Addresses []string `json:"ipv6_addresses,omitempty"`
	Gateways      []string `json:"gateways,omitempty"`
	DNSServers    []string `json:"dns_servers,omitempty"`
	DHCPEnabled   bool     `json:"dhcp_enabled"`
	InOctets      uint64   `json:"in_octets,omitempty"`
	OutOctets     uint64   `json:"out_octets,omitempty"`
	InErrors      uint64   `json:"in_errors"`
	OutErrors     uint64   `json:"out_errors"`
	InDiscards    uint64   `json:"in_discards,omitempty"`
	OutDiscards   uint64   `json:"out_discards,omitempty"`
}

// DNSResolutionTest captures deterministic DNS timing and availability measurement.
type DNSResolutionTest struct {
	QueryTarget string   `json:"query_target"`
	DurationMS  float64  `json:"duration_ms"`
	Success     bool     `json:"success"`
	ResolvedIPs []string `json:"resolved_ips,omitempty"`
	Error       string   `json:"error,omitempty"`
}

// NetworkMetrics encapsulates network subsystem telemetry.
type NetworkMetrics struct {
	Adapters []NetworkAdapterMetrics `json:"adapters"`
	DNSTest  *DNSResolutionTest      `json:"dns_test,omitempty"`
}
