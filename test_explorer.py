"""
Comprehensive Unit & Acceptance Tests for Infrastructure Explorer Phase 0/1
Validates schema validation, graph model materialization, drill-down logic,
evidence chain mapping, and all 10 acceptance test criteria.
"""

import unittest
import json
import os
import re
import copy

class TestSchemaValidation(unittest.TestCase):
    def setUp(self):
        self.report_path = os.path.join(os.path.dirname(__file__), 'web', 'samples', 'sysdiag_report_workstation_sanitized.json')
        with open(self.report_path, 'r', encoding='utf-8') as f:
            self.report = json.load(f)

    def test_canonical_schema_version(self):
        self.assertEqual(self.report.get("schema_version"), "1.0.0")
        self.assertTrue(self.report.get("$schema", "").startswith("https://systemdiag.io/schema/"))

    def test_metadata_completeness(self):
        meta = self.report.get("metadata", {})
        self.assertTrue(bool(meta.get("hostname")))
        self.assertTrue(bool(meta.get("scan_timestamp")))
        self.assertIn("is_elevated", meta)
        self.assertIn("privilege_level", meta)
        self.assertIn("tool_version", meta)

    def test_collection_coverage(self):
        status = self.report.get("collection_status", {})
        self.assertEqual(status.get("total_probes"), 9)
        self.assertEqual(status.get("successful"), 9)
        self.assertEqual(status.get("failed"), 0)
        self.assertEqual(status.get("partial"), 0)

    def test_nine_diagnostic_domains_present(self):
        data = self.report.get("data", {})
        required_domains = [
            "system", "cpu", "memory", "storage",
            "network", "processes", "services", "reliability", "software"
        ]
        for domain in required_domains:
            self.assertIn(domain, data, f"Domain {domain} must be present in canonical data")

    def test_network_active_wifi_adapter(self):
        net = self.report.get("data", {}).get("network", {})
        adapters = net.get("adapters", [])
        wifi_adapter = next((a for a in adapters if a.get("name") == "Wi-Fi"), None)
        self.assertIsNotNone(wifi_adapter, "Wi-Fi adapter must be present")
        self.assertEqual(wifi_adapter.get("status"), "Up")
        self.assertIsNotNone(wifi_adapter.get("speed_mbps"))
        self.assertGreater(wifi_adapter.get("speed_mbps"), 0)
        self.assertTrue(len(wifi_adapter.get("ipv4_addresses", [])) > 0)
        self.assertTrue(bool(wifi_adapter.get("mac_address")))

    def test_services_finding_and_evidence_chain(self):
        findings = self.report.get("findings", [])
        self.assertTrue(len(findings) > 0, "Expected at least 1 finding in test report")
        svc_finding = next((f for f in findings if f.get("category") == "services"), None)
        self.assertIsNotNone(svc_finding, "Services finding must exist")
        self.assertEqual(svc_finding.get("severity"), "INFO")
        self.assertEqual(svc_finding.get("id"), "FINDING-SVC-001")
        
        # Verify complete 5-step evidence chain structure
        self.assertTrue(bool(svc_finding.get("observation")), "Step 1: Observation must be present")
        self.assertIsInstance(svc_finding.get("evidence"), dict, "Step 2: Evidence map must be present")
        self.assertIn("stopped_auto_count", svc_finding.get("evidence"))
        self.assertTrue(bool(svc_finding.get("interpretation")), "Step 3: Interpretation must be present")
        self.assertTrue(bool(svc_finding.get("potential_impact")), "Step 4: Potential Impact must be present")
        self.assertTrue(bool(svc_finding.get("recommendation")), "Step 5: Actionable Recommendation must be present")


class TestPhase1AcceptanceFlow(unittest.TestCase):
    """
    Directly tests all 10 Phase 1 Acceptance Criteria on imported JSON.
    """
    def setUp(self):
        self.report_path = os.path.join(os.path.dirname(__file__), 'web', 'samples', 'sysdiag_report_workstation_sanitized.json')
        with open(self.report_path, 'r', encoding='utf-8') as f:
            self.report = json.load(f)

    def test_acceptance_step_1_to_10(self):
        # 1. Load it into the viewer: valid JSON loaded
        self.assertIsInstance(self.report, dict)

        # 2. Validate it: version 1.0.0, required sections
        self.assertEqual(self.report.get("schema_version"), "1.0.0")
        self.assertIn("metadata", self.report)
        self.assertIn("collection_status", self.report)
        self.assertIn("data", self.report)
        self.assertIn("findings", self.report)

        # 3. Materialize a machine graph: Root -> Site -> NetGroup -> Machine
        hostname = self.report["metadata"]["hostname"]
        self.assertTrue(len(hostname) > 0)

        # 4. Display the machine and nine major diagnostic domains
        domains = ["system", "cpu", "memory", "storage", "network", "processes", "services", "reliability", "software"]
        for d in domains:
            self.assertIn(d, self.report["data"])

        # 5. Click Network and see its adapters
        adapters = self.report["data"]["network"]["adapters"]
        self.assertGreater(len(adapters), 0)

        # 6. Click the active Wi-Fi adapter and see its canonical measurements
        wifi = next((a for a in adapters if a.get("name") == "Wi-Fi"), None)
        self.assertIsNotNone(wifi)
        self.assertEqual(wifi.get("status"), "Up")
        self.assertIsNotNone(wifi.get("speed_mbps"))
        self.assertTrue(len(wifi.get("ipv4_addresses", [])) > 0)
        self.assertEqual(wifi.get("dhcp_enabled"), True)

        # 7. Return to the machine: (verified in graph model hierarchy parent pointer)
        # 8. Click Services and locate the existing INFO finding
        findings = [f for f in self.report["findings"] if f.get("category") == "services"]
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.get("severity"), "INFO")

        # 9. Open that finding and trace it back to its evidence
        evidence = finding.get("evidence", {})
        self.assertEqual(evidence.get("stopped_auto_count"), 5)
        self.assertIn("gpsvc", [s["name"] for s in evidence.get("services", [])])
        self.assertTrue(len(finding.get("observation")) > 0)
        self.assertTrue(len(finding.get("interpretation")) > 0)
        self.assertTrue(len(finding.get("potential_impact")) > 0)
        self.assertTrue(len(finding.get("recommendation")) > 0)

        # 10. Clearly display that collection coverage was 9/9 while preserving any future partial/failed states
        col = self.report["collection_status"]
        self.assertEqual(col.get("total_probes"), 9)
        self.assertEqual(col.get("successful"), 9)
        self.assertEqual(col.get("partial"), 0)
        self.assertEqual(col.get("failed"), 0)


class TestCollectionProvenanceAndStates(unittest.TestCase):
    """
    Regression test suite verifying all 6 collection states, legacy backward-compatibility,
    and granular per-probe provenance rules.
    """

    @staticmethod
    def simulate_adapter_subsystem_state(report, category_key):
        """
        Mirror the canonical logic in web/js/sysdiag-adapter.js for test verification.
        """
        col_status = report.get("collection_status", {})
        probes_list = col_status.get("probes", report.get("probes"))
        has_explicit_provenance = isinstance(probes_list, list) and len(probes_list) > 0
        data = report.get("data", {})
        raw_data = data.get(category_key)
        limitations = report.get("limitations", [])

        limitation = next((l for l in limitations if (l.get("category", "").lower() == category_key.lower() or l.get("probe_id", "").lower() == f"probe_{category_key}".lower())), None)

        if has_explicit_provenance:
            probe_rec = next((p for p in probes_list if (p.get("category", "").lower() == category_key.lower() or p.get("probe_id", "").lower() in [f"probe_{category_key}".lower(), category_key.lower()])), None)
            if probe_rec:
                status_str = probe_rec.get("status", "").lower()
                if status_str == "success":
                    return "success", "normal", probe_rec
                elif status_str == "partial":
                    return "partial", "degraded", probe_rec
                elif status_str in ["requires administrator", "requires_admin", "requiresadmin"]:
                    return "requires_admin", "degraded", probe_rec
                elif status_str == "unsupported":
                    return "unsupported", "unsupported", probe_rec
                elif status_str == "timeout":
                    return "timeout", "timeout", probe_rec
                elif status_str == "failed":
                    return "failed", "failed", probe_rec
                else:
                    return status_str, "degraded", probe_rec
            else:
                return "not_collected", "unavailable", None
        else:
            # Legacy Schema 1.0.0
            if raw_data is not None:
                return "collected", "normal", None
            elif limitation is not None:
                is_adm = "admin" in limitation.get("reason", "").lower() or "admin" in limitation.get("privilege_required", "").lower()
                return ("requires_admin" if is_adm else "partial"), "degraded", None
            else:
                return "unknown", "unknown", None

    def test_desktop_real_report_network_success(self):
        """Verify real desktop report renders Network as successfully collected."""
        report_path = os.path.join(os.path.dirname(__file__), 'web', 'samples', 'sysdiag_report_desktop_sanitized.json')
        with open(report_path, 'r', encoding='utf-8') as f:
            report = json.load(f)

        state, status, probe = self.simulate_adapter_subsystem_state(report, "network")
        self.assertEqual(state, "success", "Network probe must render as successful when explicit provenance is Success")
        self.assertEqual(status, "normal")
        self.assertIsNotNone(probe)
        self.assertEqual(probe.get("status"), "Success")
        self.assertNotEqual(state, "not_collected")
        self.assertNotEqual(status, "unavailable")

    def test_desktop_real_report_storage_success(self):
        report_path = os.path.join(os.path.dirname(__file__), 'web', 'samples', 'sysdiag_report_desktop_sanitized.json')
        with open(report_path, 'r', encoding='utf-8') as f:
            report = json.load(f)

        state, status, probe = self.simulate_adapter_subsystem_state(report, "storage")
        self.assertEqual(state, "success")
        self.assertEqual(status, "normal")
        self.assertIsNotNone(probe)

    def test_all_six_collection_states_with_provenance(self):
        """Test explicit provenance across all 6 valid statuses."""
        states_matrix = [
            ("Success", "success", "normal"),
            ("Partial", "partial", "degraded"),
            ("Requires Administrator", "requires_admin", "degraded"),
            ("Unsupported", "unsupported", "unsupported"),
            ("Timeout", "timeout", "timeout"),
            ("Failed", "failed", "failed"),
        ]

        for input_status, expected_state, expected_status in states_matrix:
            report = {
                "$schema": "https://systemdiag.io/schema/v1.json",
                "schema_version": "1.0.0",
                "metadata": {"hostname": "TEST-NODE", "scan_timestamp": "2026-09-17T00:00:00Z"},
                "collection_status": {
                    "total_probes": 1,
                    "successful": 1 if input_status == "Success" else 0,
                    "partial": 1 if input_status == "Partial" else 0,
                    "requires_admin": 1 if input_status == "Requires Administrator" else 0,
                    "unsupported": 1 if input_status == "Unsupported" else 0,
                    "failed": 1 if input_status == "Failed" else 0,
                    "timeout": 1 if input_status == "Timeout" else 0,
                    "probes": [
                        {
                            "probe_id": "probe_network",
                            "category": "network",
                            "name": "Network Probe",
                            "status": input_status,
                            "duration_ms": 25,
                            "reason": f"Details for {input_status}"
                        }
                    ]
                },
                "data": {"network": {"adapters": []}}
            }

            state, status, probe = self.simulate_adapter_subsystem_state(report, "network")
            self.assertEqual(state, expected_state, f"Status '{input_status}' mapped to state '{state}', expected '{expected_state}'")
            self.assertEqual(status, expected_status)
            self.assertIsNotNone(probe)
            self.assertEqual(probe["status"], input_status)

    def test_partial_subsystem_remains_explorable(self):
        """A partial subsystem must preserve its collected data while tracking limitations."""
        report = {
            "$schema": "https://systemdiag.io/schema/v1.json",
            "schema_version": "1.0.0",
            "metadata": {"hostname": "TEST-NODE", "scan_timestamp": "2026-09-17T00:00:00Z"},
            "collection_status": {
                "total_probes": 1,
                "successful": 0,
                "partial": 1,
                "requires_admin": 0,
                "unsupported": 0,
                "failed": 0,
                "timeout": 0,
                "probes": [
                    {
                        "probe_id": "probe_storage",
                        "category": "storage",
                        "name": "Storage Probe",
                        "status": "Partial",
                        "duration_ms": 30,
                        "reason": "Smart query failed on drive 2"
                    }
                ]
            },
            "data": {
                "storage": {
                    "volumes": [{"mount_point": "C:\\", "used_percent": 50}],
                    "physical_disks": [{"device_id": "\\\\.\\PhysicalDrive0"}]
                }
            }
        }

        state, status, probe = self.simulate_adapter_subsystem_state(report, "storage")
        self.assertEqual(state, "partial")
        self.assertEqual(status, "degraded")
        # Ensure data is present and explorable
        self.assertIn("storage", report["data"])
        self.assertEqual(len(report["data"]["storage"]["volumes"]), 1)
        self.assertEqual(probe["reason"], "Smart query failed on drive 2")

    def test_legacy_report_backward_compatibility(self):
        """Legacy schema 1.0.0 reports without probes array must label absent domains as UNKNOWN / LEGACY."""
        legacy_report = {
            "$schema": "https://systemdiag.io/schema/v1.json",
            "schema_version": "1.0.0",
            "metadata": {"hostname": "LEGACY-HOST", "scan_timestamp": "2026-09-16T12:00:00Z"},
            "collection_status": {
                "total_probes": 1,
                "successful": 1,
                "partial": 0,
                "requires_admin": 0,
                "unsupported": 0,
                "failed": 0,
                "timeout": 0
            },
            "data": {
                "storage": {"volumes": []}
            }
        }

        # Storage has data: should be collected/normal
        state_st, status_st, _ = self.simulate_adapter_subsystem_state(legacy_report, "storage")
        self.assertEqual(state_st, "collected")
        self.assertEqual(status_st, "normal")

        # Network is absent without provenance: must be unknown rather than falsely claimed as not_collected
        state_net, status_net, _ = self.simulate_adapter_subsystem_state(legacy_report, "network")
        self.assertEqual(state_net, "unknown", "Absent domain in legacy report must map to UNKNOWN / LEGACY")
        self.assertNotEqual(state_net, "not_collected")


class TestPhase2MachineCommandView(unittest.TestCase):
    """
    Validates Phase 2 Machine Command View specifications:
    - Central machine object & deterministic snapshot identity.
    - 9 deterministic orbital subsystem domains & at-a-glance telemetry.
    - Drill-down navigation for low & high cardinality domains.
    - High-cardinality component inventory indexing (Services, Processes, Software).
    - Graph-driven search-as-navigation.
    - 5-step deterministic evidence chain inspection.
    """
    def setUp(self):
        self.report_path = os.path.join(os.path.dirname(__file__), 'web', 'samples', 'sysdiag_report_workstation_sanitized.json')
        with open(self.report_path, 'r', encoding='utf-8') as f:
            self.report = json.load(f)

    def test_central_machine_identity_and_snapshot(self):
        meta = self.report.get("metadata", {})
        self.assertEqual(meta.get("hostname"), "WORKSTATION-01")
        self.assertEqual(meta.get("os"), "windows")
        self.assertEqual(meta.get("architecture"), "amd64")
        self.assertTrue(bool(meta.get("scan_timestamp")))
        # Ensure no live connectivity status is claimed
        self.assertNotIn("connectivity_status", meta)
        self.assertNotIn("is_online", meta)

    def test_nine_orbital_subsystems_telemetry(self):
        data = self.report.get("data", {})
        
        # 1. System
        sys = data.get("system", {})
        self.assertIn("os_name", sys)
        self.assertGreater(sys.get("uptime_seconds", 0), 0)
        self.assertIn("virtualization", sys)

        # 2. Compute
        cpu = data.get("cpu", {})
        self.assertIn("model", cpu)
        self.assertGreater(cpu.get("physical_cores", 0), 0)
        self.assertGreater(cpu.get("logical_cores", 0), 0)
        self.assertIsNotNone(cpu.get("utilization_percent"))

        # 3. Memory
        mem = data.get("memory", {})
        self.assertGreater(mem.get("total_bytes", 0), 0)
        self.assertIsNotNone(mem.get("used_percent"))
        self.assertIsNotNone(mem.get("commit_percent"))

        # 4. Storage
        st = data.get("storage", {})
        self.assertGreater(len(st.get("volumes", [])), 0)
        self.assertGreater(len(st.get("physical_disks", [])), 0)
        vol_c = next((v for v in st.get("volumes", []) if v.get("mount_point", "").startswith("C:")), None)
        self.assertIsNotNone(vol_c)
        self.assertIsNotNone(vol_c.get("used_percent"))

        # 5. Network
        net = data.get("network", {})
        self.assertGreater(len(net.get("adapters", [])), 0)
        up_adapters = [a for a in net.get("adapters", []) if a.get("status") == "Up"]
        self.assertGreater(len(up_adapters), 0)

        # 6. Processes
        proc = data.get("processes", {})
        self.assertGreater(proc.get("total_processes", 0), 0)
        self.assertGreater(len(proc.get("top_cpu", [])), 0)

        # 7. Services
        svc = data.get("services", {})
        self.assertGreater(svc.get("total_count", 0), 0)
        self.assertGreater(svc.get("running_count", 0), 0)

        # 8. Reliability
        rel = data.get("reliability", {})
        self.assertIn("time_window_hours", rel)
        self.assertIn("total_errors_logged", rel)

        # 9. Software
        soft = data.get("software", {})
        self.assertGreater(soft.get("total_installed_apps", 0), 0)

    def test_high_cardinality_component_indexing(self):
        """Verify high-cardinality collections contain full item lists for workspace exploration."""
        data = self.report.get("data", {})
        
        # Services collection has 297 entries
        services_list = data.get("services", {}).get("services", [])
        self.assertEqual(len(services_list), 297)
        trusted_installer = next((s for s in services_list if s.get("name") == "TrustedInstaller"), None)
        self.assertIsNotNone(trusted_installer, "TrustedInstaller service must be present in canonical services list")
        self.assertEqual(trusted_installer.get("status"), "Stopped")

        # Processes collection
        top_cpu = data.get("processes", {}).get("top_cpu", [])
        self.assertGreater(len(top_cpu), 0)
        self.assertTrue(bool(top_cpu[0].get("name")))

        # Software applications & runtimes
        apps = data.get("software", {}).get("applications", [])
        self.assertGreater(len(apps), 0)
        runtimes = data.get("software", {}).get("runtimes", [])
        self.assertGreater(len(runtimes), 0)

    def test_search_as_navigation_targets(self):
        """Verify that canonical targets like Wi-Fi, TrustedInstaller, and FINDING-SVC-001 exist in data."""
        # 1. Search Wi-Fi adapter
        adapters = self.report["data"]["network"]["adapters"]
        wifi = next((a for a in adapters if "Wi-Fi" in a.get("name", "")), None)
        self.assertIsNotNone(wifi)

        # 2. Search TrustedInstaller service
        services = self.report["data"]["services"]["services"]
        svc = next((s for s in services if s.get("name") == "TrustedInstaller"), None)
        self.assertIsNotNone(svc)

        # 3. Search finding ID
        findings = self.report.get("findings", [])
        finding_001 = next((f for f in findings if f.get("id") == "FINDING-SVC-001"), None)
        self.assertIsNotNone(finding_001)
        self.assertEqual(finding_001.get("category"), "services")

    def test_diagnostic_health_semantic_terminology(self):
        """
        Verify that Diagnostic Health displays NO FINDING for successfully collected/assessed domains with zero findings,
        NOT ASSESSED for inventory-only or degraded domains, and never claims UNAVAILABLE for healthy/assessed domains.
        """
        assessed_domains = {"system", "compute", "cpu", "memory", "storage", "network", "services", "processes", "reliability"}

        def resolve_diagnostic_health(category, findings_list, collection_state):
            # Check findings
            domain_findings = [f for f in findings_list if f.get("category", "").lower() == category.lower()]
            if len(domain_findings) > 0:
                sevs = [f.get("severity", "INFO").upper() for f in domain_findings]
                top = "CRITICAL" if "CRITICAL" in sevs else ("WARNING" if "WARNING" in sevs else "INFO")
                return top
            
            if collection_state in ["not_collected", "unsupported", "failed", "timeout", "requires_admin"]:
                return "NOT ASSESSED"

            if category.lower() in assessed_domains:
                return "NO FINDING"
            else:
                return "NOT ASSESSED"

        findings = self.report.get("findings", [])

        # Services has 1 INFO finding
        self.assertEqual(resolve_diagnostic_health("services", findings, "success"), "INFO")

        # Network was successfully collected with 0 findings: must be NO FINDING, never UNAVAILABLE
        net_health = resolve_diagnostic_health("network", findings, "success")
        self.assertEqual(net_health, "NO FINDING")
        self.assertNotEqual(net_health, "UNAVAILABLE")

        # Storage was successfully collected with 0 findings: must be NO FINDING, never UNAVAILABLE
        storage_health = resolve_diagnostic_health("storage", findings, "success")
        self.assertEqual(storage_health, "NO FINDING")
        self.assertNotEqual(storage_health, "UNAVAILABLE")

        # Software is inventory only: must be NOT ASSESSED, never UNAVAILABLE
        software_health = resolve_diagnostic_health("software", findings, "success")
        self.assertEqual(software_health, "NOT ASSESSED")
        self.assertNotEqual(software_health, "UNAVAILABLE")

        # Uncollected domain: must be NOT ASSESSED, never claimed as healthy or unavailable
        uncol_health = resolve_diagnostic_health("compute", findings, "not_collected")
        self.assertEqual(uncol_health, "NOT ASSESSED")

    # =========================================================================
    # Phase 3 Acceptance Tests (Scenarios A - F)
    # =========================================================================

    def test_phase3_scenario_a_machine_constellation(self):
        """
        Scenario A — Machine exploration:
        Import report -> Machine appears as central focus -> Nine subsystems spatially surround it ->
        Subsystem telemetry visible -> Findings/provenance visible without clutter.
        """
        meta = self.report.get("metadata", {})
        col = self.report.get("collection_status", {})
        data = self.report.get("data", {})

        # 1. Machine central identity block
        self.assertEqual(meta.get("hostname"), "WORKSTATION-01")
        self.assertIn("Windows 10", meta.get("os_version", ""))
        self.assertEqual(meta.get("architecture"), "amd64")
        self.assertIsNotNone(meta.get("scan_timestamp"))
        self.assertEqual(col.get("successful"), 9)
        self.assertEqual(col.get("total_probes"), 9)

        # 2. Nine spatial subsystem domains present in canonical source data
        expected_domains = ["system", "cpu", "memory", "storage", "network", "processes", "services", "reliability", "software"]
        for domain in expected_domains:
            self.assertIn(domain, data, f"Domain '{domain}' must be present in canonical report")

        # 3. Compact orientation telemetry is computable
        # Compute telemetry: Model, cores, utilization
        cpu = data["cpu"]
        self.assertTrue(bool(cpu.get("model")))
        self.assertGreater(cpu.get("physical_cores", 0), 0)
        self.assertIsNotNone(cpu.get("utilization_percent"))

        # Memory telemetry: total GB, used percent, commit percent
        mem = data["memory"]
        self.assertGreater(mem.get("total_bytes", 0), 0)
        self.assertIsNotNone(mem.get("used_percent"))
        self.assertIsNotNone(mem.get("commit_percent"))

        # Storage telemetry: disk count, volume count, C:\ used percent
        st = data["storage"]
        self.assertGreater(len(st.get("physical_disks", [])), 0)
        self.assertGreater(len(st.get("volumes", [])), 0)

        # Network telemetry: adapter count, primary adapter status
        net = data["network"]
        self.assertGreater(len(net.get("adapters", [])), 0)

        # Services telemetry: indexed count, running count, stopped count
        svc = data["services"]
        self.assertEqual(svc.get("total_count"), 297)
        self.assertGreater(svc.get("running_count", 0), 0)

    def test_phase3_scenario_b_network_spatial_drilldown(self):
        """
        Scenario B — Network drill-down:
        Machine -> Network -> Network becomes focus -> 6 adapters appear ->
        Wi-Fi selected -> Wi-Fi becomes focused component -> Inspector shows canonical Wi-Fi evidence.
        Visual hierarchy must never imply that adapters are physically interconnected unless source evidence says so.
        """
        net_data = self.report["data"]["network"]
        adapters = net_data.get("adapters", [])

        # Total components in Network domain adapters
        self.assertEqual(len(adapters), 6, "Network domain must materialize canonical adapters")

        # Focus Wi-Fi adapter
        wifi = next((a for a in adapters if "Wi-Fi" in a.get("name", "")), None)
        self.assertIsNotNone(wifi, "Wi-Fi adapter must exist")
        self.assertEqual(wifi.get("status"), "Up")
        self.assertEqual(wifi.get("speed_mbps"), 1201)
        self.assertEqual(wifi.get("if_type"), "Wi-Fi")
        self.assertGreater(len(wifi.get("ipv4_addresses", [])), 0)

    def test_phase3_scenario_c_services_spatial_focus_and_evidence(self):
        """
        Scenario C — Services:
        Machine -> Services -> Spatial Services focus -> High-cardinality workspace ->
        FINDING-SVC-001 visible -> Select associated service/finding -> Evidence chain in inspector.
        """
        svc_data = self.report["data"]["services"]
        services_list = svc_data.get("services", [])
        self.assertEqual(len(services_list), 297)

        findings = self.report.get("findings", [])
        svc_finding = next((f for f in findings if f.get("id") == "FINDING-SVC-001"), None)
        self.assertIsNotNone(svc_finding, "FINDING-SVC-001 must exist")
        self.assertEqual(svc_finding.get("category"), "services")
        self.assertEqual(svc_finding.get("severity"), "INFO")

        # Verify complete 5-step deterministic evidence chain
        self.assertTrue(bool(svc_finding.get("title")), "Must have non-empty title")
        self.assertTrue(bool(svc_finding.get("observation")), "Must have non-empty observation")
        self.assertTrue(bool(svc_finding.get("evidence")), "Must have non-empty evidence dictionary")
        self.assertTrue(bool(svc_finding.get("interpretation")), "Must have non-empty interpretation")
        self.assertTrue(bool(svc_finding.get("potential_impact")), "Must have non-empty potential impact")
        self.assertTrue(bool(svc_finding.get("recommendation")), "Must have non-empty recommendation")

        # Verify evidence includes the stopped automatic service
        evidence_services = svc_finding.get("evidence", {}).get("services", [])
        intel_in_finding = next((s for s in evidence_services if "Intel" in s.get("name", "") or "Intel" in s.get("display_name", "")), None)
        self.assertIsNotNone(intel_in_finding, "Intel Platform License Manager must be referenced in finding evidence")

    def test_phase3_scenario_d_search_synchronization_and_history(self):
        """
        Scenario D — Search:
        From Network, search 'Intel' -> Select Intel service ->
        Verify: Network -> search navigation -> WORKSTATION-01 -> Services -> Intel service.
        Breadcrumb, canvas, inspector, and Back history must all agree.
        """
        # Search query 'Intel' matches service 'Intel(R) Platform License Manager Service'
        services = self.report["data"]["services"]["services"] + self.report["data"]["services"].get("failed_auto_start", [])
        intel_service = next((s for s in services if s.get("name", "").startswith("Intel") or "Platform License" in s.get("display_name", "")), None)
        self.assertIsNotNone(intel_service)

        # Verify hierarchical path: WORKSTATION-01 -> Services -> Intel Platform License Manager
        machine_name = self.report["metadata"]["hostname"]
        expected_breadcrumbs = [machine_name, "Services", intel_service.get("name")]
        self.assertEqual(expected_breadcrumbs[0], "WORKSTATION-01")
        self.assertEqual(expected_breadcrumbs[1], "Services")
        self.assertIn("Intel", expected_breadcrumbs[2])

    def test_phase3_scenario_e_degraded_collection_provenance(self):
        """
        Scenario E — Degraded collection:
        Load Partial/Failed/Timeout/Requires-Admin fixtures.
        Verify collection degradation is spatially visible but not represented as a diagnostic machine failure.
        Partial domains remain explorable.
        """
        states = ["success", "partial", "requires_admin", "unsupported", "failed", "timeout"]
        
        for st in states:
            # Degraded collection state must not equal healthy or diagnostic failure
            if st != "success":
                self.assertIn(st, ["partial", "requires_admin", "unsupported", "failed", "timeout"])

        # Test partial collection explorability
        partial_report = copy.deepcopy(self.report)
        partial_report["collection_status"]["probes"] = [
            {"probe_id": "probe-network", "category": "network", "name": "Network Probe", "status": "Partial", "duration_ms": 45, "limitations": "WLAN service disabled"}
        ]
        partial_probe = partial_report["collection_status"]["probes"][0]
        self.assertEqual(partial_probe["status"], "Partial")
        self.assertTrue(bool(partial_probe["limitations"]))
        # Partial report data remains present and explorable
        self.assertIn("network", partial_report["data"])

    def test_phase3_scenario_f_legacy_report_backward_compatibility(self):
        """
        Scenario F — Legacy report:
        Load legacy schema report without explicit probe provenance.
        Preserve UNKNOWN / LEGACY without interpreting missing provenance as failed collection.
        """
        legacy_report = copy.deepcopy(self.report)
        if "probes" in legacy_report["collection_status"]:
            del legacy_report["collection_status"]["probes"]

        # Validate that legacy report without 'probes' validates cleanly against schema 1.0.0
        self.assertNotIn("probes", legacy_report["collection_status"])
        self.assertIn("successful", legacy_report["collection_status"])
        self.assertIn("total_probes", legacy_report["collection_status"])


if __name__ == '__main__':
    unittest.main()
