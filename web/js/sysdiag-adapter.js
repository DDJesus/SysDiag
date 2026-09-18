/**
 * SysDiag 1.0.0 Model Adapter
 * Transforms canonical SysDiag JSON reports into the hierarchical InfrastructureGraph.
 * Enforces strict model boundaries, preserves source evidence, and tracks collection uncertainty.
 */

import { InfrastructureGraph, GraphNode, GraphEdge } from './graph-model.js';
import { SchemaValidator } from './schema-validator.js';

export class SysDiagAdapter {
    /**
     * Adapts a canonical SysDiag report object into an InfrastructureGraph.
     * @param {Object} report - Validated sysdiag report JSON
     * @returns {{ graph: InfrastructureGraph, rawReport: Object, metadata: Object, validation: Object }}
     */
    static materialize(report) {
        // Validate schema first
        const validation = SchemaValidator.validate(report);
        if (!validation.valid) {
            throw new Error(`Schema validation failed:\n• ${validation.errors.join('\n• ')}`);
        }

        const graph = new InfrastructureGraph();
        const meta = report.metadata || {};
        const colStatus = report.collection_status || {};
        const data = report.data || {};
        const findings = report.findings || [];
        const limitations = report.limitations || [];

        // 1. Root Level: Environment (Abstraction Level 0)
        const envNode = new GraphNode({
            id: 'env-root',
            type: 'environment',
            category: 'infrastructure',
            label: 'Observed Environment',
            subtitle: 'Canonical SysDiag Root',
            level: 0,
            parentId: null,
            sourceData: { metadata: meta, collection_status: colStatus },
            status: 'normal',
            metadata: { tool_version: meta.tool_version, scan_timestamp: meta.scan_timestamp }
        });
        graph.addNode(envNode);
        graph.rootId = envNode.id;

        // 2. Level 1: Site / Cluster (Abstraction Level 1)
        const siteNode = new GraphNode({
            id: 'site-local',
            type: 'site',
            category: 'infrastructure',
            label: 'Local Host Scope',
            subtitle: meta.hostname ? `Host context: ${meta.hostname}` : 'Local Diagnostic Scope',
            level: 1,
            parentId: envNode.id,
            sourceData: { hostname: meta.hostname, profile: meta.profile },
            status: 'normal'
        });
        graph.addNode(siteNode);

        // 3. Level 2: Network Group (Abstraction Level 2)
        const netGroupNode = new GraphNode({
            id: 'netgroup-default',
            type: 'network_group',
            category: 'infrastructure',
            label: 'Host Network Boundary',
            subtitle: 'Local interfaces & route topology',
            level: 2,
            parentId: siteNode.id,
            sourceData: data.network || null,
            status: 'normal'
        });
        graph.addNode(netGroupNode);

        // 4. Level 3: Machine Node (Central Subject)
        const hostname = meta.hostname || 'Unknown-Machine';
        const machineId = `machine-${hostname}`;
        const machineNode = new GraphNode({
            id: machineId,
            type: 'machine',
            category: 'system',
            label: hostname,
            subtitle: `${meta.os || 'OS'} ${meta.os_version || ''} (${meta.architecture || 'x64'})`,
            level: 3,
            parentId: netGroupNode.id,
            sourceData: { metadata: meta, collection_status: colStatus, dataSummary: Object.keys(data) },
            status: 'normal',
            metrics: {
                total_probes: colStatus.total_probes || 0,
                successful_probes: colStatus.successful || 0,
                scan_duration_ms: meta.scan_duration_ms || 0,
                privilege_level: meta.privilege_level || 'User',
                is_elevated: meta.is_elevated || false,
                profile: meta.profile || 'quick'
            },
            metadata: {
                ...meta,
                collection_status: colStatus
            }
        });
        graph.addNode(machineNode);
        graph.activeMachineId = machineNode.id;

        // Index limitations by probe_id and category
        const limitationsMap = new Map();
        limitations.forEach(lim => {
            if (lim.category) limitationsMap.set(lim.category.toLowerCase(), lim);
            if (lim.probe_id) limitationsMap.set(lim.probe_id.toLowerCase(), lim);
        });

        // Index per-probe collection provenance records if present
        const probesList = colStatus.probes || report.probes || null;
        const hasExplicitProvenance = Array.isArray(probesList) && probesList.length > 0;
        const probesMap = new Map();

        if (hasExplicitProvenance) {
            probesList.forEach(p => {
                if (p.probe_id) probesMap.set(p.probe_id.toLowerCase(), p);
                if (p.category) probesMap.set(p.category.toLowerCase(), p);
            });
        }

        // 5. Level 4: The 9 Major Subsystems
        const subsystemsConfig = [
            { key: 'system', label: 'System', category: 'system', desc: 'OS, host identity, uptime, virtualization' },
            { key: 'cpu', label: 'Compute', category: 'compute', desc: 'Processor architecture, cores, utilization' },
            { key: 'memory', label: 'Memory', category: 'memory', desc: 'Physical RAM, available, commit charge' },
            { key: 'storage', label: 'Storage', category: 'storage', desc: 'Physical disks, drive geometry, volumes' },
            { key: 'network', label: 'Network', category: 'network', desc: 'Adapters, IP bindings, gateway, DNS' },
            { key: 'processes', label: 'Processes', category: 'processes', desc: 'Process execution tree, top consumers' },
            { key: 'services', label: 'Services', category: 'services', desc: 'System daemons, auto-start health' },
            { key: 'reliability', label: 'Reliability', category: 'reliability', desc: 'Crashes, system errors, kernel power' },
            { key: 'software', label: 'Software', category: 'software', desc: 'Installed software, updates, runtimes' }
        ];

        const subsystemNodesMap = new Map();

        subsystemsConfig.forEach(cfg => {
            const rawSubsystemData = data[cfg.key];
            const limitation = limitationsMap.get(cfg.key) || limitationsMap.get(cfg.category);

            // Lookup probe record
            const probeRecord = hasExplicitProvenance
                ? (probesMap.get(cfg.key.toLowerCase()) || 
                   probesMap.get(cfg.category.toLowerCase()) || 
                   probesMap.get(`probe_${cfg.key.toLowerCase()}`) || 
                   probesMap.get(`probe_${cfg.category.toLowerCase()}`) || 
                   null)
                : null;

            let collectionState = 'collected';
            let status = 'normal';

            if (hasExplicitProvenance) {
                if (probeRecord) {
                    const pStatus = (probeRecord.status || '').toLowerCase();
                    if (pStatus === 'success') {
                        collectionState = 'success';
                        status = 'normal';
                    } else if (pStatus === 'partial') {
                        collectionState = 'partial';
                        status = 'degraded';
                    } else if (pStatus === 'requires administrator' || pStatus === 'requires_admin' || pStatus === 'requiresadmin') {
                        collectionState = 'requires_admin';
                        status = 'degraded';
                    } else if (pStatus === 'unsupported') {
                        collectionState = 'unsupported';
                        status = 'unsupported';
                    } else if (pStatus === 'timeout') {
                        collectionState = 'timeout';
                        status = 'timeout';
                    } else if (pStatus === 'failed') {
                        collectionState = 'failed';
                        status = 'failed';
                    } else {
                        collectionState = pStatus;
                        status = 'degraded';
                    }
                } else {
                    // Modern report with explicit probes list, but this probe was not in the execution list
                    collectionState = 'not_collected';
                    status = 'unavailable';
                }
            } else {
                // Legacy schema 1.0.0 report without per-probe provenance
                if (rawSubsystemData) {
                    collectionState = 'collected';
                    status = 'normal';
                } else if (limitation) {
                    const isAdm = limitation.reason?.toLowerCase().includes('admin') || limitation.privilege_required?.toLowerCase().includes('admin');
                    collectionState = isAdm ? 'requires_admin' : 'partial';
                    status = 'degraded';
                } else {
                    // Legacy report lacking both data and provenance: label UNKNOWN/LEGACY rather than claiming NOT COLLECTED
                    collectionState = 'unknown';
                    status = 'unknown';
                }
            }

            const subsysId = `subsys-${cfg.category}`;
            const subNode = new GraphNode({
                id: subsysId,
                type: 'subsystem',
                category: cfg.category,
                label: cfg.label,
                subtitle: cfg.desc,
                level: 4,
                parentId: machineNode.id,
                sourceData: rawSubsystemData || null,
                collectionState,
                status,
                metadata: {
                    probeRecord: probeRecord || null,
                    limitation: limitation || (probeRecord?.reason ? { reason: probeRecord.reason, probe_id: probeRecord.probe_id, category: probeRecord.category } : null)
                }
            });

            // Extract core high-level metrics per subsystem
            this._extractSubsystemMetrics(subNode, rawSubsystemData, cfg.key);

            if (probeRecord) {
                subNode.metrics.probe_id = probeRecord.probe_id;
                subNode.metrics.probe_status = probeRecord.status;
                subNode.metrics.probe_duration_ms = probeRecord.duration_ms;
                if (probeRecord.reason) subNode.metrics.probe_reason = probeRecord.reason;
                if (probeRecord.privilege_required) subNode.metrics.probe_privilege_required = probeRecord.privilege_required;
            }

            graph.addNode(subNode);
            subsystemNodesMap.set(cfg.category, subNode);
        });

        // 6. Level 5: Materialize Components within Subsystems
        this._materializeComponents(graph, data, subsystemNodesMap);

        // 7. Level 6: Findings & Evidence Overlays
        this._attachFindings(graph, findings, subsystemNodesMap, machineNode);

        // 8. Update hierarchical status indicators
        this._propagateStatus(graph);

        return {
            graph,
            rawReport: report,
            metadata: meta,
            validation
        };
    }

    /**
     * Extracts canonical scalar metrics for subsystem overview cards.
     */
    static _extractSubsystemMetrics(node, rawData, key) {
        if (!rawData) return;
        switch (key) {
            case 'system':
                node.metrics = {
                    os_name: rawData.os_name || 'Windows',
                    os_version: rawData.os_version || '',
                    os_build: rawData.os_build || '',
                    uptime_seconds: rawData.uptime_seconds || 0,
                    uptime_formatted: rawData.uptime_seconds ? `${(rawData.uptime_seconds / 3600).toFixed(1)} hrs` : '0 hrs',
                    boot_time: rawData.boot_time || null,
                    is_virtual: rawData.virtualization?.is_virtual || false,
                    hypervisor: rawData.virtualization?.hypervisor || (rawData.virtualization?.is_virtual ? 'Virtual VM' : 'Physical Hardware')
                };
                break;
            case 'cpu':
                node.metrics = {
                    model: rawData.model || 'Unknown CPU',
                    physical_cores: rawData.physical_cores || 0,
                    logical_cores: rawData.logical_cores || 0,
                    utilization_percent: rawData.utilization_percent !== undefined ? rawData.utilization_percent : null,
                    user_percent: rawData.user_percent !== undefined ? rawData.user_percent : null,
                    kernel_percent: rawData.kernel_percent !== undefined ? rawData.kernel_percent : null
                };
                break;
            case 'memory':
                node.metrics = {
                    total_bytes: rawData.total_bytes || 0,
                    available_bytes: rawData.available_bytes || 0,
                    used_bytes: rawData.used_bytes || 0,
                    used_percent: rawData.used_percent !== undefined ? rawData.used_percent : null,
                    commit_total_bytes: rawData.commit_total_bytes || 0,
                    commit_limit_bytes: rawData.commit_limit_bytes || 0,
                    commit_percent: rawData.commit_percent !== undefined ? rawData.commit_percent : null
                };
                break;
            case 'storage': {
                const volCount = rawData.volumes ? rawData.volumes.length : 0;
                const diskCount = rawData.physical_disks ? rawData.physical_disks.length : 0;
                const primaryVol = (rawData.volumes || []).find(v => v.mount_point?.toUpperCase().startsWith('C:')) || (rawData.volumes || [])[0];
                node.metrics = {
                    volume_count: volCount,
                    physical_disk_count: diskCount,
                    primary_volume_mount: primaryVol ? primaryVol.mount_point : null,
                    primary_volume_used_percent: primaryVol ? primaryVol.used_percent : null
                };
                break;
            }
            case 'network': {
                const adapters = rawData.adapters || [];
                const upAdapters = adapters.filter(a => a.status === 'Up');
                const activeWifiOrEth = upAdapters.find(a => a.name?.includes('Wi-Fi') || a.name?.includes('Ethernet')) || upAdapters[0];
                node.metrics = {
                    total_adapters: adapters.length,
                    active_adapters: upAdapters.length,
                    active_adapter_name: activeWifiOrEth ? activeWifiOrEth.name : (adapters.length > 0 ? adapters[0].name : 'None'),
                    active_adapter_status: activeWifiOrEth ? activeWifiOrEth.status : 'Down',
                    active_adapter_speed_mbps: activeWifiOrEth ? activeWifiOrEth.speed_mbps : null,
                    dns_test_latency_ms: rawData.dns_test?.duration_ms || null,
                    dns_test_success: rawData.dns_test?.success ?? null
                };
                break;
            }
            case 'processes': {
                const topCpuProc = (rawData.top_cpu || [])[0];
                node.metrics = {
                    total_processes: rawData.total_processes || (rawData.processes ? rawData.processes.length : 0),
                    total_threads: rawData.total_threads || 0,
                    top_cpu_count: rawData.top_cpu?.length || 0,
                    top_mem_count: rawData.top_memory?.length || 0,
                    top_cpu_name: topCpuProc ? topCpuProc.name : null,
                    top_cpu_usage: topCpuProc ? (topCpuProc.cpu_percent !== undefined ? `${topCpuProc.cpu_percent}%` : `${topCpuProc.cpu_time_seconds}s`) : null
                };
                break;
            }
            case 'services':
                node.metrics = {
                    total_count: rawData.total_count || (rawData.services ? rawData.services.length : 0),
                    running_count: rawData.running_count || 0,
                    stopped_count: rawData.stopped_count || 0,
                    failed_auto_start_count: rawData.failed_auto_start_count || (rawData.failed_auto_start ? rawData.failed_auto_start.length : 0)
                };
                break;
            case 'reliability':
                node.metrics = {
                    time_window_hours: rawData.time_window_hours || 24,
                    total_errors_logged: rawData.total_errors_logged || 0,
                    app_crashes_count: rawData.app_crashes?.length || 0,
                    system_errors_count: rawData.system_errors?.length || 0,
                    kernel_power_count: rawData.kernel_power_events?.length || 0,
                    bugchecks_count: rawData.bugchecks?.length || 0
                };
                break;
            case 'software':
                node.metrics = {
                    total_installed_apps: rawData.total_installed_apps || (rawData.applications ? rawData.applications.length : 0),
                    runtimes_count: rawData.runtimes?.length || 0,
                    hotfixes_count: rawData.hotfixes?.length || 0
                };
                break;
        }
    }

    /**
     * Materializes granular components for detailed exploration.
     */
    static _materializeComponents(graph, data, subsystemNodesMap) {
        // 1. Compute / CPU Component
        if (data.cpu && subsystemNodesMap.has('compute')) {
            const cpuSubsys = subsystemNodesMap.get('compute');
            const cpuComp = new GraphNode({
                id: 'comp-cpu-core',
                type: 'component',
                category: 'compute',
                label: data.cpu.model || 'Processor',
                subtitle: `${data.cpu.physical_cores} Cores / ${data.cpu.logical_cores} Threads`,
                level: 5,
                parentId: cpuSubsys.id,
                sourceData: data.cpu,
                status: 'normal',
                metrics: {
                    utilization_percent: data.cpu.utilization_percent,
                    user_percent: data.cpu.user_percent,
                    kernel_percent: data.cpu.kernel_percent,
                    physical_cores: data.cpu.physical_cores,
                    logical_cores: data.cpu.logical_cores
                }
            });
            graph.addNode(cpuComp);
        }

        // 2. Storage Components: Physical Disks & Volumes
        if (data.storage && subsystemNodesMap.has('storage')) {
            const storageSubsys = subsystemNodesMap.get('storage');

            // Physical Disks
            (data.storage.physical_disks || []).forEach((disk, idx) => {
                const diskId = `comp-disk-${disk.device_id ? disk.device_id.replace(/[^a-zA-Z0-9_-]/g, '_') : idx}`;
                const diskNode = new GraphNode({
                    id: diskId,
                    type: 'component',
                    category: 'storage',
                    label: disk.device_id || `PhysicalDisk${idx}`,
                    subtitle: `${disk.model || 'Storage Device'} [${disk.bus_type || 'Unknown'}]`,
                    level: 5,
                    parentId: storageSubsys.id,
                    sourceData: disk,
                    status: 'normal',
                    metrics: {
                        model: disk.model,
                        media_type: disk.media_type,
                        bus_type: disk.bus_type,
                        serial_number: disk.serial_number,
                        size_bytes: disk.size_bytes
                    }
                });
                graph.addNode(diskNode);
            });

            // Volumes
            (data.storage.volumes || []).forEach((vol, idx) => {
                const volId = `comp-vol-${vol.mount_point ? vol.mount_point.replace(/[^a-zA-Z0-9_-]/g, '_') : idx}`;
                const volNode = new GraphNode({
                    id: volId,
                    type: 'component',
                    category: 'storage',
                    label: vol.mount_point || `Volume ${idx}`,
                    subtitle: `${vol.volume_name || 'Volume'} (${vol.filesystem || 'Unknown'} - ${vol.used_percent}% used)`,
                    level: 5,
                    parentId: storageSubsys.id,
                    sourceData: vol,
                    status: 'normal',
                    metrics: {
                        mount_point: vol.mount_point,
                        volume_name: vol.volume_name,
                        filesystem: vol.filesystem,
                        drive_type: vol.drive_type,
                        total_bytes: vol.total_bytes,
                        free_bytes: vol.free_bytes,
                        used_bytes: vol.used_bytes,
                        used_percent: vol.used_percent,
                        is_read_only: vol.is_read_only
                    }
                });
                graph.addNode(volNode);
            });
        }

        // 3. Network Adapters Components
        if (data.network && subsystemNodesMap.has('network')) {
            const netSubsys = subsystemNodesMap.get('network');
            (data.network.adapters || []).forEach((adapter, idx) => {
                const adapterId = `comp-adapter-${adapter.name ? encodeURIComponent(adapter.name) : idx}`;
                const isUp = adapter.status === 'Up';
                const adapterNode = new GraphNode({
                    id: adapterId,
                    type: 'component',
                    category: 'network',
                    label: adapter.name || `Adapter ${idx}`,
                    subtitle: `${adapter.description || adapter.if_type || 'Network Interface'} (${adapter.status})`,
                    level: 5,
                    parentId: netSubsys.id,
                    sourceData: adapter,
                    status: isUp ? 'normal' : 'unavailable',
                    metrics: {
                        id: adapter.id,
                        name: adapter.name,
                        status: adapter.status,
                        if_type: adapter.if_type,
                        speed_mbps: adapter.speed_mbps,
                        mac_address: adapter.mac_address,
                        ipv4_addresses: adapter.ipv4_addresses || [],
                        ipv6_addresses: adapter.ipv6_addresses || [],
                        gateways: adapter.gateways || [],
                        dns_servers: adapter.dns_servers || [],
                        dhcp_enabled: adapter.dhcp_enabled,
                        in_errors: adapter.in_errors || 0,
                        out_errors: adapter.out_errors || 0
                    }
                });
                graph.addNode(adapterNode);
            });

            if (data.network.dns_test) {
                const dnsNode = new GraphNode({
                    id: 'comp-net-dns-test',
                    type: 'component',
                    category: 'network',
                    label: 'DNS Resolution Probe',
                    subtitle: `Target: ${data.network.dns_test.query_target} (${data.network.dns_test.duration_ms} ms)`,
                    level: 5,
                    parentId: netSubsys.id,
                    sourceData: data.network.dns_test,
                    status: data.network.dns_test.success ? 'normal' : 'warning',
                    metrics: {
                        query_target: data.network.dns_test.query_target,
                        duration_ms: data.network.dns_test.duration_ms,
                        success: data.network.dns_test.success,
                        resolved_ips: data.network.dns_test.resolved_ips || [],
                        error: data.network.dns_test.error || null
                    }
                });
                graph.addNode(dnsNode);
            }
        }

        // 4. Processes: Top CPU, Top Memory & All Processes
        if (data.processes && subsystemNodesMap.has('processes')) {
            const procSubsys = subsystemNodesMap.get('processes');
            (data.processes.top_cpu || []).slice(0, 5).forEach(proc => {
                const procId = `comp-proc-cpu-${proc.pid}`;
                const procNode = new GraphNode({
                    id: procId,
                    type: 'component',
                    category: 'processes',
                    label: `${proc.name} (PID: ${proc.pid})`,
                    subtitle: `Top CPU Consumer • ${proc.cpu_time_seconds ? proc.cpu_time_seconds.toFixed(1) + 's CPU' : (proc.cpu_percent || 0) + '% CPU'}`,
                    level: 5,
                    parentId: procSubsys.id,
                    sourceData: proc,
                    status: 'normal',
                    metrics: { ...proc }
                });
                graph.addNode(procNode);
            });

            (data.processes.top_memory || []).slice(0, 5).forEach(proc => {
                const procId = `comp-proc-mem-${proc.pid}`;
                if (!graph.getNode(procId)) {
                    const procNode = new GraphNode({
                        id: procId,
                        type: 'component',
                        category: 'processes',
                        label: `${proc.name} (PID: ${proc.pid})`,
                        subtitle: `Top Memory Consumer • ${(proc.working_set_bytes / (1024*1024)).toFixed(1)} MB RAM`,
                        level: 5,
                        parentId: procSubsys.id,
                        sourceData: proc,
                        status: 'normal',
                        metrics: { ...proc }
                    });
                    graph.addNode(procNode);
                }
            });

            // Index all processes for search & workspace exploration
            (data.processes.processes || []).forEach(proc => {
                const procId = `comp-proc-${proc.pid}`;
                if (!graph.getNode(procId)) {
                    const procNode = new GraphNode({
                        id: procId,
                        type: 'component',
                        category: 'processes',
                        label: `${proc.name} (PID: ${proc.pid})`,
                        subtitle: `Process • ${proc.thread_count || 0} threads • ${(proc.working_set_bytes ? (proc.working_set_bytes / (1024*1024)).toFixed(1) + ' MB' : '0 MB')}`,
                        level: 5,
                        parentId: procSubsys.id,
                        sourceData: proc,
                        status: 'normal',
                        metrics: { ...proc }
                    });
                    graph.addNode(procNode);
                }
            });
        }

        // 5. Services: Failed Auto-Start & All Services Components
        if (data.services && subsystemNodesMap.has('services')) {
            const svcSubsys = subsystemNodesMap.get('services');
            (data.services.failed_auto_start || []).forEach(svc => {
                const svcId = `comp-svc-failed-${svc.name ? encodeURIComponent(svc.name) : 'unknown'}`;
                const svcNode = new GraphNode({
                    id: svcId,
                    type: 'component',
                    category: 'services',
                    label: svc.display_name || svc.name,
                    subtitle: `Service "${svc.name}" • ${svc.start_type} • ${svc.status} (Exit: ${svc.exit_code || 0})`,
                    level: 5,
                    parentId: svcSubsys.id,
                    sourceData: svc,
                    status: svc.exit_code !== 0 ? 'warning' : 'info',
                    metrics: {
                        name: svc.name,
                        display_name: svc.display_name,
                        start_type: svc.start_type,
                        status: svc.status,
                        exit_code: svc.exit_code
                    }
                });
                graph.addNode(svcNode);
            });

            // Index all registered services
            (data.services.services || []).forEach((svc, idx) => {
                const svcId = `comp-svc-${svc.name ? encodeURIComponent(svc.name) : idx}`;
                if (!graph.getNode(svcId)) {
                    const isRunning = (svc.status || '').toLowerCase() === 'running';
                    const isWarn = svc.exit_code && svc.exit_code !== 0;
                    const svcNode = new GraphNode({
                        id: svcId,
                        type: 'component',
                        category: 'services',
                        label: svc.display_name || svc.name,
                        subtitle: `Service "${svc.name}" • ${svc.start_type || 'Manual'} • ${svc.status || 'Stopped'}`,
                        level: 5,
                        parentId: svcSubsys.id,
                        sourceData: svc,
                        status: isWarn ? 'warning' : (isRunning ? 'normal' : 'info'),
                        metrics: {
                            name: svc.name,
                            display_name: svc.display_name,
                            start_type: svc.start_type,
                            status: svc.status,
                            pid: svc.pid,
                            binary_path: svc.binary_path,
                            account: svc.account,
                            exit_code: svc.exit_code
                        }
                    });
                    graph.addNode(svcNode);
                }
            });
        }

        // 6. Reliability Components: App Crashes, System Errors & BSODs
        if (data.reliability && subsystemNodesMap.has('reliability')) {
            const relSubsys = subsystemNodesMap.get('reliability');
            (data.reliability.app_crashes || []).forEach((crash, idx) => {
                const crashId = `comp-rel-crash-${idx}`;
                const crashNode = new GraphNode({
                    id: crashId,
                    type: 'component',
                    category: 'reliability',
                    label: `Crash: ${crash.application || 'App'}`,
                    subtitle: `Fault: ${crash.fault_module || 'Unknown'} (Exception: ${crash.exception_code || 'N/A'})`,
                    level: 5,
                    parentId: relSubsys.id,
                    sourceData: crash,
                    status: 'warning',
                    metrics: { ...crash }
                });
                graph.addNode(crashNode);
            });
            (data.reliability.bugchecks || []).forEach((bsod, idx) => {
                const bsodId = `comp-rel-bsod-${idx}`;
                const bsodNode = new GraphNode({
                    id: bsodId,
                    type: 'component',
                    category: 'reliability',
                    label: `BSOD: ${bsod.bugcheck_string || bsod.bugcheck_code || 'Kernel Dump'}`,
                    subtitle: bsod.message || 'Blue Screen of Death event',
                    level: 5,
                    parentId: relSubsys.id,
                    sourceData: bsod,
                    status: 'critical',
                    metrics: { ...bsod }
                });
                graph.addNode(bsodNode);
            });
        }

        // 7. Software Components: Installed Apps, Runtimes & Hotfixes
        if (data.software && subsystemNodesMap.has('software')) {
            const softSubsys = subsystemNodesMap.get('software');
            (data.software.applications || []).forEach((app, idx) => {
                const appId = `comp-soft-app-${app.name ? encodeURIComponent(app.name) : idx}`;
                if (!graph.getNode(appId)) {
                    const appNode = new GraphNode({
                        id: appId,
                        type: 'component',
                        category: 'software',
                        label: app.name || 'Application',
                        subtitle: `Version: ${app.version || 'Unknown'} ${app.publisher ? `• ${app.publisher}` : ''}`,
                        level: 5,
                        parentId: softSubsys.id,
                        sourceData: app,
                        status: 'normal',
                        metrics: { ...app }
                    });
                    graph.addNode(appNode);
                }
            });

            (data.software.runtimes || []).forEach((runtime, idx) => {
                const rtId = `comp-soft-runtime-${idx}`;
                const rtNode = new GraphNode({
                    id: rtId,
                    type: 'component',
                    category: 'software',
                    label: runtime.name || 'Runtime',
                    subtitle: `Version: ${runtime.version} ${runtime.path ? `(${runtime.path})` : ''}`,
                    level: 5,
                    parentId: softSubsys.id,
                    sourceData: runtime,
                    status: 'normal',
                    metrics: { ...runtime }
                });
                graph.addNode(rtNode);
            });

            (data.software.hotfixes || []).forEach((hf, idx) => {
                const hfId = `comp-soft-hotfix-${hf.hotfix_id ? encodeURIComponent(hf.hotfix_id) : idx}`;
                if (!graph.getNode(hfId)) {
                    const hfNode = new GraphNode({
                        id: hfId,
                        type: 'component',
                        category: 'software',
                        label: hf.hotfix_id || `Hotfix ${idx}`,
                        subtitle: `${hf.description || 'Windows Update'} • Installed: ${hf.installed_on || 'N/A'}`,
                        level: 5,
                        parentId: softSubsys.id,
                        sourceData: hf,
                        status: 'normal',
                        metrics: { ...hf }
                    });
                    graph.addNode(hfNode);
                }
            });
        }
    }

    /**
     * Attaches findings as canonical overlays to the relevant subsystem and component nodes.
     */
    static _attachFindings(graph, findings, subsystemNodesMap, machineNode) {
        findings.forEach(finding => {
            const category = (finding.category || 'general').toLowerCase();
            const targetSubsystem = subsystemNodesMap.get(category);

            // Register finding node in graph (Level 6)
            const parentId = targetSubsystem ? targetSubsystem.id : machineNode.id;
            const findingNode = new GraphNode({
                id: `finding-${finding.id}`,
                type: 'finding',
                category,
                label: finding.title || finding.id,
                subtitle: `Severity: ${finding.severity} • Confidence: ${finding.confidence}`,
                level: 6,
                parentId,
                sourceData: finding,
                status: finding.severity.toLowerCase(),
                metrics: {
                    id: finding.id,
                    severity: finding.severity,
                    confidence: finding.confidence,
                    category: finding.category
                },
                metadata: {
                    observation: finding.observation,
                    evidence: finding.evidence,
                    interpretation: finding.interpretation,
                    potential_impact: finding.potential_impact,
                    recommendation: finding.recommendation
                }
            });
            graph.addNode(findingNode);

            // Associate with target subsystem
            if (targetSubsystem) {
                targetSubsystem.findings.push(finding);
                // Also check if any component under this subsystem is directly targeted by this finding
                const children = graph.getChildren(targetSubsystem.id);
                children.forEach(child => {
                    // Check if finding references service or disk or adapter
                    if (finding.evidence && finding.evidence.services && Array.isArray(finding.evidence.services)) {
                        finding.evidence.services.forEach(s => {
                            if (child.id === `comp-svc-failed-${s.name}`) {
                                child.findings.push(finding);
                                child.status = finding.severity.toLowerCase();
                            }
                        });
                    }
                });
            } else {
                machineNode.findings.push(finding);
            }
        });
    }

    /**
     * Propagates finding severities and collection states up the hierarchy.
     */
    static _propagateStatus(graph) {
        const severityRank = {
            critical: 4,
            warning: 3,
            info: 2,
            degraded: 2,
            unavailable: 1,
            normal: 0
        };

        const updateNodeStatus = (node) => {
            let maxRank = severityRank[node.status] || 0;

            // Check direct findings
            if (node.findings && node.findings.length > 0) {
                node.findings.forEach(f => {
                    const rank = severityRank[f.severity.toLowerCase()] || 0;
                    if (rank > maxRank) maxRank = rank;
                });
            }

            // Check children
            const children = graph.getChildren(node.id);
            children.forEach(child => {
                const childStatus = updateNodeStatus(child);
                const rank = severityRank[childStatus] || 0;
                if (rank > maxRank) maxRank = rank;
            });

            // Map rank back to status string
            for (const [statusStr, rank] of Object.entries(severityRank)) {
                if (rank === maxRank) {
                    node.status = statusStr;
                    break;
                }
            }

            return node.status;
        };

        if (graph.rootId) {
            updateNodeStatus(graph.getNode(graph.rootId));
        }
    }
}
