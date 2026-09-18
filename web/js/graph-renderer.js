/**
 * Interactive Infrastructure Graph Renderer - Phase 3 Spatial Infrastructure Navigation
 * 
 * Implements a generic spatial-focus navigation architecture:
 * Focus Object → Related/Child Objects → Select → Refocus → Drill Down → Evidence.
 * Supports:
 * - Machine focal constellation with deterministic 9-subsystem orbital layout
 * - Subsystem focal hubs with spatial child components (low-cardinality)
 * - Reusable high-cardinality workspaces with immediate spatial synchronization
 * - Component focal view with rich technical telemetry, sibling navigation, and finding links
 * - Receded hierarchical parent context visualization
 * - Dynamic SVG bounding-box fit and semantic zoom/pan controls
 * - Strict diagnostic integrity (no inferred topology or fake real-time animation)
 */

export class GraphRenderer {
    /**
     * @param {HTMLElement} container
     * @param {Object} callbacks
     * @param {Function} callbacks.onSelectNode - Called when a node is clicked/selected
     * @param {Function} callbacks.onDrillDown - Called when a node is focused/drilled into
     */
    constructor(container, { onSelectNode, onDrillDown }) {
        this.container = container;
        this.onSelectNode = onSelectNode;
        this.onDrillDown = onDrillDown;

        this.graph = null;
        this.currentFocusNodeId = null;
        this.selectedNodeId = null;
        this.viewMode = 'spatial'; // 'spatial' | 'workspace'

        this.zoomLevel = 1;
        this.panX = 0;
        this.panY = 0;
        this.isDragging = false;
        this.dragStartX = 0;
        this.dragStartY = 0;

        this.workspaceFilter = 'all';
        this.workspaceQuery = '';
        this.workspaceSortField = 'name';
        this.workspaceSortAsc = true;

        this._initDOM();
    }

    _initDOM() {
        this.container.innerHTML = `
            <div class="viewport-controls">
                <button class="ctrl-btn" id="btn-zoom-in" title="Zoom In">+</button>
                <button class="ctrl-btn" id="btn-zoom-out" title="Zoom Out">−</button>
                <button class="ctrl-btn" id="btn-zoom-fit" title="Fit Spatial View">⊙</button>
                <button class="ctrl-btn" id="btn-zoom-reset" title="Reset View">⤢</button>
            </div>
            <div class="topology-stage">
                <svg class="topology-svg" width="100%" height="100%">
                    <defs>
                        <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                            <feGaussianBlur stdDeviation="3" result="blur" />
                            <feMerge>
                                <feMergeNode in="blur" />
                                <feMergeNode in="SourceGraphic" />
                            </feMerge>
                        </filter>
                        <linearGradient id="edge-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                            <stop offset="0%" stop-color="#00e5ff" stop-opacity="0.6"/>
                            <stop offset="100%" stop-color="#38bdf8" stop-opacity="0.2"/>
                        </linearGradient>
                        <linearGradient id="edge-warn-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                            <stop offset="0%" stop-color="#f59e0b" stop-opacity="0.7"/>
                            <stop offset="100%" stop-color="#fbbf24" stop-opacity="0.3"/>
                        </linearGradient>
                        <linearGradient id="edge-crit-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                            <stop offset="0%" stop-color="#ef4444" stop-opacity="0.8"/>
                            <stop offset="100%" stop-color="#f87171" stop-opacity="0.3"/>
                        </linearGradient>
                        <pattern id="dot-grid" width="30" height="30" patternUnits="userSpaceOnUse">
                            <circle cx="2" cy="2" r="1" fill="#1e293b" opacity="0.6"/>
                        </pattern>
                    </defs>
                    <rect width="100%" height="100%" fill="url(#dot-grid)" class="bg-grid-rect" />
                    <g class="svg-edges-layer"></g>
                    <g class="svg-nodes-layer"></g>
                </svg>
                <div class="workspace-overlay" id="workspace-overlay" style="display: none;"></div>
            </div>
        `;

        this.stage = this.container.querySelector('.topology-stage');
        this.svg = this.container.querySelector('.topology-svg');
        this.edgesLayer = this.container.querySelector('.svg-edges-layer');
        this.nodesLayer = this.container.querySelector('.svg-nodes-layer');
        this.workspaceOverlay = this.container.querySelector('#workspace-overlay');

        // Setup Viewport Control listeners
        this.container.querySelector('#btn-zoom-in').addEventListener('click', () => this.zoom(1.15));
        this.container.querySelector('#btn-zoom-out').addEventListener('click', () => this.zoom(0.85));
        this.container.querySelector('#btn-zoom-fit').addEventListener('click', () => this.fitView());
        this.container.querySelector('#btn-zoom-reset').addEventListener('click', () => this.resetView());

        // Pan & Zoom mouse listeners
        this.svg.addEventListener('mousedown', (e) => {
            if (e.target.closest('.topo-node') || e.target.closest('button') || e.target.closest('a')) return;
            this.isDragging = true;
            this.dragStartX = e.clientX - this.panX;
            this.dragStartY = e.clientY - this.panY;
            this.svg.style.cursor = 'grabbing';
        });

        window.addEventListener('mousemove', (e) => {
            if (!this.isDragging) return;
            this.panX = e.clientX - this.dragStartX;
            this.panY = e.clientY - this.dragStartY;
            this._applyTransform();
        });

        window.addEventListener('mouseup', () => {
            this.isDragging = false;
            if (this.svg) this.svg.style.cursor = 'grab';
        });

        this.svg.addEventListener('wheel', (e) => {
            e.preventDefault();
            const delta = e.deltaY < 0 ? 1.1 : 0.9;
            this.zoom(delta);
        }, { passive: false });

        window.addEventListener('resize', () => {
            if (this.graph && this.currentFocusNodeId) {
                this.render();
            }
        });
    }

    /**
     * Attaches and renders an InfrastructureGraph.
     * @param {InfrastructureGraph} graph
     * @param {string} [focusNodeId]
     */
    setGraph(graph, focusNodeId = null) {
        this.graph = graph;
        this.currentFocusNodeId = focusNodeId || graph.activeMachineId || graph.rootId;
        this.selectedNodeId = this.currentFocusNodeId;
        this.fitView();
    }

    /**
     * Focuses a specific node (Machine, Subsystem, Component, or Finding).
     * @param {string} nodeId
     * @param {string} [mode='spatial']
     */
    focusNode(nodeId, mode = 'spatial') {
        this.currentFocusNodeId = nodeId;
        this.selectedNodeId = nodeId;
        this.viewMode = mode;
        this.render();
        // Automatically fit view to the newly focused layout
        this.fitView();
    }

    /**
     * Highlights selected node without changing focus layout if already visible.
     */
    selectNode(nodeId) {
        this.selectedNodeId = nodeId;
        this.container.querySelectorAll('.topo-node').forEach(el => {
            if (el.dataset.nodeId === nodeId) {
                el.classList.add('selected');
            } else {
                el.classList.remove('selected');
            }
        });

        // Also update workspace table row selection if present
        if (this.workspaceOverlay) {
            this.workspaceOverlay.querySelectorAll('.ws-table-row').forEach(row => {
                if (row.dataset.nodeId === nodeId) {
                    row.classList.add('selected-row');
                } else {
                    row.classList.remove('selected-row');
                }
            });
        }
    }

    zoom(factor) {
        this.zoomLevel = Math.max(0.4, Math.min(2.5, this.zoomLevel * factor));
        this._applyTransform();
    }

    resetView() {
        this.zoomLevel = 1;
        this.panX = 0;
        this.panY = 0;
        this._applyTransform();
    }

    /**
     * Dynamically calculates bounds from rendered graph elements and centers/fits them.
     */
    fitView() {
        if (!this.container || !this.svg) return;
        const rect = this.container.getBoundingClientRect();
        const width = rect.width || 900;
        const height = rect.height || 600;

        // Give DOM a microtick if just rendered
        try {
            const bbox = this.nodesLayer.getBBox();
            if (bbox && bbox.width > 0 && bbox.height > 0) {
                const padding = 50;
                const scaleX = (width - padding * 2) / bbox.width;
                const scaleY = (height - padding * 2) / bbox.height;
                this.zoomLevel = Math.min(1.2, Math.max(0.65, Math.min(scaleX, scaleY)));
                
                // Center the computed bounding box
                const centerX = bbox.x + bbox.width / 2;
                const centerY = bbox.y + bbox.height / 2;
                this.panX = (width / 2) - (centerX * this.zoomLevel);
                this.panY = (height / 2) - (centerY * this.zoomLevel);
                this._applyTransform();
                return;
            }
        } catch (e) {
            // Fallback to nominal calculation
        }

        const scaleX = (width - 40) / 920;
        const scaleY = (height - 40) / 640;
        this.zoomLevel = Math.min(1.2, Math.max(0.65, Math.min(scaleX, scaleY)));
        this.panX = 0;
        this.panY = 0;
        this._applyTransform();
    }

    _applyTransform() {
        const transformStr = `translate(${this.panX}, ${this.panY}) scale(${this.zoomLevel})`;
        this.edgesLayer.setAttribute('transform', transformStr);
        this.nodesLayer.setAttribute('transform', transformStr);
    }

    /**
     * Primary spatial rendering pipeline.
     * Evaluates the current focusNode and determines the appropriate spatial hierarchy representation.
     */
    render() {
        if (!this.graph || !this.currentFocusNodeId) return;

        const focusNode = this.graph.getNode(this.currentFocusNodeId);
        if (!focusNode) return;

        this.edgesLayer.innerHTML = '';
        this.nodesLayer.innerHTML = '';

        const rect = this.container.getBoundingClientRect();
        const width = rect.width || 900;
        const height = rect.height || 600;
        const centerX = width / 2;
        const centerY = height / 2;

        const highCardinalityCategories = ['services', 'processes', 'software'];

        // 1. Machine / Environment / Site Focus
        if (focusNode.type === 'machine' || focusNode.type === 'environment' || focusNode.type === 'site' || focusNode.type === 'network_group') {
            this.workspaceOverlay.style.display = 'none';
            this.svg.style.display = 'block';
            this._renderMachineConstellation(focusNode, centerX, centerY);
        }
        // 2. Subsystem Focus
        else if (focusNode.type === 'subsystem') {
            const isHighCard = highCardinalityCategories.includes(focusNode.category);
            
            if (isHighCard && this.viewMode === 'workspace') {
                this.svg.style.display = 'none';
                this.workspaceOverlay.style.display = 'flex';
                this._renderHighCardinalityWorkspace(focusNode);
            } else if (isHighCard && this.viewMode === 'spatial') {
                this.workspaceOverlay.style.display = 'none';
                this.svg.style.display = 'block';
                this._renderHighCardinalitySpatialHub(focusNode, centerX, centerY);
            } else {
                this.workspaceOverlay.style.display = 'none';
                this.svg.style.display = 'block';
                this._renderSubsystemDrillDownLayout(focusNode, centerX, centerY);
            }
        }
        // 3. Component Focus
        else if (focusNode.type === 'component') {
            this.workspaceOverlay.style.display = 'none';
            this.svg.style.display = 'block';
            this._renderComponentFocalLayout(focusNode, centerX, centerY);
        }
        // 4. Finding Focus
        else if (focusNode.type === 'finding') {
            this.workspaceOverlay.style.display = 'none';
            this.svg.style.display = 'block';
            this._renderFindingFocalLayout(focusNode, centerX, centerY);
        }
        // Fallback
        else {
            this.workspaceOverlay.style.display = 'none';
            this.svg.style.display = 'block';
            this._renderMachineConstellation(focusNode, centerX, centerY);
        }

        this._applyTransform();
    }

    /**
     * Machine Focal Constellation (Phase 3 Core Specification):
     * Center: Stylized technical chassis representation with snapshot identity and collection coverage.
     * Orbit: The 9 supported diagnostic domains deterministically arranged with non-crossing hierarchy lines.
     */
    _renderMachineConstellation(focusNode, centerX, centerY) {
        let machineNode = focusNode;
        if (focusNode.type !== 'machine') {
            machineNode = this.graph.getNode(this.graph.activeMachineId) || focusNode;
        }

        const subsystems = this.graph.getSubsystems(machineNode.id);

        // Deterministic orbital layout slots
        const orbitalSlots = [
            { key: 'system', x: 0, y: -220, label: 'SYSTEM', icon: '💻' },
            { key: 'compute', x: -255, y: -150, label: 'COMPUTE', icon: '⚡' },
            { key: 'memory', x: 255, y: -150, label: 'MEMORY', icon: '🧠' },
            { key: 'storage', x: -345, y: 5, label: 'STORAGE', icon: '💾' },
            { key: 'network', x: 345, y: 5, label: 'NETWORK', icon: '🌐' },
            { key: 'processes', x: -255, y: 165, label: 'PROCESSES', icon: '⚙️' },
            { key: 'services', x: 255, y: 165, label: 'SERVICES', icon: '🛡️' },
            { key: 'reliability', x: -115, y: 255, label: 'RELIABILITY', icon: '⚠️' },
            { key: 'software', x: 115, y: 255, label: 'SOFTWARE', icon: '📦' }
        ];

        // 1. Render Central Machine Node
        const centerNodeEl = this._createMachineCenterNode(machineNode, centerX, centerY);
        this.nodesLayer.appendChild(centerNodeEl);

        // 2. Render Orbital Subsystems
        orbitalSlots.forEach(slot => {
            const posX = centerX + slot.x;
            const posY = centerY + slot.y;

            const subNode = subsystems.find(s => s.category === slot.key);
            if (subNode) {
                // Draw connecting hierarchy edge
                const edgeEl = this._createEdge(centerX, centerY, posX, posY, subNode.status);
                this.edgesLayer.appendChild(edgeEl);

                // Draw subsystem card with high-value telemetry
                const nodeEl = this._createSubsystemCard(subNode, posX, posY, slot.icon);
                this.nodesLayer.appendChild(nodeEl);
            }
        });
    }

    /**
     * Subsystem Drill-Down Layout (Low/Medium Cardinality: Network, Storage, Compute, Memory, Reliability):
     * Top: Receded Machine link & Subsystem Anchor Hub.
     * Bottom: Connected Child Component Cards.
     */
    _renderSubsystemDrillDownLayout(subNode, centerX, centerY) {
        const components = this.graph.getChildren(subNode.id);
        const machineNode = this.graph.getNode(this.graph.activeMachineId);

        // 1. Receded Machine Parent Context Anchor
        if (machineNode) {
            const machineLinkEl = this._createRecededParentAnchor(machineNode, 'MACHINE', centerX, centerY - 210);
            this.nodesLayer.appendChild(machineLinkEl);

            // Connector from Machine to Subsystem Hub
            const connEdge = this._createEdge(centerX, centerY - 195, centerX, centerY - 150, subNode.status);
            this.edgesLayer.appendChild(connEdge);
        }

        // 2. Focused Subsystem Hub
        const topBannerY = centerY - 120;
        const bannerEl = this._createSubsystemTopBanner(subNode, centerX, topBannerY);
        this.nodesLayer.appendChild(bannerEl);

        if (components.length === 0) {
            const emptyEl = this._createNoticeNode(
                subNode.collectionState === 'collected' || subNode.collectionState === 'success'
                    ? 'No child components reported in canonical source data.'
                    : `Domain Status: ${this._formatCollectionStateBadge(subNode.collectionState)}`,
                centerX,
                centerY + 40
            );
            this.nodesLayer.appendChild(emptyEl);
            return;
        }

        // 3. Layout Component Cards Spatially
        const count = components.length;
        const maxCols = Math.min(4, Math.max(2, Math.ceil(Math.sqrt(count))));
        const colWidth = 230;
        const rowHeight = 110;
        const totalGridWidth = (Math.min(count, maxCols) - 1) * colWidth;
        const startX = centerX - totalGridWidth / 2;
        const startY = centerY + 10;

        components.forEach((comp, idx) => {
            const row = Math.floor(idx / maxCols);
            const col = idx % maxCols;
            const cx = startX + col * colWidth;
            const cy = startY + row * rowHeight;

            // Draw Edge from Subsystem Anchor to Component
            const edgeEl = this._createEdge(centerX, topBannerY + 40, cx, cy, comp.status);
            this.edgesLayer.appendChild(edgeEl);

            // Draw Component Card
            const compEl = this._createComponentCard(comp, cx, cy, comp.id === this.selectedNodeId);
            this.nodesLayer.appendChild(compEl);
        });
    }

    /**
     * High-Cardinality Spatial Hub (Services, Processes, Software):
     * Renders a spatial focus card with domain stats and an immediate action button to open the workspace.
     */
    _renderHighCardinalitySpatialHub(subNode, centerX, centerY) {
        const components = this.graph.getChildren(subNode.id);
        const machineNode = this.graph.getNode(this.graph.activeMachineId);

        // 1. Receded Machine Parent Context Anchor
        if (machineNode) {
            const machineLinkEl = this._createRecededParentAnchor(machineNode, 'MACHINE', centerX, centerY - 210);
            this.nodesLayer.appendChild(machineLinkEl);

            const connEdge = this._createEdge(centerX, centerY - 195, centerX, centerY - 140, subNode.status);
            this.edgesLayer.appendChild(connEdge);
        }

        // 2. High Cardinality Spatial Focal Node
        const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        g.setAttribute('class', `topo-node spatial-hub-node status-${subNode.status} selected`);
        g.setAttribute('transform', `translate(${centerX}, ${centerY - 40})`);
        g.dataset.nodeId = subNode.id;

        const w = 420;
        const h = 200;
        const telemetry = this._getSubsystemTelemetryLines(subNode);
        const findingCount = subNode.findings ? subNode.findings.length : 0;

        g.innerHTML = `
            <rect class="hub-box-bg" x="${-w/2}" y="${-h/2}" width="${w}" height="${h}" rx="8" />
            <rect class="hub-box-border" x="${-w/2}" y="${-h/2}" width="${w}" height="${h}" rx="8" />
            
            <text class="hub-icon" x="0" y="${-h/2 + 34}" text-anchor="middle">${this._getDomainIcon(subNode.category)}</text>
            <text class="hub-title" x="0" y="${-h/2 + 62}" text-anchor="middle">${this._escape(subNode.label).toUpperCase()} DOMAIN</text>
            <text class="hub-sub" x="0" y="${-h/2 + 84}" text-anchor="middle">${components.length} canonical components indexed • ${this._escape(telemetry.line1)}</text>
            <text class="hub-meta" x="0" y="${-h/2 + 104}" text-anchor="middle">${this._escape(telemetry.line2)}</text>
            
            ${findingCount > 0 ? `
                <g transform="translate(0, ${-h/2 + 130})">
                    <rect class="finding-badge-bg sev-${subNode.status}" x="-90" y="-10" width="180" height="20" rx="4" />
                    <text class="finding-badge-text" x="0" y="4" text-anchor="middle">⚠️ ${findingCount} Finding Overlay Detected</text>
                </g>
            ` : `
                <g transform="translate(0, ${-h/2 + 130})">
                    <rect class="uncol-badge-bg uncol-success" x="-80" y="-10" width="160" height="20" rx="4" />
                    <text class="uncol-badge-text uncol-success" x="0" y="4" text-anchor="middle">PROVENANCE: SUCCESS</text>
                </g>
            `}

            <!-- Interactive Workspace Trigger Action -->
            <g class="hub-action-btn" transform="translate(0, ${h/2 - 25})">
                <rect class="hub-btn-bg" x="-130" y="-14" width="260" height="28" rx="4" />
                <text class="hub-btn-text" x="0" y="4" text-anchor="middle">⚡ OPEN COMPONENT WORKSPACE (${components.length})</text>
            </g>
        `;

        g.querySelector('.hub-action-btn').addEventListener('click', (e) => {
            e.stopPropagation();
            this.viewMode = 'workspace';
            this.render();
        });

        g.addEventListener('click', (e) => {
            e.stopPropagation();
            this.selectedNodeId = subNode.id;
            this.selectNode(subNode.id);
            if (this.onSelectNode) this.onSelectNode(subNode.id);
        });

        this.nodesLayer.appendChild(g);
    }

    /**
     * Component Focal Layout (Phase 3 Component Drill-Down):
     * When any component (e.g. Wi-Fi, PhysicalDrive0, C:\, TrustedInstaller) becomes the focal object.
     * Shows full ancestral context (Machine → Subsystem → Component), prominent focal card, and sibling navigation.
     */
    _renderComponentFocalLayout(compNode, centerX, centerY) {
        const parentSub = this.graph.getParent(compNode.id);
        const machineNode = this.graph.getNode(this.graph.activeMachineId);

        // 1. Ancestral Context Chain
        if (machineNode) {
            const machineAnchor = this._createRecededParentAnchor(machineNode, 'MACHINE', centerX - 140, centerY - 210);
            this.nodesLayer.appendChild(machineAnchor);
        }

        if (parentSub) {
            const subAnchor = this._createRecededParentAnchor(parentSub, 'SUBSYSTEM', centerX + 140, centerY - 210);
            this.nodesLayer.appendChild(subAnchor);

            // Connectors to focal card
            const connEdge = this._createEdge(centerX + 140, centerY - 195, centerX, centerY - 110, compNode.status);
            this.edgesLayer.appendChild(connEdge);
        }

        // 2. Component Focal Card
        const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        g.setAttribute('class', `topo-node component-focal-node status-${compNode.status} selected`);
        g.setAttribute('transform', `translate(${centerX}, ${centerY - 10})`);
        g.dataset.nodeId = compNode.id;

        const w = 480;
        const h = 210;
        const m = compNode.metrics || {};
        const findingCount = compNode.findings ? compNode.findings.length : 0;

        let focalMetricsHtml = '';
        if (m.speed_mbps !== undefined) {
            focalMetricsHtml = `Link Speed: ${m.speed_mbps} Mbps • Interface: ${m.if_type || 'Ethernet'} • Status: ${m.status || 'Up'}`;
        } else if (m.used_percent !== undefined) {
            focalMetricsHtml = `Capacity: ${m.used_percent}% Used of ${(m.total_bytes / (1024*1024*1024)).toFixed(1)} GB (${m.filesystem || 'NTFS'})`;
        } else if (m.size_bytes !== undefined) {
            focalMetricsHtml = `Disk Size: ${(m.size_bytes / (1024*1024*1024)).toFixed(1)} GB • ${m.media_type || 'Disk'} (${m.bus_type || 'NVMe'})`;
        } else if (m.display_name) {
            focalMetricsHtml = `Display: "${this._escape(this._truncate(m.display_name, 35))}" • Start Type: ${m.start_type || 'Auto'}`;
        } else {
            focalMetricsHtml = compNode.subtitle || 'Measured Component';
        }

        g.innerHTML = `
            <rect class="focal-card-bg" x="${-w/2}" y="${-h/2}" width="${w}" height="${h}" rx="8" />
            <rect class="focal-card-border" x="${-w/2}" y="${-h/2}" width="${w}" height="${h}" rx="8" />
            
            <!-- Type & Category Tag -->
            <g transform="translate(${-w/2 + 20}, ${-h/2 + 26})">
                <rect class="type-tag-bg" x="0" y="-12" width="90" height="18" rx="3" />
                <text class="type-tag-text" x="45" y="1" text-anchor="middle">${compNode.type.toUpperCase()}</text>
            </g>

            <!-- State Badge -->
            <g transform="translate(${w/2 - 60}, ${-h/2 + 26})">
                <rect class="focal-state-bg status-${compNode.status}" x="-40" y="-12" width="80" height="18" rx="3" />
                <text class="focal-state-text status-${compNode.status}" x="0" y="1" text-anchor="middle">${this._escape(m.status || compNode.status).toUpperCase()}</text>
            </g>

            <!-- Focal Title & Subtitle -->
            <text class="focal-title" x="0" y="${-h/2 + 65}" text-anchor="middle">${this._escape(this._truncate(compNode.label, 32))}</text>
            <text class="focal-sub" x="0" y="${-h/2 + 88}" text-anchor="middle">${this._escape(this._truncate(compNode.subtitle || '', 45))}</text>
            
            <!-- Focal Metrics Box -->
            <g transform="translate(0, ${-h/2 + 120})">
                <rect class="focal-metric-bg" x="${-w/2 + 20}" y="-16" width="${w - 40}" height="32" rx="4" />
                <text class="focal-metric-text" x="0" y="4" text-anchor="middle">${this._escape(focalMetricsHtml)}</text>
            </g>

            <!-- Finding Overlay Banner or Healthy Status -->
            ${findingCount > 0 ? `
                <g class="focal-finding-banner" transform="translate(0, ${h/2 - 25})">
                    <rect class="finding-badge-bg sev-${compNode.status}" x="-140" y="-12" width="280" height="24" rx="4" />
                    <text class="finding-badge-text" x="0" y="4" text-anchor="middle">⚠️ ${findingCount} Finding Overlay — Inspect Evidence</text>
                </g>
            ` : `
                <g transform="translate(0, ${h/2 - 25})">
                    <rect class="uncol-badge-bg uncol-success" x="-100" y="-12" width="200" height="24" rx="4" />
                    <text class="uncol-badge-text uncol-success" x="0" y="4" text-anchor="middle">DIAGNOSTIC STATE: NO FINDING</text>
                </g>
            `}
        `;

        g.addEventListener('click', (e) => {
            e.stopPropagation();
            this.selectedNodeId = compNode.id;
            this.selectNode(compNode.id);
            if (this.onSelectNode) this.onSelectNode(compNode.id);
        });

        this.nodesLayer.appendChild(g);

        // 3. Sibling Navigation Strip (if siblings exist)
        if (parentSub) {
            const siblings = this.graph.getChildren(parentSub.id);
            if (siblings.length > 1) {
                const stripY = centerY + 145;
                const stripEl = this._createSiblingNavStrip(siblings, compNode.id, centerX, stripY);
                this.nodesLayer.appendChild(stripEl);
            }
        }
    }

    /**
     * Finding Focal Layout (Exposes direct evidence linking).
     */
    _renderFindingFocalLayout(findingNode, centerX, centerY) {
        const parentComp = this.graph.getParent(findingNode.id);
        const machineNode = this.graph.getNode(this.graph.activeMachineId);

        if (machineNode) {
            const machineAnchor = this._createRecededParentAnchor(machineNode, 'MACHINE', centerX - 140, centerY - 210);
            this.nodesLayer.appendChild(machineAnchor);
        }

        if (parentComp) {
            const compAnchor = this._createRecededParentAnchor(parentComp, 'COMPONENT', centerX + 140, centerY - 210);
            this.nodesLayer.appendChild(compAnchor);

            const connEdge = this._createEdge(centerX + 140, centerY - 195, centerX, centerY - 110, findingNode.status);
            this.edgesLayer.appendChild(connEdge);
        }

        const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        g.setAttribute('class', `topo-node finding-focal-node status-${findingNode.status} selected`);
        g.setAttribute('transform', `translate(${centerX}, ${centerY})`);
        g.dataset.nodeId = findingNode.id;

        const w = 460;
        const h = 180;
        const f = findingNode.sourceData || {};

        g.innerHTML = `
            <rect class="focal-card-bg" x="${-w/2}" y="${-h/2}" width="${w}" height="${h}" rx="8" />
            <rect class="focal-card-border" x="${-w/2}" y="${-h/2}" width="${w}" height="${h}" rx="8" />
            
            <g transform="translate(0, ${-h/2 + 24})">
                <rect class="finding-badge-bg sev-${findingNode.status}" x="-70" y="-10" width="140" height="20" rx="4" />
                <text class="finding-badge-text" x="0" y="4" text-anchor="middle">${(f.severity || 'INFO').toUpperCase()} FINDING</text>
            </g>

            <text class="focal-title" x="0" y="${-h/2 + 65}" text-anchor="middle">${this._escape(f.id || findingNode.label)}</text>
            <text class="focal-sub" x="0" y="${-h/2 + 88}" text-anchor="middle">${this._escape(f.title || '')}</text>
            <text class="focal-metric-text" x="0" y="${-h/2 + 115}" text-anchor="middle">Observation: "${this._escape(this._truncate(f.observation || '', 55))}"</text>

            <g class="focal-action-btn" transform="translate(0, ${h/2 - 25})">
                <rect class="hub-btn-bg" x="-120" y="-12" width="240" height="24" rx="4" />
                <text class="hub-btn-text" x="0" y="4" text-anchor="middle">🔍 VIEW 5-STEP EVIDENCE CHAIN</text>
            </g>
        `;

        g.addEventListener('click', (e) => {
            e.stopPropagation();
            this.selectedNodeId = findingNode.id;
            this.selectNode(findingNode.id);
            if (this.onSelectNode) this.onSelectNode(findingNode.id);
        });

        this.nodesLayer.appendChild(g);
    }

    /**
     * Sibling Navigation Rail:
     * Renders compact interactive chips to switch between sibling components quickly.
     */
    _createSiblingNavStrip(siblings, activeId, cx, cy) {
        const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        g.setAttribute('class', 'sibling-nav-rail');
        g.setAttribute('transform', `translate(${cx}, ${cy})`);

        const maxDisplay = Math.min(siblings.length, 6);
        const chipWidth = 110;
        const totalW = (maxDisplay - 1) * (chipWidth + 10);
        const startX = -totalW / 2;

        siblings.slice(0, maxDisplay).forEach((sib, idx) => {
            const chipX = startX + idx * (chipWidth + 10);
            const isCurrent = sib.id === activeId;

            const chipG = document.createElementNS('http://www.w3.org/2000/svg', 'g');
            chipG.setAttribute('class', `sibling-chip ${isCurrent ? 'active' : ''}`);
            chipG.setAttribute('transform', `translate(${chipX}, 0)`);

            chipG.innerHTML = `
                <rect class="chip-bg" x="${-chipWidth/2}" y="-14" width="${chipWidth}" height="28" rx="4" />
                <text class="chip-text" x="0" y="4" text-anchor="middle">${this._escape(this._truncate(sib.label, 12))}</text>
            `;

            chipG.addEventListener('click', (e) => {
                e.stopPropagation();
                if (this.onDrillDown) this.onDrillDown(sib.id);
            });

            g.appendChild(chipG);
        });

        return g;
    }

    /**
     * High-Cardinality Workspace View (Services, Processes, Software):
     * Mounts an interactive, searchable, sortable component table.
     */
    _renderHighCardinalityWorkspace(subNode, activeComponentId = null) {
        const components = this.graph.getChildren(subNode.id);
        const machineNode = this.graph.getNode(this.graph.activeMachineId);

        let filterPills = '';
        if (subNode.category === 'services') {
            const total = subNode.metrics?.total_count || components.length;
            const running = subNode.metrics?.running_count || 0;
            const stopped = subNode.metrics?.stopped_count || 0;
            const failed = subNode.metrics?.failed_auto_start_count || 0;
            const findingsCount = subNode.findings?.length || 0;

            filterPills = `
                <button class="ws-filter-btn ${this.workspaceFilter === 'all' ? 'active' : ''}" data-filter="all">All (${total})</button>
                <button class="ws-filter-btn ${this.workspaceFilter === 'running' ? 'active' : ''}" data-filter="running">Running (${running})</button>
                <button class="ws-filter-btn ${this.workspaceFilter === 'stopped' ? 'active' : ''}" data-filter="stopped">Stopped (${stopped})</button>
                ${failed > 0 ? `<button class="ws-filter-btn ${this.workspaceFilter === 'failed' ? 'active' : ''}" data-filter="failed">Failed Auto-Start (${failed})</button>` : ''}
                ${findingsCount > 0 ? `<button class="ws-filter-btn ${this.workspaceFilter === 'findings' ? 'active' : ''}" data-filter="findings">Findings (${findingsCount})</button>` : ''}
            `;
        } else if (subNode.category === 'processes') {
            const total = subNode.metrics?.total_processes || components.length;
            filterPills = `
                <button class="ws-filter-btn ${this.workspaceFilter === 'all' ? 'active' : ''}" data-filter="all">All Processes (${total})</button>
                <button class="ws-filter-btn ${this.workspaceFilter === 'top_cpu' ? 'active' : ''}" data-filter="top_cpu">Top CPU</button>
                <button class="ws-filter-btn ${this.workspaceFilter === 'top_mem' ? 'active' : ''}" data-filter="top_mem">Top Memory</button>
            `;
        } else if (subNode.category === 'software') {
            const total = subNode.metrics?.total_installed_apps || components.length;
            const runtimes = subNode.metrics?.runtimes_count || 0;
            const hotfixes = subNode.metrics?.hotfixes_count || 0;
            filterPills = `
                <button class="ws-filter-btn ${this.workspaceFilter === 'all' ? 'active' : ''}" data-filter="all">All Software (${total})</button>
                <button class="ws-filter-btn ${this.workspaceFilter === 'runtimes' ? 'active' : ''}" data-filter="runtimes">Runtimes (${runtimes})</button>
                ${hotfixes > 0 ? `<button class="ws-filter-btn ${this.workspaceFilter === 'hotfixes' ? 'active' : ''}" data-filter="hotfixes">Hotfixes (${hotfixes})</button>` : ''}
            `;
        }

        // Filter and sort items
        const filtered = this._filterWorkspaceComponents(components, subNode.category);

        this.workspaceOverlay.innerHTML = `
            <div class="workspace-panel">
                <div class="workspace-header">
                    <div class="ws-header-left">
                        <button class="ws-back-machine-btn" id="ws-btn-back-machine">
                            ⬅ RETURN TO MACHINE COMMAND VIEW
                        </button>
                        <button class="ws-view-toggle-btn" id="ws-btn-spatial-view">
                            ◈ SPATIAL DOMAIN OVERVIEW
                        </button>
                        <div class="ws-domain-title">
                            <span class="ws-domain-icon">${this._getDomainIcon(subNode.category)}</span>
                            <span class="ws-domain-name">${this._escape(subNode.label).toUpperCase()} WORKSPACE</span>
                            <span class="ws-domain-count">(${components.length} components indexed)</span>
                        </div>
                    </div>
                    <div class="ws-header-right">
                        ${subNode.findings && subNode.findings.length > 0 ? `<span class="ws-finding-alert">⚠️ ${subNode.findings.length} Finding Overlay</span>` : ''}
                        ${(subNode.collectionState && subNode.collectionState !== 'collected' && subNode.collectionState !== 'success') ? `
                            <span class="ws-col-badge col-${subNode.collectionState}">${this._formatCollectionStateBadge(subNode.collectionState)}</span>
                        ` : ''}
                    </div>
                </div>

                <div class="workspace-controls-bar">
                    <div class="ws-filter-group">${filterPills}</div>
                    <div class="ws-search-box">
                        <input type="text" id="ws-search-input" placeholder="Filter ${this._escape(subNode.label).toLowerCase()}..." value="${this._escape(this.workspaceQuery)}" />
                    </div>
                </div>

                <div class="workspace-table-container">
                    <table class="workspace-table">
                        <thead>
                            <tr>
                                <th data-sort="name">NAME / ID</th>
                                <th data-sort="status">STATE</th>
                                <th data-sort="metric">ATTRIBUTES / MEASUREMENTS</th>
                                <th>FINDING OVERLAY</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${filtered.length > 0 ? filtered.map(comp => `
                                <tr class="ws-table-row ${comp.id === (activeComponentId || this.selectedNodeId) ? 'selected-row' : ''}" data-node-id="${comp.id}">
                                    <td>
                                        <div class="ws-cell-name">
                                            <span class="ws-cell-title">${this._escape(comp.label)}</span>
                                            <span class="ws-cell-sub">${this._escape(comp.subtitle || '')}</span>
                                        </div>
                                    </td>
                                    <td>
                                        <span class="status-pill status-${comp.status}">${this._escape(comp.metrics?.status || comp.status).toUpperCase()}</span>
                                    </td>
                                    <td>
                                        <div class="ws-cell-metrics">${this._formatComponentMetricsSnippet(comp)}</div>
                                    </td>
                                    <td>
                                        ${comp.findings && comp.findings.length > 0 ? `
                                            <span class="finding-dot-pill sev-${comp.findings[0].severity ? comp.findings[0].severity.toLowerCase() : 'info'}">
                                                ● ${this._escape(comp.findings[0].id || 'Finding')}
                                            </span>
                                        ` : '<span class="text-muted">—</span>'}
                                    </td>
                                </tr>
                            `).join('') : `
                                <tr>
                                    <td colspan="4" class="ws-empty-cell">No components match current filter query.</td>
                                </tr>
                            `}
                        </tbody>
                    </table>
                </div>
            </div>
        `;

        // Bind Workspace actions
        const backBtn = this.workspaceOverlay.querySelector('#ws-btn-back-machine');
        if (backBtn && machineNode) {
            backBtn.addEventListener('click', () => {
                if (this.onDrillDown) this.onDrillDown(machineNode.id);
            });
        }

        const spatialViewBtn = this.workspaceOverlay.querySelector('#ws-btn-spatial-view');
        if (spatialViewBtn) {
            spatialViewBtn.addEventListener('click', () => {
                this.viewMode = 'spatial';
                this.render();
            });
        }

        this.workspaceOverlay.querySelectorAll('.ws-filter-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.workspaceFilter = e.currentTarget.dataset.filter;
                this._renderHighCardinalityWorkspace(subNode, activeComponentId);
            });
        });

        const wsSearchInput = this.workspaceOverlay.querySelector('#ws-search-input');
        if (wsSearchInput) {
            wsSearchInput.addEventListener('input', (e) => {
                this.workspaceQuery = e.target.value.toLowerCase().trim();
                this._renderHighCardinalityWorkspace(subNode, activeComponentId);
                // Keep input focus
                const newInput = this.workspaceOverlay.querySelector('#ws-search-input');
                if (newInput) {
                    newInput.focus();
                    newInput.setSelectionRange(newInput.value.length, newInput.value.length);
                }
            });
        }

        this.workspaceOverlay.querySelectorAll('.ws-table-row').forEach(row => {
            row.addEventListener('click', (e) => {
                const nodeId = e.currentTarget.dataset.nodeId;
                if (!nodeId) return;
                this.selectedNodeId = nodeId;
                this.selectNode(nodeId);
                if (this.onSelectNode) this.onSelectNode(nodeId);
            });
        });
    }

    _filterWorkspaceComponents(components, category) {
        let result = components;

        // Apply tab filter
        if (this.workspaceFilter === 'running') {
            result = result.filter(c => (c.metrics?.status || '').toLowerCase() === 'running');
        } else if (this.workspaceFilter === 'stopped') {
            result = result.filter(c => (c.metrics?.status || '').toLowerCase() === 'stopped');
        } else if (this.workspaceFilter === 'failed') {
            result = result.filter(c => c.id.includes('failed') || (c.metrics?.exit_code && c.metrics.exit_code !== 0));
        } else if (this.workspaceFilter === 'findings') {
            result = result.filter(c => c.findings && c.findings.length > 0);
        } else if (this.workspaceFilter === 'top_cpu') {
            result = result.filter(c => c.id.includes('cpu'));
        } else if (this.workspaceFilter === 'top_mem') {
            result = result.filter(c => c.id.includes('mem'));
        } else if (this.workspaceFilter === 'runtimes') {
            result = result.filter(c => c.id.includes('runtime'));
        } else if (this.workspaceFilter === 'hotfixes') {
            result = result.filter(c => c.id.includes('hotfix'));
        }

        // Apply text query
        if (this.workspaceQuery) {
            const q = this.workspaceQuery;
            result = result.filter(c => 
                c.label.toLowerCase().includes(q) ||
                (c.subtitle && c.subtitle.toLowerCase().includes(q)) ||
                (c.metrics?.name && c.metrics.name.toLowerCase().includes(q)) ||
                (c.metrics?.display_name && c.metrics.display_name.toLowerCase().includes(q)) ||
                (c.findings && c.findings.some(f => f.title.toLowerCase().includes(q) || f.id.toLowerCase().includes(q)))
            );
        }

        return result;
    }

    _formatComponentMetricsSnippet(comp) {
        const m = comp.metrics || {};
        if (m.speed_mbps) return `<span class="metric-highlight">${m.speed_mbps} Mbps</span> • ${m.if_type || 'Ethernet'}`;
        if (m.used_percent !== undefined && m.total_bytes) {
            return `<span class="metric-highlight">${m.used_percent}% used</span> of ${(m.total_bytes / (1024*1024*1024)).toFixed(1)} GB (${m.filesystem || 'NTFS'})`;
        }
        if (m.size_bytes) return `${(m.size_bytes / (1024*1024*1024)).toFixed(1)} GB • ${m.media_type || 'Disk'} (${m.bus_type || 'NVMe'})`;
        if (m.binary_path) return `<code>${this._escape(this._truncate(m.binary_path, 40))}</code>`;
        if (m.working_set_bytes) return `${(m.working_set_bytes / (1024*1024)).toFixed(1)} MB RAM • ${m.thread_count || 0} threads`;
        if (m.version) return `Version: <code>${this._escape(m.version)}</code>`;
        if (m.exception_code) return `Exception: <code>${this._escape(m.exception_code)}</code>`;
        return comp.subtitle || '—';
    }

    _createEdge(x1, y1, x2, y2, status) {
        const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        line.setAttribute('x1', x1);
        line.setAttribute('y1', y1);
        line.setAttribute('x2', x2);
        line.setAttribute('y2', y2);
        line.setAttribute('class', `topo-edge edge-status-${status || 'normal'}`);
        return line;
    }

    _createMachineCenterNode(node, cx, cy) {
        const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        g.setAttribute('class', `topo-node machine-center-node ${node.id === this.selectedNodeId ? 'selected' : ''}`);
        g.setAttribute('transform', `translate(${cx}, ${cy})`);
        g.dataset.nodeId = node.id;

        const w = 260;
        const h = 160;

        const meta = node.metadata || {};
        const col = meta.collection_status || {};
        const timestampStr = meta.scan_timestamp ? this._formatSnapshotTimestamp(meta.scan_timestamp) : '2026-09-17 11:15';
        const osArch = `${(meta.os_version || meta.os || 'Windows').toUpperCase()} • ${(meta.architecture || 'amd64').toLowerCase()}`;

        g.innerHTML = `
            <rect class="machine-box-bg" x="${-w/2}" y="${-h/2}" width="${w}" height="${h}" rx="8" />
            <rect class="machine-box-border" x="${-w/2}" y="${-h/2}" width="${w}" height="${h}" rx="8" />
            
            <!-- Technical Framing Brackets -->
            <path class="tech-bracket" d="M ${-w/2 + 8} ${-h/2 + 18} L ${-w/2 + 8} ${-h/2 + 8} L ${-w/2 + 18} ${-h/2 + 8}" />
            <path class="tech-bracket" d="M ${w/2 - 8} ${-h/2 + 18} L ${w/2 - 8} ${-h/2 + 8} L ${w/2 - 18} ${-h/2 + 8}" />
            <path class="tech-bracket" d="M ${-w/2 + 8} ${h/2 - 18} L ${-w/2 + 8} ${h/2 - 8} L ${-w/2 + 18} ${h/2 - 8}" />
            <path class="tech-bracket" d="M ${w/2 - 8} ${h/2 - 18} L ${w/2 - 8} ${h/2 - 8} L ${w/2 - 18} ${h/2 - 8}" />
            
            <!-- Snapshot Identity Header -->
            <g transform="translate(0, ${-h/2 + 20})">
                <rect class="snapshot-badge-bg" x="-95" y="-10" width="190" height="18" rx="3" />
                <text class="snapshot-badge-text" x="0" y="3" text-anchor="middle">SNAPSHOT • Captured ${this._escape(timestampStr)}</text>
            </g>
            
            <!-- Machine Identity Core -->
            <text class="machine-title" x="0" y="${-h/2 + 62}" text-anchor="middle">${this._escape(node.label).toUpperCase()}</text>
            <text class="machine-sub" x="0" y="${-h/2 + 82}" text-anchor="middle">${this._escape(osArch)}</text>
            <text class="machine-scan-meta" x="0" y="${-h/2 + 102}" text-anchor="middle">SCAN: ${meta.scan_duration_ms || 0} ms • ${(meta.profile || 'quick').toUpperCase()} PROFILE</text>
            
            <!-- Collection Coverage Badge -->
            <g transform="translate(0, ${-h/2 + 130})">
                <rect class="badge-bg" x="-85" y="-11" width="170" height="22" rx="4" />
                <text class="badge-text" x="0" y="4" text-anchor="middle">COLLECTION: ${col.successful || node.metrics?.successful_probes || 0}/${col.total_probes || node.metrics?.total_probes || 0} PROBES</text>
            </g>
        `;

        g.addEventListener('click', (e) => {
            e.stopPropagation();
            this.selectedNodeId = node.id;
            this.selectNode(node.id);
            if (this.onSelectNode) this.onSelectNode(node.id);
        });

        return g;
    }

    _createSubsystemCard(node, cx, cy, icon) {
        const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        g.setAttribute('class', `topo-node subsystem-node status-${node.status} ${node.id === this.selectedNodeId ? 'selected' : ''}`);
        g.setAttribute('transform', `translate(${cx}, ${cy})`);
        g.dataset.nodeId = node.id;

        const w = 200;
        const h = 90;

        const findingCount = node.findings ? node.findings.length : 0;
        const telemetry = this._getSubsystemTelemetryLines(node);

        g.innerHTML = `
            <rect class="subsystem-box-bg" x="${-w/2}" y="${-h/2}" width="${w}" height="${h}" rx="6" />
            <rect class="subsystem-box-border" x="${-w/2}" y="${-h/2}" width="${w}" height="${h}" rx="6" />
            
            <!-- Header: Icon & Category Label -->
            <text class="subsystem-icon" x="${-w/2 + 16}" y="${-h/2 + 24}">${icon}</text>
            <text class="subsystem-title" x="${-w/2 + 38}" y="${-h/2 + 24}">${this._escape(node.label).toUpperCase()}</text>
            
            <!-- At-a-glance Subsystem Telemetry -->
            <text class="subsystem-telemetry-line1" x="${-w/2 + 16}" y="${-h/2 + 48}">${this._escape(telemetry.line1)}</text>
            <text class="subsystem-telemetry-line2" x="${-w/2 + 16}" y="${-h/2 + 66}">${this._escape(telemetry.line2)}</text>
            
            <!-- Restrained Finding Indicator -->
            ${findingCount > 0 ? `
                <g transform="translate(${w/2 - 40}, ${-h/2 + 20})">
                    <rect class="finding-badge-bg sev-${node.status}" x="-25" y="-8" width="50" height="16" rx="3" />
                    <text class="finding-badge-text" x="0" y="3" text-anchor="middle">● ${findingCount} ${node.status.toUpperCase()}</text>
                </g>
            ` : ''}

            <!-- Collection Provenance Badge -->
            ${(node.collectionState && node.collectionState !== 'collected' && node.collectionState !== 'success') ? `
                <g transform="translate(0, ${h/2 - 6})">
                    <rect class="uncol-badge-bg uncol-${node.collectionState}" x="-55" y="-8" width="110" height="15" rx="3" />
                    <text class="uncol-badge-text uncol-${node.collectionState}" x="0" y="3" text-anchor="middle">${this._formatCollectionStateBadge(node.collectionState)}</text>
                </g>
            ` : ''}
        `;

        g.addEventListener('click', (e) => {
            e.stopPropagation();
            this.selectedNodeId = node.id;
            this.selectNode(node.id);
            if (this.onSelectNode) this.onSelectNode(node.id);
            if (this.onDrillDown) this.onDrillDown(node.id);
        });

        return g;
    }

    _createRecededParentAnchor(node, roleLabel, cx, cy) {
        const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        g.setAttribute('class', 'topo-node receded-parent-anchor');
        g.setAttribute('transform', `translate(${cx}, ${cy})`);
        g.dataset.nodeId = node.id;

        const w = 240;
        const h = 32;

        g.innerHTML = `
            <rect class="receded-box-bg" x="${-w/2}" y="${-h/2}" width="${w}" height="${h}" rx="4" />
            <rect class="receded-box-border" x="${-w/2}" y="${-h/2}" width="${w}" height="${h}" rx="4" />
            <text class="receded-text" x="0" y="4" text-anchor="middle">⬅ ${roleLabel}: ${this._escape(this._truncate(node.label, 18)).toUpperCase()}</text>
        `;

        g.addEventListener('click', (e) => {
            e.stopPropagation();
            if (this.onDrillDown) this.onDrillDown(node.id);
        });

        return g;
    }

    _createSubsystemTopBanner(node, cx, cy) {
        const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        g.setAttribute('class', `topo-node subsystem-top-banner status-${node.status} ${node.id === this.selectedNodeId ? 'selected' : ''}`);
        g.setAttribute('transform', `translate(${cx}, ${cy})`);
        g.dataset.nodeId = node.id;

        const w = 380;
        const h = 80;
        const telemetry = this._getSubsystemTelemetryLines(node);

        g.innerHTML = `
            <rect class="banner-bg" x="${-w/2}" y="${-h/2}" width="${w}" height="${h}" rx="8" />
            <rect class="banner-border" x="${-w/2}" y="${-h/2}" width="${w}" height="${h}" rx="8" />
            
            <text class="banner-title" x="0" y="${-h/2 + 26}" text-anchor="middle">${this._getDomainIcon(node.category)} ${this._escape(node.label).toUpperCase()} SUBSYSTEM</text>
            <text class="banner-sub" x="0" y="${-h/2 + 48}" text-anchor="middle">${this._escape(telemetry.line1)} • ${this._escape(telemetry.line2)}</text>
            
            ${node.findings && node.findings.length > 0 ? `
                <text class="banner-findings" x="0" y="${-h/2 + 68}" text-anchor="middle">⚠️ ${node.findings.length} Associated Finding(s) Detected</text>
            ` : `
                <text class="banner-provenance" x="0" y="${-h/2 + 68}" text-anchor="middle">PROVENANCE: ${this._formatCollectionStateBadge(node.collectionState || 'Success')}</text>
            `}
        `;

        g.addEventListener('click', (e) => {
            e.stopPropagation();
            this.selectedNodeId = node.id;
            this.selectNode(node.id);
            if (this.onSelectNode) this.onSelectNode(node.id);
        });

        return g;
    }

    _createComponentCard(node, cx, cy, isSelected) {
        const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        g.setAttribute('class', `topo-node component-node status-${node.status} ${isSelected ? 'selected' : ''}`);
        g.setAttribute('transform', `translate(${cx}, ${cy})`);
        g.dataset.nodeId = node.id;

        const w = 210;
        const h = 80;

        let extraBadge = '';
        if (node.metrics?.speed_mbps) {
            extraBadge = `${node.metrics.speed_mbps} Mbps`;
        } else if (node.metrics?.used_percent !== undefined) {
            extraBadge = `${node.metrics.used_percent}% Used`;
        } else if (node.metrics?.utilization_percent !== undefined) {
            extraBadge = `${node.metrics.utilization_percent}% Util`;
        } else if (node.metrics?.status) {
            extraBadge = `${node.metrics.status}`;
        }

        const findingCount = node.findings ? node.findings.length : 0;

        g.innerHTML = `
            <rect class="comp-box-bg" x="${-w/2}" y="${-h/2}" width="${w}" height="${h}" rx="6" />
            <rect class="comp-box-border" x="${-w/2}" y="${-h/2}" width="${w}" height="${h}" rx="6" />
            
            <text class="comp-title" x="${-w/2 + 12}" y="${-h/2 + 22}">${this._escape(this._truncate(node.label, 20))}</text>
            <text class="comp-sub" x="${-w/2 + 12}" y="${-h/2 + 42}">${this._escape(this._truncate(node.subtitle || '', 24))}</text>
            
            ${extraBadge ? `
                <g transform="translate(${-w/2 + 12}, ${-h/2 + 52})">
                    <rect class="comp-metric-badge-bg" x="0" y="0" width="85" height="16" rx="3" />
                    <text class="comp-metric-badge-text" x="42" y="12" text-anchor="middle">${this._escape(extraBadge)}</text>
                </g>
            ` : ''}

            ${findingCount > 0 ? `
                <g transform="translate(${w/2 - 20}, ${-h/2 + 20})">
                    <circle class="finding-badge-bg sev-${node.status}" r="9" />
                    <text class="finding-badge-text" y="3" text-anchor="middle">${findingCount}</text>
                </g>
            ` : ''}
        `;

        g.addEventListener('click', (e) => {
            e.stopPropagation();
            this.selectedNodeId = node.id;
            this.selectNode(node.id);
            if (this.onSelectNode) this.onSelectNode(node.id);
            if (this.onDrillDown) this.onDrillDown(node.id);
        });

        return g;
    }

    _createNoticeNode(text, cx, cy) {
        const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        g.setAttribute('class', 'topo-node notice-node');
        g.setAttribute('transform', `translate(${cx}, ${cy})`);
        g.innerHTML = `
            <rect class="notice-box-bg" x="-180" y="-20" width="360" height="40" rx="6" />
            <text class="notice-text" x="0" y="5" text-anchor="middle">${this._escape(text)}</text>
        `;
        return g;
    }

    _getSubsystemTelemetryLines(node) {
        const m = node.metrics || {};
        switch (node.category) {
            case 'system':
                return {
                    line1: m.os_version ? `${m.os_name || 'Windows'} (${m.os_version})` : (m.os_name || 'Windows Host'),
                    line2: `${m.uptime_formatted || '0 hrs'} • ${m.hypervisor || 'Physical'}`
                };
            case 'cpu':
            case 'compute':
                return {
                    line1: m.model ? this._truncate(m.model.replace(/Intel\(R\)\s*Core\(TM\)\s*/i, '').replace(/Processor/i, ''), 18) : 'CPU',
                    line2: `${m.physical_cores || 0}C / ${m.logical_cores || 0}T • ${m.utilization_percent !== null && m.utilization_percent !== undefined ? m.utilization_percent + '%' : 'N/A'}`
                };
            case 'memory': {
                const totalGB = m.total_bytes ? (m.total_bytes / (1024*1024*1024)).toFixed(1) : '0';
                return {
                    line1: `${totalGB} GB (${m.used_percent !== null && m.used_percent !== undefined ? m.used_percent + '%' : '0%'} used)`,
                    line2: `Commit: ${m.commit_used_percent !== undefined ? m.commit_used_percent + '%' : 'N/A'}`
                };
            }
            case 'storage':
                return {
                    line1: `${m.physical_disks_count || 0} Disk(s) • ${m.volumes_count || 0} Vol(s)`,
                    line2: m.system_drive_used_percent !== undefined ? `C:\\ ${m.system_drive_used_percent}% used` : 'Storage Online'
                };
            case 'network':
                return {
                    line1: `${m.adapters_count || 0} Component(s)`,
                    line2: m.primary_adapter_name ? `${m.primary_adapter_name}: ${m.primary_adapter_status || 'Up'}` : 'Interfaces Online'
                };
            case 'processes':
                return {
                    line1: `${m.total_processes || 0} Processes Active`,
                    line2: m.top_cpu_name ? `Top CPU: ${this._truncate(m.top_cpu_name, 14)}` : 'Process Telemetry'
                };
            case 'services':
                return {
                    line1: `${m.total_count || 0} Indexed (${m.running_count || 0} Running)`,
                    line2: `${m.stopped_count || 0} Stopped • ${m.failed_auto_start_count || 0} Failed`
                };
            case 'reliability':
                return {
                    line1: `${m.total_errors_logged || 0} Event(s) (${m.time_window_hours || 24}h Window)`,
                    line2: `${m.critical_events_count || 0} Critical • ${m.app_crashes_count || 0} App Crash`
                };
            case 'software':
                return {
                    line1: `${m.total_installed_apps || 0} Installed App(s)`,
                    line2: `${m.runtimes_count || 0} Runtime(s) • ${m.hotfixes_count || 0} Hotfix(es)`
                };
            default:
                return { line1: node.subtitle || 'Domain Telemetry', line2: 'Canonical Data Ready' };
        }
    }

    _getDomainIcon(category) {
        const icons = {
            system: '💻',
            compute: '⚡',
            cpu: '⚡',
            memory: '🧠',
            storage: '💾',
            network: '🌐',
            processes: '⚙️',
            services: '🛡️',
            reliability: '⚠️',
            software: '📦'
        };
        return icons[category] || '◈';
    }

    _formatCollectionStateBadge(colState) {
        const labels = {
            success: 'SUCCESS',
            collected: 'SUCCESS',
            partial: 'PARTIAL',
            requires_admin: 'REQUIRES ADMIN',
            unsupported: 'UNSUPPORTED',
            failed: 'FAILED',
            timeout: 'TIMEOUT',
            unknown: 'UNKNOWN / LEGACY',
            legacy: 'UNKNOWN / LEGACY'
        };
        return labels[colState] || String(colState).toUpperCase();
    }

    _formatSnapshotTimestamp(isoStr) {
        if (!isoStr) return '2026-09-17 11:15';
        try {
            const d = new Date(isoStr);
            if (isNaN(d.getTime())) return isoStr;
            const yyyy = d.getFullYear();
            const mm = String(d.getMonth() + 1).padStart(2, '0');
            const dd = String(d.getDate()).padStart(2, '0');
            const hh = String(d.getHours()).padStart(2, '0');
            const min = String(d.getMinutes()).padStart(2, '0');
            return `${yyyy}-${mm}-${dd} ${hh}:${min}`;
        } catch {
            return isoStr;
        }
    }

    _truncate(str, maxLen = 20) {
        if (!str) return '';
        return str.length > maxLen ? str.substring(0, maxLen - 1) + '…' : str;
    }

    _escape(str) {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }
}
