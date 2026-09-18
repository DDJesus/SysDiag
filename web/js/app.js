/**
 * Infrastructure Explorer - Application Controller
 * Phase 3 Spatial Infrastructure Navigation
 * Orchestrates schema validation, model adaptation, generic spatial focus navigation,
 * formalized navigation history, search-as-navigation, and evidence chain inspection.
 */

import { SchemaValidator } from './schema-validator.js';
import { SysDiagAdapter } from './sysdiag-adapter.js';
import { GraphRenderer } from './graph-renderer.js';
import { DetailInspector } from './detail-inspector.js';

export class InfrastructureExplorerApp {
    constructor() {
        this.currentReport = null;
        this.currentGraph = null;
        this.activeNodeId = null;
        this.historyStack = [];

        this._initElements();
        this._initComponents();
        this._bindEvents();
    }

    _initElements() {
        this.dropZone = document.getElementById('drop-zone');
        this.fileInput = document.getElementById('file-input');
        this.btnOpenFile = document.getElementById('btn-open-file');
        this.sampleSelect = document.getElementById('sample-select');
        this.breadcrumbsEl = document.getElementById('breadcrumbs');
        this.btnBack = document.getElementById('btn-nav-back');
        this.topologyContainer = document.getElementById('topology-container');
        this.inspectorContainer = document.getElementById('inspector-container');
        this.validationBanner = document.getElementById('validation-banner');
        this.statusBar = document.getElementById('status-bar');
        this.searchFilter = document.getElementById('search-filter');
        this.searchDropdown = document.getElementById('search-dropdown');
    }

    _initComponents() {
        this.inspector = new DetailInspector(this.inspectorContainer, (nodeId) => {
            this.navigateToNode(nodeId, true);
        });

        this.renderer = new GraphRenderer(this.topologyContainer, {
            onSelectNode: (nodeId) => {
                this.selectNode(nodeId);
            },
            onDrillDown: (nodeId) => {
                this.navigateToNode(nodeId, true);
            }
        });
    }

    _bindEvents() {
        // Drag & Drop
        window.addEventListener('dragover', (e) => {
            e.preventDefault();
            this.dropZone.classList.add('drag-active');
        });

        window.addEventListener('dragleave', (e) => {
            if (e.relatedTarget === null) {
                this.dropZone.classList.remove('drag-active');
            }
        });

        window.addEventListener('drop', (e) => {
            e.preventDefault();
            this.dropZone.classList.remove('drag-active');
            if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                this._handleFile(e.dataTransfer.files[0]);
            }
        });

        // File Picker
        this.btnOpenFile.addEventListener('click', () => {
            this.fileInput.click();
        });

        this.fileInput.addEventListener('change', (e) => {
            if (e.target.files && e.target.files.length > 0) {
                this._handleFile(e.target.files[0]);
            }
        });

        // Sample Select
        this.sampleSelect.addEventListener('change', (e) => {
            const val = e.target.value;
            if (val) {
                this.loadSample(val);
            }
        });

        // Formalized Back Navigation
        this.btnBack.addEventListener('click', () => {
            this.navigateBack();
        });

        // Search as Navigation
        this.searchFilter.addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase().trim();
            this._handleSearchQuery(query);
        });

        this.searchFilter.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this._closeSearchDropdown();
                this.searchFilter.value = '';
            } else if (e.key === 'Enter') {
                const firstResult = this.searchDropdown.querySelector('.search-result-item');
                if (firstResult) {
                    const nodeId = firstResult.dataset.nodeId;
                    if (nodeId) this._navigateFromSearchResult(nodeId);
                }
            }
        });

        // Close search dropdown on click outside
        document.addEventListener('click', (e) => {
            if (!e.target.closest('.search-box-container')) {
                this._closeSearchDropdown();
            }
        });
    }

    /**
     * Reads a dropped or picked JSON file.
     */
    _handleFile(file) {
        const reader = new FileReader();
        reader.onload = (e) => {
            try {
                const json = JSON.parse(e.target.result);
                this.loadReport(json, file.name);
            } catch (err) {
                this._showValidationError(`Invalid JSON file format: ${err.message}`);
            }
        };
        reader.onerror = () => {
            this._showValidationError(`Failed to read file "${file.name}".`);
        };
        reader.readAsText(file);
    }

    /**
     * Loads a pre-bundled sample report.
     */
    async loadSample(sampleName) {
        try {
            const response = await fetch(`./samples/${sampleName}`);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: Failed to fetch sample file.`);
            }
            const json = await response.json();
            this.loadReport(json, sampleName);
        } catch (err) {
            this._showValidationError(`Could not load sample "${sampleName}": ${err.message}`);
        }
    }

    /**
     * Loads and validates a canonical SysDiag report object.
     * @param {Object} report
     * @param {string} sourceName
     */
    loadReport(report, sourceName = 'sysdiag_report.json') {
        // Validate Schema
        const validation = SchemaValidator.validate(report);
        if (!validation.valid) {
            this._showValidationError(`Schema Validation Failed for "${sourceName}":\n• ${validation.errors.join('\n• ')}`);
            return;
        }

        try {
            const result = SysDiagAdapter.materialize(report);
            this.currentReport = report;
            this.currentGraph = result.graph;
            this.historyStack = [];

            this._showValidationSuccess(result.metadata, sourceName);
            this._updateStatusBar(result.metadata, report.collection_status);

            // Automatically transition into Machine spatial focus view
            const startNodeId = this.currentGraph.activeMachineId || this.currentGraph.rootId;
            this.navigateToNode(startNodeId, false);
        } catch (err) {
            this._showValidationError(`Model Materialization Error: ${err.message}`);
        }
    }

    /**
     * Generic Spatial Focus Navigation API:
     * Navigates to a specific node, updating focus, renderer, breadcrumbs, and inspector.
     * @param {string} nodeId
     * @param {boolean} [pushHistory=true]
     * @param {string} [viewMode='spatial']
     */
    navigateToNode(nodeId, pushHistory = true, viewMode = 'spatial') {
        if (!this.currentGraph) return;
        const node = this.currentGraph.getNode(nodeId);
        if (!node) return;

        if (pushHistory && this.activeNodeId && this.activeNodeId !== node.id) {
            this.historyStack.push({
                nodeId: this.activeNodeId,
                viewMode: this.renderer.viewMode || 'spatial'
            });
        }

        this.activeNodeId = node.id;
        this.renderer.focusNode(node.id, viewMode);
        this.inspector.inspect(node, this.currentGraph);
        this._updateBreadcrumbs(node.id);
        this._updateBackButton();
    }

    /**
     * Navigates back in history stack, or falls back to parent node.
     */
    navigateBack() {
        if (!this.currentGraph || !this.activeNodeId) return;

        if (this.historyStack.length > 0) {
            const prev = this.historyStack.pop();
            this.navigateToNode(prev.nodeId, false, prev.viewMode);
            return;
        }

        const currNode = this.currentGraph.getNode(this.activeNodeId);
        if (currNode && currNode.parentId) {
            this.navigateToNode(currNode.parentId, false, 'spatial');
        } else if (this.currentGraph.activeMachineId && this.activeNodeId !== this.currentGraph.activeMachineId) {
            this.navigateToNode(this.currentGraph.activeMachineId, false, 'spatial');
        }
    }

    /**
     * Selects a node without necessarily resetting canvas focus level.
     * Synchronizes inspector and breadcrumbs.
     */
    selectNode(nodeId) {
        if (!this.currentGraph) return;
        const node = this.currentGraph.getNode(nodeId);
        if (!node) return;

        this.activeNodeId = node.id;
        this.renderer.selectNode(node.id);
        this.inspector.inspect(node, this.currentGraph);
        this._updateBreadcrumbs(node.id);
        this._updateBackButton();
    }

    /**
     * Handles search input and displays navigational search suggestions.
     */
    _handleSearchQuery(query) {
        if (!this.currentGraph || !query) {
            this._closeSearchDropdown();
            return;
        }

        const matches = this.currentGraph.filterNodes(n => {
            const labelMatch = n.label && n.label.toLowerCase().includes(query);
            const subMatch = n.subtitle && n.subtitle.toLowerCase().includes(query);
            const idMatch = n.id && n.id.toLowerCase().includes(query);
            const catMatch = n.category && n.category.toLowerCase().includes(query);
            const findingMatch = n.findings && n.findings.some(f => 
                (f.id && f.id.toLowerCase().includes(query)) ||
                (f.title && f.title.toLowerCase().includes(query)) ||
                (f.observation && f.observation.toLowerCase().includes(query))
            );
            return labelMatch || subMatch || idMatch || catMatch || findingMatch;
        });

        if (matches.length === 0) {
            this.searchDropdown.innerHTML = `
                <div class="search-empty">No infrastructure nodes or findings match "${this._escape(query)}"</div>
            `;
            this.searchDropdown.style.display = 'block';
            return;
        }

        // Limit to top 10 relevant matches
        const topMatches = matches.slice(0, 10);

        this.searchDropdown.innerHTML = `
            <div class="search-results-list">
                ${topMatches.map(n => {
                    const breadcrumbs = this.currentGraph.getBreadcrumbs(n.id);
                    const pathStr = breadcrumbs.map(b => b.label).join(' → ');
                    return `
                        <div class="search-result-item" data-node-id="${n.id}">
                            <div class="sr-left">
                                <span class="sr-type-badge type-${n.type}">${n.type.toUpperCase()}</span>
                                <div class="sr-text">
                                    <div class="sr-title">${this._escape(n.label)}</div>
                                    <div class="sr-path">${this._escape(pathStr)}</div>
                                </div>
                            </div>
                            <div class="sr-right">
                                <span class="status-pill status-${n.status}">${n.status.toUpperCase()}</span>
                            </div>
                        </div>
                    `;
                }).join('')}
            </div>
        `;
        this.searchDropdown.style.display = 'block';

        this.searchDropdown.querySelectorAll('.search-result-item').forEach(item => {
            item.addEventListener('click', () => {
                const targetId = item.dataset.nodeId;
                if (targetId) this._navigateFromSearchResult(targetId);
            });
        });
    }

    /**
     * Executes search-driven navigation via the unified spatial focus API.
     */
    _navigateFromSearchResult(nodeId) {
        this._closeSearchDropdown();
        this.searchFilter.value = '';

        const node = this.currentGraph.getNode(nodeId);
        if (!node) return;

        // Unified Spatial Focus Navigation
        this.navigateToNode(node.id, true, 'spatial');

        if (node.type === 'finding') {
            this.inspector.activeTab = 'findings';
            this.inspector.inspect(node, this.currentGraph);
        }
    }

    _closeSearchDropdown() {
        if (this.searchDropdown) {
            this.searchDropdown.style.display = 'none';
        }
    }

    _updateBreadcrumbs(nodeId) {
        const trail = this.currentGraph.getBreadcrumbs(nodeId);
        this.breadcrumbsEl.innerHTML = trail.map((n, idx) => {
            const isLast = idx === trail.length - 1;
            return `
                <span class="crumb-item ${isLast ? 'crumb-active' : ''}" data-crumb-id="${n.id}">
                    <span class="crumb-type">${n.type.toUpperCase()}:</span>
                    <span class="crumb-label">${this._escape(n.label)}</span>
                </span>
                ${!isLast ? '<span class="crumb-sep">/</span>' : ''}
            `;
        }).join('');

        this.breadcrumbsEl.querySelectorAll('.crumb-item').forEach(el => {
            el.addEventListener('click', (e) => {
                const targetId = e.currentTarget.dataset.crumbId;
                if (targetId) this.navigateToNode(targetId, true);
            });
        });
    }

    _updateBackButton() {
        if (this.historyStack.length > 0) {
            this.btnBack.disabled = false;
            const prev = this.historyStack[this.historyStack.length - 1];
            const prevNode = this.currentGraph.getNode(prev.nodeId);
            this.btnBack.title = `Back to ${prevNode ? prevNode.label : 'Previous'}`;
            return;
        }

        const currNode = this.currentGraph.getNode(this.activeNodeId);
        if (currNode && currNode.parentId) {
            this.btnBack.disabled = false;
            this.btnBack.title = `Back to ${this.currentGraph.getNode(currNode.parentId)?.label || 'Parent'}`;
        } else {
            this.btnBack.disabled = true;
            this.btnBack.title = 'At Root Level';
        }
    }

    _showValidationError(message) {
        this.validationBanner.className = 'val-banner val-error';
        this.validationBanner.innerHTML = `
            <div class="val-icon">❌</div>
            <div class="val-msg">
                <div class="val-title">SCHEMA / MODEL ERROR</div>
                <div class="val-desc">${this._escape(message)}</div>
            </div>
        `;
        this.validationBanner.style.display = 'flex';
    }

    _showValidationSuccess(meta, sourceName) {
        this.validationBanner.className = 'val-banner val-success';
        this.validationBanner.innerHTML = `
            <div class="val-icon">✓</div>
            <div class="val-msg">
                <div class="val-title">CANONICAL SYSDIAG REPORT VALIDATED & LOADED</div>
                <div class="val-desc">Source: <strong>${this._escape(sourceName)}</strong> • Host: <strong>${this._escape(meta.hostname || 'Unknown')}</strong> • Schema: <code>1.0.0</code> • Coverage: <strong>${meta.collection_status?.successful || 0}/${meta.collection_status?.total_probes || 0} Probes</strong></div>
            </div>
            <button class="val-close-btn" id="btn-close-banner">✕</button>
        `;
        this.validationBanner.style.display = 'flex';

        document.getElementById('btn-close-banner')?.addEventListener('click', () => {
            this.validationBanner.style.display = 'none';
        });
    }

    _updateStatusBar(meta, col) {
        col = col || {};
        const isElevated = meta.is_elevated ? 'Elevated' : 'Standard User';
        const scanTime = meta.scan_timestamp ? new Date(meta.scan_timestamp).toLocaleTimeString() : 'N/A';
        const duration = meta.scan_duration_ms !== undefined ? `${meta.scan_duration_ms} ms` : 'N/A';

        this.statusBar.innerHTML = `
            <div class="status-item"><span class="s-key">HOST:</span> <span class="s-val">${this._escape(meta.hostname || 'N/A')}</span></div>
            <div class="status-item"><span class="s-key">OS:</span> <span class="s-val">${this._escape(meta.os_version || meta.os || 'N/A')}</span></div>
            <div class="status-item"><span class="s-key">COVERAGE:</span> <span class="s-val ${col.successful === col.total_probes ? 's-val-ok' : 's-val-warn'}">${col.successful || 0}/${col.total_probes || 0} Probes (${col.total_probes ? Math.round(((col.successful || 0)/col.total_probes)*100) : 0}%)</span></div>
            <div class="status-item"><span class="s-key">PRIVILEGE:</span> <span class="s-val">${this._escape(meta.privilege_level || 'User')} (${isElevated})</span></div>
            <div class="status-item"><span class="s-key">SCAN TIME:</span> <span class="s-val">${scanTime} (${duration})</span></div>
            <div class="status-item"><span class="s-key">MODE:</span> <span class="s-val s-val-readonly">READ-ONLY OBSERVATIONAL</span></div>
        `;
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

// Instantiate Explorer on DOM load
window.addEventListener('DOMContentLoaded', () => {
    window.app = new InfrastructureExplorerApp();
});
