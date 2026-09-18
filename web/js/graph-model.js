/**
 * Infrastructure Graph Model
 * Provides the canonical graph data structure for hierarchical multi-layer infrastructure exploration.
 * Supports Environment → Site → Network → Machine → Subsystem → Component → Evidence.
 */

export class GraphNode {
    /**
     * @param {Object} options
     * @param {string} options.id - Stable unique identifier
     * @param {string} options.type - 'environment' | 'site' | 'network_group' | 'machine' | 'subsystem' | 'component' | 'finding' | 'evidence'
     * @param {string} options.category - Diagnostic category (e.g., 'system', 'compute', 'storage', 'network', etc.)
     * @param {string} options.label - Primary human-readable label
     * @param {string} [options.subtitle] - Secondary descriptor
     * @param {number} options.level - Hierarchy depth (0=Environment, 1=Site, 2=Network, 3=Machine, 4=Subsystem, 5=Component, 6=Evidence)
     * @param {string|null} [options.parentId=null] - Parent node ID
     * @param {any} [options.sourceData=null] - Unmodified reference to the source canonical JSON slice
     * @param {Array<any>} [options.findings=[]] - Direct or aggregated findings
     * @param {string} [options.collectionState='collected'] - 'collected' | 'not_collected' | 'partial' | 'requires_admin' | 'unsupported' | 'failed' | 'timeout'
     * @param {Object} [options.metrics={}] - Measured key-value metrics
     * @param {string} [options.status='normal'] - 'normal' | 'info' | 'warning' | 'critical' | 'unavailable'
     * @param {Object} [options.metadata={}] - Additional structural metadata
     */
    constructor({
        id,
        type,
        category = 'general',
        label,
        subtitle = '',
        level = 0,
        parentId = null,
        sourceData = null,
        findings = [],
        collectionState = 'collected',
        metrics = {},
        status = 'normal',
        metadata = {}
    }) {
        this.id = id;
        this.type = type;
        this.category = category;
        this.label = label;
        this.subtitle = subtitle;
        this.level = level;
        this.parentId = parentId;
        this.childrenIds = [];
        this.sourceData = sourceData;
        this.findings = findings;
        this.collectionState = collectionState;
        this.metrics = metrics;
        this.status = status;
        this.metadata = metadata;
    }
}

export class GraphEdge {
    /**
     * @param {Object} options
     * @param {string} options.id
     * @param {string} options.source - Source Node ID
     * @param {string} options.target - Target Node ID
     * @param {string} [options.type='hierarchy'] - 'hierarchy' | 'contains' | 'association' | 'evidence_link'
     * @param {string} [options.label='']
     */
    constructor({ id, source, target, type = 'hierarchy', label = '' }) {
        this.id = id || `${source}->${target}`;
        this.source = source;
        this.target = target;
        this.type = type;
        this.label = label;
    }
}

export class InfrastructureGraph {
    constructor() {
        /** @type {Map<string, GraphNode>} */
        this.nodes = new Map();
        /** @type {Map<string, GraphEdge>} */
        this.edges = new Map();
        /** @type {string|null} */
        this.rootId = null;
        /** @type {string|null} */
        this.activeMachineId = null;
    }

    /**
     * Clears all nodes and edges.
     */
    clear() {
        this.nodes.clear();
        this.edges.clear();
        this.rootId = null;
        this.activeMachineId = null;
    }

    /**
     * Registers a node in the graph.
     * @param {GraphNode} node
     */
    addNode(node) {
        if (!node || !node.id) throw new Error('GraphNode must have a valid ID.');
        this.nodes.set(node.id, node);

        if (node.parentId && this.nodes.has(node.parentId)) {
            const parent = this.nodes.get(node.parentId);
            if (!parent.childrenIds.includes(node.id)) {
                parent.childrenIds.push(node.id);
            }
            const edgeId = `${parent.id}->${node.id}`;
            this.addEdge(new GraphEdge({
                id: edgeId,
                source: parent.id,
                target: node.id,
                type: 'hierarchy'
            }));
        }

        return node;
    }

    /**
     * Registers a directed edge.
     * @param {GraphEdge} edge
     */
    addEdge(edge) {
        if (!edge || !edge.id) return;
        this.edges.set(edge.id, edge);
    }

    /**
     * Retrieves a node by ID.
     * @param {string} id
     * @returns {GraphNode|undefined}
     */
    getNode(id) {
        return this.nodes.get(id);
    }

    /**
     * Retrieves immediate children of a node.
     * @param {string} id
     * @returns {GraphNode[]}
     */
    getChildren(id) {
        const node = this.getNode(id);
        if (!node) return [];
        return node.childrenIds
            .map(childId => this.nodes.get(childId))
            .filter(Boolean);
    }

    /**
     * Retrieves parent of a node.
     * @param {string} id
     * @returns {GraphNode|null}
     */
    getParent(id) {
        const node = this.getNode(id);
        if (!node || !node.parentId) return null;
        return this.getNode(node.parentId) || null;
    }

    /**
     * Retrieves full path of ancestors from root down to node.
     * @param {string} id
     * @returns {GraphNode[]}
     */
    getBreadcrumbs(id) {
        const breadcrumbs = [];
        let curr = this.getNode(id);
        while (curr) {
            breadcrumbs.unshift(curr);
            curr = curr.parentId ? this.getNode(curr.parentId) : null;
        }
        return breadcrumbs;
    }

    /**
     * Finds nodes matching a predicate.
     * @param {(node: GraphNode) => boolean} predicate
     * @returns {GraphNode[]}
     */
    filterNodes(predicate) {
        const results = [];
        for (const node of this.nodes.values()) {
            if (predicate(node)) {
                results.push(node);
            }
        }
        return results;
    }

    /**
     * Returns the 9 major subsystems for a given machine node.
     * @param {string} machineId
     * @returns {GraphNode[]}
     */
    getSubsystems(machineId) {
        return this.getChildren(machineId).filter(n => n.type === 'subsystem');
    }

    /**
     * Computes high-level statistics for the graph.
     */
    getSummary() {
        let totalNodes = this.nodes.size;
        let totalFindings = 0;
        let findingsBySeverity = { CRITICAL: 0, WARNING: 0, INFO: 0 };
        let degradedProbes = 0;

        for (const node of this.nodes.values()) {
            if (node.findings && node.findings.length > 0) {
                totalFindings += node.findings.length;
                node.findings.forEach(f => {
                    if (findingsBySeverity[f.severity] !== undefined) {
                        findingsBySeverity[f.severity]++;
                    }
                });
            }
            if (['partial', 'requires_admin', 'unsupported', 'failed', 'timeout', 'not_collected'].includes(node.collectionState)) {
                degradedProbes++;
            }
        }

        return {
            totalNodes,
            totalFindings,
            findingsBySeverity,
            degradedProbes
        };
    }
}
