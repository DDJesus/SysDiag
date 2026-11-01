/**
 * SysDiag Schema Validator (v1.0.0)
 * Validates canonical sysdiag JSON reports before ingestion into the infrastructure graph.
 * Fails gracefully with clear structural explanations on schema mismatches.
 */

export class SchemaValidator {
    static SUPPORTED_SCHEMA_VERSIONS = ['1.0.0'];
    static CANONICAL_SCHEMA_URL_PREFIX = 'https://systemdiag.io/schema/';

    /**
     * Validates a parsed JSON object against sysdiag 1.0.0 contract.
     * @param {any} report
     * @returns {{ valid: boolean, errors: string[], warnings: string[], version: string }}
     */
    static validate(report) {
        const errors = [];
        const warnings = [];

        if (!report || typeof report !== 'object' || Array.isArray(report)) {
            return {
                valid: false,
                errors: ['Input is not a valid JSON object.'],
                warnings: [],
                version: 'unknown'
            };
        }

        // 1. Schema & Version Validation
        const schema = report['$schema'];
        const schemaVersion = report['schema_version'];

        if (!schemaVersion) {
            errors.push('Missing required root property "schema_version".');
        } else if (!this.SUPPORTED_SCHEMA_VERSIONS.includes(schemaVersion)) {
            errors.push(`Unsupported schema version "${schemaVersion}". Supported versions: ${this.SUPPORTED_SCHEMA_VERSIONS.join(', ')}.`);
        }

        if (!schema) {
            warnings.push('Root property "$schema" is missing (expected https://systemdiag.io/schema/v1.json).');
        }

        // 2. Metadata Validation
        if (!report.metadata || typeof report.metadata !== 'object') {
            errors.push('Missing or invalid "metadata" object in report.');
        } else {
            const meta = report.metadata;
            if (!meta.hostname) errors.push('Missing "metadata.hostname".');
            if (!meta.scan_timestamp) errors.push('Missing "metadata.scan_timestamp".');
            if (meta.is_elevated === undefined) warnings.push('"metadata.is_elevated" is undefined.');
        }

        // 3. Collection Status Validation
        if (!report.collection_status || typeof report.collection_status !== 'object') {
            errors.push('Missing or invalid "collection_status" object in report.');
        } else {
            const status = report.collection_status;
            const requiredNumericFields = ['total_probes', 'successful', 'partial', 'requires_admin', 'unsupported', 'failed', 'timeout'];
            for (const field of requiredNumericFields) {
                if (typeof status[field] !== 'number') {
                    errors.push(`"collection_status.${field}" must be a numeric integer.`);
                }
            }
            for (const field of ['canceled', 'skipped']) {
                if (status[field] !== undefined && typeof status[field] !== 'number') {
                    errors.push(`"collection_status.${field}" must be a numeric integer when provided.`);
                }
            }

            // Validate explicit per-probe collection records if present
            if (status.probes !== undefined) {
                if (!Array.isArray(status.probes)) {
                    errors.push('"collection_status.probes" must be an array when provided.');
                } else {
                    const validStatuses = ['Success', 'Partial', 'Requires Administrator', 'Unsupported', 'Failed', 'Timeout', 'Canceled', 'Skipped'];
                    status.probes.forEach((p, idx) => {
                        if (!p.probe_id && !p.category) {
                            errors.push(`Probe record at index ${idx} missing "probe_id" or "category".`);
                        }
                        if (!p.status) {
                            errors.push(`Probe record at index ${idx} missing "status".`);
                        } else if (!validStatuses.includes(p.status)) {
                            warnings.push(`Probe record "${p.probe_id || idx}" has non-standard status "${p.status}".`);
                        }
                    });
                }
            }
        }

        // 4. Data Object Validation
        if (!report.data || typeof report.data !== 'object') {
            errors.push('Missing or invalid "data" container object.');
        }

        // 5. Findings Array Validation
        if (report.findings && !Array.isArray(report.findings)) {
            errors.push('"findings" must be an array.');
        } else if (Array.isArray(report.findings)) {
            report.findings.forEach((f, idx) => {
                if (!f.id) errors.push(`Finding at index ${idx} missing "id".`);
                if (!f.category) errors.push(`Finding at index ${idx} missing "category".`);
                if (!f.severity || !['INFO', 'WARNING', 'CRITICAL'].includes(f.severity)) {
                    errors.push(`Finding "${f.id || idx}" has invalid severity "${f.severity}". Must be INFO, WARNING, or CRITICAL.`);
                }
                if (!f.observation) errors.push(`Finding "${f.id || idx}" missing "observation".`);
                if (!f.interpretation) errors.push(`Finding "${f.id || idx}" missing "interpretation".`);
                if (!f.recommendation) errors.push(`Finding "${f.id || idx}" missing "recommendation".`);
            });
        }

        // 6. Limitations Array Validation
        if (report.limitations && !Array.isArray(report.limitations)) {
            errors.push('"limitations" must be an array.');
        }

        return {
            valid: errors.length === 0,
            errors,
            warnings,
            version: schemaVersion || 'unknown'
        };
    }
}
