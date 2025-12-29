# 🔐 SIT Protocol Security Model

## Threat Model

### Adversary Capabilities

We assume an adversary who can:

1. **Craft arbitrary user inputs** - Including adversarial prompts, injection attempts
2. **Observe request/response patterns** - Timing, size, frequency
3. **Access public documentation** - This security model is public
4. **Attempt to bypass L1-L4 layers** - Through malformed inputs

We assume an adversary who **cannot**:

1. Modify the SIT validator code in production
2. Access the private policy rules
3. Compromise the execution sandbox directly
4. Intercept encrypted SIT State in transit

### Attack Surface

| Layer | Attack Vector | Mitigation |
|-------|--------------|------------|
| L1 (Serializer) | Prompt injection to produce malicious SIT State | Schema validation, forbidden patterns |
| L2 (Firewall) | Policy bypass through edge cases | Deny-by-default, rule priority |
| L3 (Executor) | Sandbox escape | OS-level isolation, resource limits |
| L4 (Sanitizer) | Data leakage in response | Pattern redaction, schema enforcement |

---

## Security Properties

### 1. Data Isolation

**Property:** Raw data never crosses layer boundaries.

**Enforcement:**
- L1 outputs only schema-valid SIT State
- L2 operates only on SIT State fields
- L3 receives only approved SIT State
- L4 outputs only sanitized SIT Response

**Verification:** Static analysis of data flow; no raw data fields in SIT schema.

### 2. Injection Resistance

**Property:** Known injection patterns are blocked.

**Enforcement:**
- `forbidden_patterns` regex scan on all string values
- `forbidden_fields` blocklist on all field names
- Schema rejects additional properties

**Verification:** Regex test suite against OWASP injection examples.

### 3. Policy Enforcement

**Property:** Only policy-compliant requests execute.

**Enforcement:**
- Deny-by-default when no rules match
- Priority-ordered rule evaluation
- ESCALATE action for sensitive scopes

**Verification:** Policy simulation tests.

### 4. Auditability

**Property:** All state transitions are logged.

**Enforcement:**
- `metadata.request_id` (UUID) for tracing
- `metadata.chain` for transformation history
- Hash chain for tamper detection

**Verification:** Audit log integrity checks.

---

## Compliance Mapping

### SOC 2

| Control | SIT Implementation |
|---------|-------------------|
| CC6.1 (Logical Access) | `requester.role`, `clearance_level` |
| CC6.6 (System Boundaries) | L1-L4 layer isolation |
| CC7.2 (Anomaly Detection) | `forbidden_patterns` scanning |
| CC8.1 (Change Management) | Schema versioning |

### HIPAA

| Requirement | SIT Implementation |
|-------------|-------------------|
| Access Control (§164.312(a)) | Policy rules on `scope.data_types_allowed` |
| Audit Controls (§164.312(b)) | `metadata.chain` with hash |
| Integrity (§164.312(c)) | Schema validation, forbidden patterns |
| Transmission Security (§164.312(e)) | SIT State is structured, not raw PHI |

### PCI-DSS

| Requirement | SIT Implementation |
|-------------|-------------------|
| 7.1 (Need to Know) | `scope.entity_scope` limits |
| 7.2 (Access Control) | `clearance_level` + policy rules |
| 10.2 (Audit Trail) | `metadata.request_id`, `chain` |
| 11.5 (Change Detection) | Schema hash verification |

---

## Known Limitations

### 1. L1 Serializer Dependency

The security of SIT depends on L1 correctly serializing intent. If L1 is compromised or buggy, malformed SIT States may be produced.

**Mitigation:** Defense in depth. L2 validates all SIT States regardless of source.

### 2. Policy Completeness

Policies must be comprehensive. Missing rules may allow unintended access.

**Mitigation:** Deny-by-default. Unknown = blocked.

### 3. Novel Injection Patterns

New injection techniques may bypass `forbidden_patterns`.

**Mitigation:** Continuous pattern updates. Community reporting.

### 4. Side Channels

Timing or size differences may leak information.

**Mitigation:** Constant-time operations (future). Response padding (future).

---

## Vulnerability Reporting

If you discover a security vulnerability in SIT Protocol:

1. **Do not** open a public issue
2. Email: [security@your-domain.com]
3. Include: Steps to reproduce, potential impact, suggested fix
4. We will respond within 48 hours

We follow responsible disclosure and will credit reporters.

---

## Security Changelog

| Version | Date | Change |
|---------|------|--------|
| 1.0.0 | 2025-12-29 | Initial security model |

---

**"Security is not a feature. It's a property of the architecture."**
