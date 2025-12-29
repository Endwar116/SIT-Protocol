# 📋 SIT Protocol Compliance Mapping

**Version:** 1.0 | **IMCC Round 8**

---

## SOC 2 Type II

| Control | SIT Implementation |
|---------|-------------------|
| **CC6.1** Logical Access | `requester.role`, `clearance_level`, Policy Engine |
| **CC6.6** System Boundaries | L1-L4 layer isolation |
| **CC6.7** Data Classification | `scope.data_types_allowed/denied` |
| **CC7.2** Anomaly Detection | `forbidden_patterns` scanning |
| **CC8.1** Change Management | Schema versioning (`sit_version`) |

---

## HIPAA (Healthcare)

| Requirement | SIT Implementation |
|-------------|-------------------|
| **§164.312(a)** Access Control | Policy rules on `scope`, `clearance_level` |
| **§164.312(b)** Audit Controls | `metadata.chain` with hash trail |
| **§164.312(c)** Integrity | Schema validation, forbidden patterns |
| **§164.312(d)** Authentication | `requester.id`, `session_fingerprint` |
| **§164.312(e)** Transmission Security | SIT State = structured, not raw PHI |

**PHI Protection:** Add `"health"` to `scope.data_types_denied`

---

## PCI-DSS (Payment)

| Requirement | SIT Implementation |
|-------------|-------------------|
| **7.1** Need to Know | `scope.entity_scope` limits |
| **7.2** Access Control | `clearance_level` + policy rules |
| **8.3** Authentication | `requester` identity validation |
| **10.2** Audit Trail | `metadata.request_id`, `chain` |
| **11.5** Change Detection | Schema hash verification |

**Cardholder Data Protection:** Add `"financial", "credit_card"` to `scope.data_types_denied`

---

## GDPR (Privacy)

| Principle | SIT Implementation |
|-----------|-------------------|
| **Lawfulness** | `intent.purpose` documents justification |
| **Purpose Limitation** | `scope` restricts data access |
| **Data Minimization** | `constraints.max_tokens` limits response |
| **Accuracy** | Audit trail enables correction tracking |
| **Storage Limitation** | SIT State is transient, not stored |
| **Security** | L1-L4 defense in depth |
| **Accountability** | `metadata` enables full traceability |

**Right to Erasure:** SIT State contains no persistent PII

---

## Quick Compliance Checklist

### For HIPAA Deployment
```json
"scope": {
  "data_types_denied": ["health", "pii", "credentials"]
}
```

### For PCI-DSS Deployment  
```json
"scope": {
  "data_types_denied": ["financial", "credit_card", "credentials"]
}
```

### For GDPR Deployment
```json
"intent": {
  "purpose": "Required for GDPR Art. 6 lawful basis"
}
```

---

## Audit Evidence

SIT Protocol generates compliance-ready evidence:

| Evidence | Location | Format |
|----------|----------|--------|
| Access Logs | `metadata.chain` | JSON with hashes |
| Policy Decisions | L2 output | ALLOW/DENY + rule_id |
| Data Handling | `sanitization` block | Redaction counts |
| Request Justification | `intent.purpose` | Free text |

---

**"Compliance by design, not by accident."**

— IMCC Compliance Team
