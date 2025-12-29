# 🎯 SIT Protocol Threat Model

**Version:** 1.0 | **IMCC Round 7**

---

## Threat Catalog

| ID | Threat | Layer | MITRE | Risk | Status |
|----|--------|-------|-------|------|--------|
| T1 | Prompt Injection | L1 | T1059 | 🔴 CRITICAL | ✅ Mitigated |
| T2 | SQL Injection | L1/L3 | T1190 | 🔴 HIGH | ✅ Mitigated |
| T3 | Privilege Escalation | L2 | T1548 | 🟠 HIGH | ✅ Mitigated |
| T4 | Data Exfiltration | L4 | T1041 | 🟠 HIGH | ⚠️ Partial |
| T5 | System Prompt Extraction | L1/L4 | T1552 | 🟡 MEDIUM | ✅ Mitigated |

---

## Attack Surface by Layer

### L1: Intent Serializer
- Prompt injection → `forbidden_patterns`
- Schema bypass → strict JSON Schema
- DoS → input size limits

### L2: Semantic Firewall  
- Policy bypass → deny-by-default
- Role spoofing → external IAM validation

### L3: Isolated Executor
- Sandbox escape → OS-level isolation
- Resource exhaustion → timeouts, memory caps

### L4: Response Sanitizer
- Pattern evasion → encoding detection
- Field leakage → `FORBIDDEN_RESPONSE_FIELDS`

---

## Security Controls

| Control | Implementation |
|---------|----------------|
| Schema Validation | `sit-state-v1.json` |
| Injection Detection | `forbidden_patterns` regex |
| Policy Engine | DSL with priority rules |
| Deny-by-Default | No match = DENY |
| Response Redaction | Pattern + field blocklist |
| Audit Trail | Hash-chained logs |

---

## References

- OWASP Top 10: https://owasp.org/Top10/
- MITRE ATT&CK: https://attack.mitre.org/
