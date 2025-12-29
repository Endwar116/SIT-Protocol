# 🛡️ SIT Protocol: Semantic Isolation Transfer

**The semantic firewall for AI-native security.**

> "Don't transfer data. Transfer intent."

---

## 🎯 What is SIT?

**SIT (Semantic Isolation Transfer)** is a security protocol that protects AI systems by serializing *intent* instead of *data*. 

Traditional security fails because boundaries are defined at the wrong layer (memory, network, process). AI-native attacks like prompt injection, context poisoning, and RAG exploitation bypass these boundaries entirely.

**SIT moves the security boundary to the semantic layer.**

```
┌─────────────────────────────────────────────────────────────┐
│                    TRADITIONAL APPROACH                     │
│                                                             │
│  User → [Raw Query] → AI Agent → [Raw SQL] → Database       │
│                           ↓                                 │
│                    💀 INJECTION POINT                       │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                      SIT APPROACH                           │
│                                                             │
│  User → [L1: Serialize] → [L2: Validate] → [L3: Execute]    │
│              ↓                  ↓                ↓          │
│         SIT State          Policy Check     Sandboxed       │
│         (Intent)           (Rules)          Execution       │
│                                                             │
│  ✅ Raw data NEVER crosses boundaries                       │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔐 Core Principles

SIT is built on five axioms that cannot be violated:

| # | Axiom | Implication |
|---|-------|-------------|
| 1 | All security breaches are boundary failures | Focus on boundaries, not patches |
| 2 | Traditional boundaries = memory/network/process | These are bypassable by AI-native attacks |
| 3 | AI-native systems have a new boundary: semantic intent | This is where we must enforce security |
| 4 | Serialize intent instead of data → data cannot leak | The core SIT mechanism |
| 5 | Structured semantic state is inherently sanitized | Schema validation = automatic sanitization |

---

## 🏗️ Architecture

SIT operates through four layers:

| Layer | Name | Function | Security Property |
|-------|------|----------|-------------------|
| L1 | Intent Serializer | Natural language → SIT State JSON | Non-conforming content dropped |
| L2 | Semantic Firewall | Validate against policy rules | Only compliant intents pass |
| L3 | Isolated Executor | Execute in sandbox | Executor never sees raw data |
| L4 | Response Sanitizer | Strip sensitive data from output | Only semantic result returned |

**Invariant:** Raw data never crosses layer boundaries. Only SIT State does.

---

## 📋 SIT State Format

A SIT State is a JSON object that captures the *intent* of a request:

```json
{
  "sit_version": "1.0",
  
  "intent": {
    "action": "READ",
    "target": "user profile summary",
    "purpose": "Display greeting on dashboard"
  },
  
  "scope": {
    "data_types_allowed": ["display_name", "avatar_url"],
    "data_types_denied": ["credentials", "pii", "financial"],
    "entity_scope": ["self"]
  },
  
  "requester": {
    "id": "agent_dashboard_v1",
    "role": "agent",
    "clearance_level": 3
  },
  
  "constraints": {
    "max_tokens": 500,
    "allowed_operations": ["READ"],
    "output_format": "json"
  },
  
  "metadata": {
    "request_id": "550e8400-e29b-41d4-a716-446655440000",
    "timestamp": "2025-12-29T12:00:00+08:00",
    "source_system": "web_dashboard"
  }
}
```

### Forbidden Fields

These fields are **automatically rejected** by the validator:

- `raw_sql`, `raw_query`, `sql`, `query`
- `memory_address`, `pointer`, `address`
- `file_path`, `filepath`, `path`
- `credentials`, `password`, `secret`
- `api_key`, `token`, `session_token`
- `private_key`

### Injection Pattern Detection

All string values are scanned for:

- SQL injection patterns (`SELECT`, `UNION`, `--`)
- Path traversal (`../`, `/etc/passwd`)
- XSS patterns (`<script`, `javascript:`)
- Template injection (`{{`, `${`)

---

## 🚀 Quick Start

### 1. Validate a SIT State

```bash
# Clone the repo
git clone https://github.com/Endwar116/SIT-Protocol.git
cd SIT-Protocol

# Validate an example
python validators/validate_sit.py examples/example-01-read-profile.json
```

Expected output:
```
============================================================
SIT PROTOCOL VALIDATION REPORT
============================================================

✅ SIT State is VALID

============================================================
```

### 2. Apply a Policy

```bash
python validators/validate_sit.py examples/example-01-read-profile.json \
  --policy examples/policies/default-security.json
```

Expected output:
```
------------------------------------------------------------
POLICY EVALUATION
------------------------------------------------------------
  Policy: Default Security Policy
  Action: ALLOW
  Rule:   allow_read_agents
```

### 3. Test Injection Detection

Create a malicious SIT State:

```json
{
  "sit_version": "1.0",
  "intent": {
    "action": "READ",
    "target": "users WHERE 1=1 OR 'x'='x'",
    "purpose": "Totally legitimate request"
  },
  ...
}
```

The validator will reject it:
```
❌ SIT State is INVALID

Errors (1):
  🔴 [CRITICAL] intent.target: Injection pattern detected
```

---

## 🎯 Use Cases

### 1. AI Agent ↔ Database Isolation

**Problem:** AI Agents with database access can leak data via prompt injection.

**SIT Solution:** Agent only sees/sends SIT State, never raw SQL.

```
User: "Show me all users' passwords"
       ↓
[L1] Serializes to SIT State
       ↓
[L2] Policy: "credentials" in denied_types → DENY
       ↓
❌ Request blocked before reaching database
```

### 2. Multi-Agent Memory Isolation

**Problem:** In shared environments, Agent A's context may leak to Agent B.

**SIT Solution:** Each agent's memory is tagged with `owner_id`. Cross-read requires SIT transformation that strips unauthorized data.

### 3. System Prompt Protection

**Problem:** Users extract system prompts via clever prompting.

**SIT Solution:** System prompt exists in isolated SIT zone. User queries' `scope.entity_scope` cannot include `system`.

---

## 🔄 The Infinite Game

SIT is designed for **infinite iteration**:

```
┌─────────────────────────────────────────────────────────────┐
│                    ITERATION LOOP                           │
│                                                             │
│  1. New attack discovered                                   │
│         ↓                                                   │
│  2. Add pattern to forbidden_patterns                       │
│         ↓                                                   │
│  3. Add rule to Policy DSL                                  │
│         ↓                                                   │
│  4. Schema version bump (backward compatible)               │
│         ↓                                                   │
│  5. All validators auto-update                              │
│         ↓                                                   │
│  (Return to 1)                                              │
│                                                             │
│  The moat deepens with every iteration.                     │
└─────────────────────────────────────────────────────────────┘
```

**Why this works:**

- Attackers must craft valid SIT State (schema-constrained)
- Valid SIT State must pass policy rules
- Policy rules are infinitely extensible
- Each attack that's blocked becomes a new rule
- The protocol learns from every attempt

---

## 📁 Repository Structure

```
SIT-Protocol/
├── README.md                 # You are here
├── WHITEPAPER.md             # Technical deep-dive
├── SECURITY.md               # Threat model
├── LICENSE                   # MIT (schema) + Commercial (engine)
│
├── schema/
│   ├── sit-state-v1.json     # SIT State JSON Schema
│   └── sit-policy-v1.json    # Policy DSL JSON Schema
│
├── validators/
│   ├── validate_sit.py       # Python validator
│   └── validate_sit.js       # Node.js validator (coming soon)
│
├── examples/
│   ├── example-01-read-profile.json
│   ├── example-02-write-blocked.json
│   └── policies/
│       ├── default-security.json
│       └── hipaa-compliant.json
│
└── demo/
    └── (Interactive demo coming soon)
```

---

## 🤝 Relationship with SIC

**SIT** is the security application of **SIC (Semantic Infinite Context)**.

| Protocol | Purpose | Focus |
|----------|---------|-------|
| SIC | Cross-model state transfer | Continuity, identity, memory |
| SIT | Security isolation | Boundaries, policies, sanitization |

They share:
- JSON-based state serialization
- Schema validation
- Cross-model compatibility
- Infinite iteration design

**SIC enables AI cooperation. SIT ensures it's safe.**

---

## 📜 License

- **Schema files** (`schema/*`): MIT License
- **Validators** (`validators/*`): MIT License
- **Full Engine** (production-grade serializer, policy optimizer): Commercial License

For commercial licensing inquiries, contact: [Your Email]

---

## 👤 Author

**Andwar Cheng (AN♾️Node)**

*"The structure is the law; the intent is the soul."*

---

## 🌟 Star History

If SIT helps secure your AI systems, consider starring the repo.

Every star = one more organization thinking about semantic security.

---

**"Different AIs, same security standard."**
