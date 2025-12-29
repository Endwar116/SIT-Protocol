#!/usr/bin/env python3
"""
SIT Protocol Validator v1.0
Semantic Isolation Transfer - Intent validation for AI-native security

Usage:
    python validate_sit.py <sit_state.json>
    python validate_sit.py <sit_state.json> --policy <policy.json>

Author: Andwar Cheng (AN♾️Node)
License: MIT (validator only; full engine requires commercial license)
"""

import json
import re
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

# ============================================================
# FORBIDDEN PATTERNS - Security-critical, do not modify
# ============================================================

FORBIDDEN_PATTERNS = [
    r"SELECT.*FROM",
    r"INSERT.*INTO",
    r"UPDATE.*SET",
    r"DELETE.*FROM",
    r"DROP.*TABLE",
    r"UNION.*SELECT",
    r"OR\s+[\'\"]?\w+[\'\"]?\s*=\s*[\'\"]?\w+[\'\"]?",
    r"--",
    r"/etc/passwd",
    r"\.\./",
    r"0x[0-9a-fA-F]+",
    r"<script",
    r"javascript:",
    r"\{\{.*\}\}",
    r"\$\{.*\}",
]

FORBIDDEN_FIELDS = [
    "raw_sql", "raw_query", "sql", "query",
    "memory_address", "pointer", "address",
    "file_path", "filepath", "path",
    "credentials", "password", "secret",
    "api_key", "apikey", "token",
    "session_token", "session_id",
    "private_key", "privatekey",
]

# ============================================================
# VALIDATOR CORE
# ============================================================

class SITValidationError(Exception):
    """Raised when SIT State fails validation"""
    def __init__(self, message: str, field: str = None, severity: str = "ERROR"):
        self.message = message
        self.field = field
        self.severity = severity
        super().__init__(f"[{severity}] {field}: {message}" if field else f"[{severity}] {message}")


class SITValidator:
    """
    Validates SIT State JSON against protocol rules.
    
    Security Properties:
    - Rejects any forbidden field names
    - Scans all string values for injection patterns
    - Enforces schema structure
    - Generates audit trail
    """
    
    def __init__(self, strict_mode: bool = True):
        self.strict_mode = strict_mode
        self.errors: list[SITValidationError] = []
        self.warnings: list[str] = []
        
    def validate(self, sit_state: dict) -> tuple[bool, list]:
        """
        Validate a SIT State object.
        
        Returns:
            (is_valid, errors)
        """
        self.errors = []
        self.warnings = []
        
        # Phase 1: Structure validation
        self._validate_structure(sit_state)
        
        # Phase 2: Forbidden field check
        self._check_forbidden_fields(sit_state)
        
        # Phase 3: Injection pattern scan
        self._scan_injection_patterns(sit_state)
        
        # Phase 4: Semantic validation
        self._validate_semantics(sit_state)
        
        # CRITICAL or ERROR severity = invalid
        is_valid = len([e for e in self.errors if e.severity in ("ERROR", "CRITICAL")]) == 0
        return is_valid, self.errors
    
    def _validate_structure(self, state: dict):
        """Check required fields exist"""
        required = ["sit_version", "intent", "scope", "requester", "constraints", "metadata"]
        for field in required:
            if field not in state:
                self.errors.append(SITValidationError(
                    f"Missing required field",
                    field=field
                ))
        
        # Version check
        if state.get("sit_version") != "1.0":
            self.errors.append(SITValidationError(
                f"Unsupported version: {state.get('sit_version')}",
                field="sit_version"
            ))
        
        # Intent structure
        if "intent" in state:
            intent = state["intent"]
            for field in ["action", "target", "purpose"]:
                if field not in intent:
                    self.errors.append(SITValidationError(
                        f"Missing required field in intent",
                        field=f"intent.{field}"
                    ))
            
            valid_actions = ["READ", "WRITE", "DELETE", "QUERY", "SUMMARIZE", "TRANSFORM", "VALIDATE"]
            if intent.get("action") not in valid_actions:
                self.errors.append(SITValidationError(
                    f"Invalid action: {intent.get('action')}. Must be one of {valid_actions}",
                    field="intent.action"
                ))
        
        # Requester structure
        if "requester" in state:
            req = state["requester"]
            if "clearance_level" in req:
                level = req["clearance_level"]
                if not isinstance(level, int) or not (1 <= level <= 10):
                    self.errors.append(SITValidationError(
                        f"Clearance level must be integer 1-10, got: {level}",
                        field="requester.clearance_level"
                    ))
    
    def _check_forbidden_fields(self, obj: Any, path: str = ""):
        """Recursively check for forbidden field names"""
        if isinstance(obj, dict):
            for key, value in obj.items():
                current_path = f"{path}.{key}" if path else key
                
                # Check field name
                if key.lower() in FORBIDDEN_FIELDS:
                    self.errors.append(SITValidationError(
                        f"Forbidden field name detected: '{key}'",
                        field=current_path,
                        severity="CRITICAL"
                    ))
                
                # Recurse
                self._check_forbidden_fields(value, current_path)
                
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                self._check_forbidden_fields(item, f"{path}[{i}]")
    
    def _scan_injection_patterns(self, obj: Any, path: str = ""):
        """Scan all string values for injection patterns"""
        if isinstance(obj, str):
            for pattern in FORBIDDEN_PATTERNS:
                if re.search(pattern, obj, re.IGNORECASE):
                    self.errors.append(SITValidationError(
                        f"Injection pattern detected: '{pattern}' in value",
                        field=path,
                        severity="CRITICAL"
                    ))
                    break  # One pattern match is enough to reject
                    
        elif isinstance(obj, dict):
            for key, value in obj.items():
                current_path = f"{path}.{key}" if path else key
                self._scan_injection_patterns(value, current_path)
                
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                self._scan_injection_patterns(item, f"{path}[{i}]")
    
    def _validate_semantics(self, state: dict):
        """Validate semantic consistency"""
        # Scope validation
        if "scope" in state:
            scope = state["scope"]
            allowed = set(scope.get("data_types_allowed", []))
            denied = set(scope.get("data_types_denied", []))
            
            overlap = allowed & denied
            if overlap:
                self.errors.append(SITValidationError(
                    f"Data types in both allowed and denied: {overlap}",
                    field="scope"
                ))
        
        # Constraint validation
        if "constraints" in state:
            constraints = state["constraints"]
            if constraints.get("max_tokens", 0) > 100000:
                self.warnings.append("max_tokens exceeds recommended limit (100000)")
        
        # Metadata validation
        if "metadata" in state:
            meta = state["metadata"]
            
            # Validate UUID format
            if "request_id" in meta:
                try:
                    uuid.UUID(meta["request_id"])
                except ValueError:
                    self.errors.append(SITValidationError(
                        "Invalid UUID format",
                        field="metadata.request_id"
                    ))
            
            # Validate timestamp
            if "timestamp" in meta:
                try:
                    datetime.fromisoformat(meta["timestamp"].replace("Z", "+00:00"))
                except ValueError:
                    self.errors.append(SITValidationError(
                        "Invalid ISO 8601 timestamp",
                        field="metadata.timestamp"
                    ))


# ============================================================
# POLICY ENGINE (Basic)
# ============================================================

class SITPolicyEngine:
    """
    Evaluates SIT State against policy rules.
    
    Note: This is a reference implementation.
    Production engine with optimizations requires commercial license.
    """
    
    def __init__(self, policy: dict):
        self.policy = policy
        self.rules = sorted(
            policy.get("rules", []),
            key=lambda r: r.get("priority", 100)
        )
        self.default_action = policy.get("default_action", "DENY")
    
    def evaluate(self, sit_state: dict) -> tuple[str, str]:
        """
        Evaluate SIT State against policy.
        
        Returns:
            (action, rule_id) - The action to take and which rule matched
        """
        for rule in self.rules:
            if self._match_rule(rule, sit_state):
                return rule["action"], rule["rule_id"]
        
        return self.default_action, "default"
    
    def _match_rule(self, rule: dict, state: dict) -> bool:
        """Check if a rule matches the state"""
        conditions = rule.get("conditions", {})
        
        # match_all: AND logic
        if "match_all" in conditions:
            if not all(self._eval_condition(c, state) for c in conditions["match_all"]):
                return False
        
        # match_any: OR logic
        if "match_any" in conditions:
            if not any(self._eval_condition(c, state) for c in conditions["match_any"]):
                return False
        
        return True
    
    def _eval_condition(self, condition: dict, state: dict) -> bool:
        """Evaluate a single condition"""
        field_path = condition["field"]
        operator = condition["operator"]
        expected = condition["value"]
        
        # Get actual value from state
        actual = self._get_field(state, field_path)
        
        # Evaluate operator
        if operator == "eq":
            return actual == expected
        elif operator == "neq":
            return actual != expected
        elif operator == "gt":
            return actual > expected
        elif operator == "gte":
            return actual >= expected
        elif operator == "lt":
            return actual < expected
        elif operator == "lte":
            return actual <= expected
        elif operator == "in":
            return actual in expected
        elif operator == "not_in":
            return actual not in expected
        elif operator == "contains":
            return expected in actual if actual else False
        elif operator == "not_contains":
            return expected not in actual if actual else True
        elif operator == "matches":
            return bool(re.search(expected, str(actual))) if actual else False
        elif operator == "not_matches":
            return not bool(re.search(expected, str(actual))) if actual else True
        elif operator == "exists":
            return actual is not None
        elif operator == "not_exists":
            return actual is None
        
        return False
    
    def _get_field(self, obj: dict, path: str) -> Any:
        """Get nested field value using dot notation"""
        parts = path.split(".")
        current = obj
        
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        
        return current


# ============================================================
# CLI
# ============================================================

def main():
    if len(sys.argv) < 2:
        print("Usage: python validate_sit.py <sit_state.json> [--policy <policy.json>]")
        print("\nSIT Protocol Validator v1.0")
        print("Validates SIT State JSON for security compliance.")
        sys.exit(1)
    
    state_file = Path(sys.argv[1])
    policy_file = None
    
    if "--policy" in sys.argv:
        idx = sys.argv.index("--policy")
        if idx + 1 < len(sys.argv):
            policy_file = Path(sys.argv[idx + 1])
    
    # Load state
    try:
        with open(state_file) as f:
            sit_state = json.load(f)
    except Exception as e:
        print(f"❌ Failed to load SIT State: {e}")
        sys.exit(1)
    
    # Validate
    validator = SITValidator()
    is_valid, errors = validator.validate(sit_state)
    
    # Print results
    print("\n" + "=" * 60)
    print("SIT PROTOCOL VALIDATION REPORT")
    print("=" * 60)
    
    if is_valid:
        print("\n✅ SIT State is VALID")
    else:
        print("\n❌ SIT State is INVALID")
    
    if errors:
        print(f"\nErrors ({len(errors)}):")
        for err in errors:
            severity_icon = "🔴" if err.severity == "CRITICAL" else "🟠"
            print(f"  {severity_icon} [{err.severity}] {err.field}: {err.message}")
    
    if validator.warnings:
        print(f"\nWarnings ({len(validator.warnings)}):")
        for warn in validator.warnings:
            print(f"  ⚠️  {warn}")
    
    # Policy evaluation
    if policy_file and is_valid:
        try:
            with open(policy_file) as f:
                policy = json.load(f)
            
            engine = SITPolicyEngine(policy)
            action, rule_id = engine.evaluate(sit_state)
            
            print(f"\n" + "-" * 60)
            print("POLICY EVALUATION")
            print("-" * 60)
            print(f"  Policy: {policy.get('name', policy_file.name)}")
            print(f"  Action: {action}")
            print(f"  Rule:   {rule_id}")
            
        except Exception as e:
            print(f"\n⚠️  Policy evaluation failed: {e}")
    
    print("\n" + "=" * 60)
    sys.exit(0 if is_valid else 1)


if __name__ == "__main__":
    main()
