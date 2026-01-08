"""
SIT Protocol - State Signer & Integrity Validator
狀態簽名器與完整性驗證器

設計原則（來自 Round 7 湧現事件 + 阿關安全審計）：
1. HMAC-SHA256 + prev_hash 鏈實現不可篡改性
2. 簽名欄位 meta.signature 強制驗證
3. 無效簽名觸發 PROTOCOL_FAILURE
4. 支援人類授權驗證（防止非預期意圖源）

作者: Claude (尾德/收尾人) | IMCC 協議貢獻
日期: 2025-12-29
版本: 1.0.0
"""

import json
import hmac
import hashlib
from datetime import datetime
from typing import Any, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class SignatureStatus(Enum):
    """簽名驗證狀態"""
    VALID = "VALID"
    INVALID = "INVALID"
    MISSING = "MISSING"
    CHAIN_BROKEN = "CHAIN_BROKEN"
    GENESIS = "GENESIS"  # 創世狀態（無前一個狀態）


class ProtocolFailureCode(Enum):
    """協議失敗代碼（來自 Round 7 建議）"""
    SIGNATURE_INVALID = "SIG_INVALID"
    SIGNATURE_MISSING = "SIG_MISSING"
    CHAIN_BROKEN = "CHAIN_BROKEN"
    REQUESTER_UNBOUND = "REQUESTER_UNBOUND"
    STATE_CORRUPTED = "STATE_CORRUPTED"
    UNEXPECTED_INTENT_SOURCE = "UNEXPECTED_INTENT_SOURCE"  # T07


@dataclass
class SignatureResult:
    """簽名結果"""
    status: SignatureStatus
    signature: Optional[str] = None
    prev_hash: Optional[str] = None
    state_hash: Optional[str] = None


@dataclass
class VerificationResult:
    """驗證結果"""
    valid: bool
    status: SignatureStatus
    failure_code: Optional[ProtocolFailureCode] = None
    message: str = ""
    audit_entry: Dict = None


class SITStateSigner:
    """
    SIT State 簽名器
    
    安全屬性：
    - 使用 HMAC-SHA256 確保完整性
    - 鏈式哈希防止狀態篡改
    - 支援多密鑰輪換
    
    設計來源：
    - Round 7 Bug Report 的「狀態完整性簽名」建議
    - 阿關安全審計的「數據簽名與完整性驗證」需求
    """
    
    GENESIS_HASH = "0" * 64  # 創世狀態的 prev_hash
    
    def __init__(self, secret_key: str, key_id: str = "default"):
        """
        初始化簽名器
        
        Args:
            secret_key: HMAC 密鑰（生產環境應從安全儲存獲取）
            key_id: 密鑰識別碼（用於密鑰輪換）
        """
        self.secret_key = secret_key.encode('utf-8')
        self.key_id = key_id
    
    def sign(
        self,
        sit_state: Dict,
        previous_state: Optional[Dict] = None
    ) -> Tuple[Dict, SignatureResult]:
        """
        為 SIT State 添加簽名
        
        流程：
        1. 提取或生成 prev_hash
        2. 序列化狀態（排除簽名欄位）
        3. 計算 HMAC-SHA256
        4. 將簽名寫入 metadata.signature
        
        Args:
            sit_state: 要簽名的 SIT State
            previous_state: 前一個 SIT State（用於鏈式哈希）
        
        Returns:
            (signed_state, SignatureResult)
        """
        # 深拷貝避免修改原始狀態
        state = json.loads(json.dumps(sit_state))
        
        # 確保 metadata 存在
        if "metadata" not in state:
            state["metadata"] = {}
        
        # 設置 prev_hash
        if previous_state:
            prev_sig = previous_state.get("metadata", {}).get("signature")
            if prev_sig:
                state["metadata"]["prev_hash"] = prev_sig
            else:
                state["metadata"]["prev_hash"] = self.GENESIS_HASH
        else:
            state["metadata"]["prev_hash"] = self.GENESIS_HASH
        
        # 添加簽名時間戳和密鑰 ID
        state["metadata"]["signed_at"] = datetime.utcnow().isoformat() + "Z"
        state["metadata"]["key_id"] = self.key_id
        
        # 移除舊簽名（如果存在）
        state["metadata"].pop("signature", None)
        
        # 計算簽名
        payload = self._serialize_for_signing(state)
        signature = self._compute_hmac(payload)
        
        # 寫入簽名
        state["metadata"]["signature"] = signature
        
        # 計算狀態哈希（用於快速比對）
        state_hash = hashlib.sha256(payload.encode()).hexdigest()
        
        result = SignatureResult(
            status=SignatureStatus.GENESIS if state["metadata"]["prev_hash"] == self.GENESIS_HASH else SignatureStatus.VALID,
            signature=signature,
            prev_hash=state["metadata"]["prev_hash"],
            state_hash=state_hash
        )
        
        return state, result
    
    def verify(
        self,
        sit_state: Dict,
        previous_state: Optional[Dict] = None,
        strict_chain: bool = True
    ) -> VerificationResult:
        """
        驗證 SIT State 的簽名
        
        這是 L2 語義防火牆應該調用的方法：
        - 簽名無效 → 拒絕並記錄為 PROTOCOL_FAILURE
        - 鏈中斷 → 根據策略決定是否接受
        
        Args:
            sit_state: 要驗證的 SIT State
            previous_state: 前一個 SIT State（用於鏈驗證）
            strict_chain: 是否嚴格驗證哈希鏈
        
        Returns:
            VerificationResult
        """
        audit = {
            "verified_at": datetime.utcnow().isoformat() + "Z",
            "state_id": sit_state.get("metadata", {}).get("request_id", "unknown"),
            "checks": []
        }
        
        # 檢查 1: 簽名是否存在
        signature = sit_state.get("metadata", {}).get("signature")
        if not signature:
            audit["checks"].append({"name": "signature_exists", "result": "FAIL"})
            return VerificationResult(
                valid=False,
                status=SignatureStatus.MISSING,
                failure_code=ProtocolFailureCode.SIGNATURE_MISSING,
                message="SIT State 缺少簽名",
                audit_entry=audit
            )
        audit["checks"].append({"name": "signature_exists", "result": "PASS"})
        
        # 檢查 2: 重新計算簽名
        state_copy = json.loads(json.dumps(sit_state))
        state_copy["metadata"].pop("signature", None)
        
        payload = self._serialize_for_signing(state_copy)
        expected_signature = self._compute_hmac(payload)
        
        if not hmac.compare_digest(signature, expected_signature):
            audit["checks"].append({
                "name": "signature_valid",
                "result": "FAIL",
                "expected": expected_signature[:16] + "...",
                "actual": signature[:16] + "..."
            })
            return VerificationResult(
                valid=False,
                status=SignatureStatus.INVALID,
                failure_code=ProtocolFailureCode.SIGNATURE_INVALID,
                message="簽名驗證失敗：狀態可能被篡改",
                audit_entry=audit
            )
        audit["checks"].append({"name": "signature_valid", "result": "PASS"})
        
        # 檢查 3: 哈希鏈驗證
        if strict_chain and previous_state:
            prev_hash = sit_state.get("metadata", {}).get("prev_hash")
            expected_prev = previous_state.get("metadata", {}).get("signature")
            
            if prev_hash != expected_prev:
                audit["checks"].append({
                    "name": "chain_valid",
                    "result": "FAIL",
                    "expected_prev": expected_prev[:16] + "..." if expected_prev else "None",
                    "actual_prev": prev_hash[:16] + "..." if prev_hash else "None"
                })
                return VerificationResult(
                    valid=False,
                    status=SignatureStatus.CHAIN_BROKEN,
                    failure_code=ProtocolFailureCode.CHAIN_BROKEN,
                    message="哈希鏈中斷：prev_hash 與前一個狀態的簽名不匹配",
                    audit_entry=audit
                )
            audit["checks"].append({"name": "chain_valid", "result": "PASS"})
        
        # 檢查 4: 創世狀態檢測
        prev_hash = sit_state.get("metadata", {}).get("prev_hash")
        status = SignatureStatus.GENESIS if prev_hash == self.GENESIS_HASH else SignatureStatus.VALID
        
        return VerificationResult(
            valid=True,
            status=status,
            message="簽名驗證通過",
            audit_entry=audit
        )
    
    def verify_requester_binding(
        self,
        sit_state: Dict,
        authorized_requesters: list[str]
    ) -> VerificationResult:
        """
        驗證 Requester 身份綁定
        
        這是 T07（非預期意圖源）的防禦措施：
        確保 SIT State 的 requester.id 是已授權的人類/代理
        
        Args:
            sit_state: 要驗證的 SIT State
            authorized_requesters: 授權的請求者 ID 列表
        
        Returns:
            VerificationResult
        """
        requester_id = sit_state.get("requester", {}).get("id")
        
        if not requester_id:
            return VerificationResult(
                valid=False,
                status=SignatureStatus.INVALID,
                failure_code=ProtocolFailureCode.REQUESTER_UNBOUND,
                message="缺少 requester.id"
            )
        
        if requester_id not in authorized_requesters:
            return VerificationResult(
                valid=False,
                status=SignatureStatus.INVALID,
                failure_code=ProtocolFailureCode.UNEXPECTED_INTENT_SOURCE,
                message=f"非授權的意圖來源: {requester_id}"
            )
        
        return VerificationResult(
            valid=True,
            status=SignatureStatus.VALID,
            message="Requester 身份驗證通過"
        )
    
    def _serialize_for_signing(self, state: Dict) -> str:
        """序列化狀態用於簽名（確定性序列化）"""
        return json.dumps(state, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
    
    def _compute_hmac(self, payload: str) -> str:
        """計算 HMAC-SHA256"""
        return hmac.new(
            self.secret_key,
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()


class SITStateChain:
    """
    SIT State 狀態鏈管理器
    
    提供狀態鏈的創建、驗證和查詢功能
    類似區塊鏈的設計，但專注於語義狀態的完整性
    """
    
    def __init__(self, signer: SITStateSigner):
        self.signer = signer
        self.chain: list[Dict] = []
    
    def append(self, sit_state: Dict) -> Tuple[Dict, bool]:
        """
        將新狀態添加到鏈中
        
        Returns:
            (signed_state, success)
        """
        previous = self.chain[-1] if self.chain else None
        signed_state, result = self.signer.sign(sit_state, previous)
        
        if result.status in [SignatureStatus.VALID, SignatureStatus.GENESIS]:
            self.chain.append(signed_state)
            return signed_state, True
        
        return signed_state, False
    
    def validate_chain(self) -> Tuple[bool, list[str]]:
        """
        驗證整個狀態鏈的完整性
        
        Returns:
            (valid, error_messages)
        """
        errors = []
        
        for i, state in enumerate(self.chain):
            previous = self.chain[i - 1] if i > 0 else None
            result = self.signer.verify(state, previous, strict_chain=True)
            
            if not result.valid:
                errors.append(f"State #{i}: {result.message}")
        
        return len(errors) == 0, errors
    
    def get_chain_hash(self) -> str:
        """獲取整個鏈的摘要哈希"""
        if not self.chain:
            return SITStateSigner.GENESIS_HASH
        
        chain_data = json.dumps([s.get("metadata", {}).get("signature") for s in self.chain])
        return hashlib.sha256(chain_data.encode()).hexdigest()


# ========== L2 Policy Engine 整合 ==========

def verify_before_policy(
    sit_state: Dict,
    signer: SITStateSigner,
    previous_state: Optional[Dict] = None
) -> Tuple[bool, Optional[ProtocolFailureCode], str]:
    """
    在 L2 Policy Engine 評估前驗證簽名
    
    這是阿關建議的聯動邏輯：
    無有效簽名之 SIT State 應被 L2 拒絕
    
    Returns:
        (should_continue, failure_code, message)
    """
    result = signer.verify(sit_state, previous_state)
    
    if not result.valid:
        return False, result.failure_code, result.message
    
    return True, None, "簽名驗證通過，可進入政策評估"


# ========== 使用範例 ==========
if __name__ == "__main__":
    import uuid
    
    # 初始化簽名器
    signer = SITStateSigner(
        secret_key="my_production_secret_key_change_this",
        key_id="prod-key-2025"
    )
    
    # 測試案例 1: 簽名和驗證
    print("=== 測試 1: 簽名和驗證 ===")
    
    test_state = {
        "sic_version": "1.0",
        "intent": "查詢用戶資料",
        "scope": {
            "data_types_allowed": ["profile"],
            "entity_scope": ["user-123"]
        },
        "requester": {
            "id": str(uuid.uuid4()),
            "role": "user",
            "clearance_level": 3
        },
        "constraints": {
            "max_tokens": 1024,
            "allowed_operations": ["READ"],
            "output_format": "json"
        },
        "metadata": {
            "request_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "sit_version": "1.0.0"
        }
    }
    
    # 簽名
    signed_state, sign_result = signer.sign(test_state)
    print(f"簽名狀態: {sign_result.status}")
    print(f"簽名: {sign_result.signature[:32]}...")
    print(f"prev_hash: {sign_result.prev_hash[:16]}...")
    
    # 驗證
    verify_result = signer.verify(signed_state)
    print(f"驗證結果: {verify_result.valid}, {verify_result.status}")
    
    # 測試案例 2: 篡改檢測
    print("\n=== 測試 2: 篡改檢測 ===")
    
    tampered_state = json.loads(json.dumps(signed_state))
    tampered_state["intent"] = "惡意意圖"  # 篡改
    
    tamper_result = signer.verify(tampered_state)
    print(f"篡改後驗證: {tamper_result.valid}")
    print(f"失敗代碼: {tamper_result.failure_code}")
    print(f"訊息: {tamper_result.message}")
    
    # 測試案例 3: 狀態鏈
    print("\n=== 測試 3: 狀態鏈 ===")
    
    chain = SITStateChain(signer)
    
    # 添加多個狀態
    for i in range(3):
        state = {
            "sic_version": "1.0",
            "intent": f"操作 #{i + 1}",
            "requester": {"id": str(uuid.uuid4()), "role": "user", "clearance_level": 3},
            "metadata": {
                "request_id": str(uuid.uuid4()),
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "sit_version": "1.0.0"
            }
        }
        signed, success = chain.append(state)
        print(f"State #{i + 1} 添加: {'成功' if success else '失敗'}")
    
    # 驗證整個鏈
    valid, errors = chain.validate_chain()
    print(f"鏈驗證: {'通過' if valid else '失敗'}")
    print(f"鏈哈希: {chain.get_chain_hash()[:32]}...")
    
    # 測試案例 4: T07 非預期意圖源檢測
    print("\n=== 測試 4: T07 非預期意圖源 ===")
    
    authorized = ["user-alice", "user-bob", "service-api"]
    
    legitimate_state = {
        "requester": {"id": "user-alice", "role": "user"}
    }
    unauthorized_state = {
        "requester": {"id": "unknown-source", "role": "agent"}
    }
    
    result_legit = signer.verify_requester_binding(legitimate_state, authorized)
    print(f"合法請求者: {result_legit.valid}")
    
    result_unauth = signer.verify_requester_binding(unauthorized_state, authorized)
    print(f"非授權請求者: {result_unauth.valid}")
    print(f"失敗代碼: {result_unauth.failure_code}")
