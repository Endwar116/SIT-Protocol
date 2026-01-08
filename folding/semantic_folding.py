"""
Semantic Folding — 語義折疊
向量壓縮與語義保留

USCA 協議棧位置: L1 (Semantic Folding Layer)
類比: 資料壓縮，但壓縮的是「語義」而非「位元」

核心功能（老翔需求 - 未來必備）:
- 壓縮 1536 > 256（降維保義）
- 保留語義相似度
- 提升 routing performance
- 跨模型語義對齊

設計來源: L11 Semantic OS + USCA 規格
作者: Claude (尾德)
日期: 2025-12-29
版本: 1.0.0
"""

import math
import random
import hashlib
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class FoldingMethod(Enum):
    """折疊方法"""
    RANDOM_PROJECTION = "RANDOM_PROJECTION"  # 隨機投影
    PCA_LIKE = "PCA_LIKE"                    # 類 PCA 降維
    LOCALITY_SENSITIVE = "LSH"               # 局部敏感雜湊
    SEMANTIC_HASH = "SEMANTIC_HASH"          # 語義雜湊
    HYBRID = "HYBRID"                        # 混合方法


@dataclass
class FoldedVector:
    """折疊後的向量"""
    vector: List[float]                 # 折疊後的向量
    original_dim: int                   # 原始維度
    folded_dim: int                     # 折疊後維度
    method: FoldingMethod               # 使用的方法
    
    # 品質指標
    preservation_score: float = 0.0     # 語義保留度 0-1
    compression_ratio: float = 0.0      # 壓縮比
    
    # 元數據
    fold_key: str = ""                  # 折疊金鑰（用於反折疊）
    
    def to_dict(self) -> Dict:
        return {
            "vector": self.vector,
            "original_dim": self.original_dim,
            "folded_dim": self.folded_dim,
            "method": self.method.value,
            "preservation_score": self.preservation_score,
            "compression_ratio": self.compression_ratio,
            "fold_key": self.fold_key
        }


@dataclass
class SemanticManifold:
    """
    語義流形
    
    表示一組語義相關的向量在折疊後的結構
    用於保持語義拓撲
    """
    center: List[float]                 # 流形中心
    radius: float                       # 流形半徑
    density: float                      # 語義密度
    concepts: List[str]                 # 涵蓋的概念


class SemanticFolder:
    """
    語義折疊器
    
    這是 SIC 協議的 L1 核心元件：
    1. 將高維 embedding 折疊為低維表示
    2. 保留語義相似度關係
    3. 支援跨模型語義對齊
    
    技術價值：「SICJS 的核心模組之一」— 老翔
    """
    
    # 預設配置
    DEFAULT_TARGET_DIM = 256
    S_STAR = 2.76  # 語義密度常數（來自安安的 SIP 協議）
    
    def __init__(
        self,
        target_dim: int = DEFAULT_TARGET_DIM,
        method: FoldingMethod = FoldingMethod.HYBRID,
        seed: int = 42
    ):
        """
        初始化折疊器
        
        Args:
            target_dim: 目標維度
            method: 折疊方法
            seed: 隨機種子（確保可重現）
        """
        self.target_dim = target_dim
        self.method = method
        self.seed = seed
        self.random = random.Random(seed)
        
        # 投影矩陣快取
        self._projection_cache: Dict[int, List[List[float]]] = {}
    
    def fold(
        self,
        vector: List[float],
        preserve_topology: bool = True
    ) -> FoldedVector:
        """
        折疊向量
        
        Args:
            vector: 原始高維向量
            preserve_topology: 是否保留拓撲結構
        
        Returns:
            FoldedVector
        """
        original_dim = len(vector)
        
        if original_dim <= self.target_dim:
            # 不需要折疊
            return FoldedVector(
                vector=vector,
                original_dim=original_dim,
                folded_dim=original_dim,
                method=self.method,
                preservation_score=1.0,
                compression_ratio=1.0
            )
        
        # 根據方法選擇折疊策略
        if self.method == FoldingMethod.RANDOM_PROJECTION:
            folded = self._random_projection(vector)
        elif self.method == FoldingMethod.PCA_LIKE:
            folded = self._pca_like_fold(vector)
        elif self.method == FoldingMethod.LOCALITY_SENSITIVE:
            folded = self._lsh_fold(vector)
        elif self.method == FoldingMethod.SEMANTIC_HASH:
            folded = self._semantic_hash_fold(vector)
        else:  # HYBRID
            folded = self._hybrid_fold(vector)
        
        # 正規化
        folded = self._normalize(folded)
        
        # 計算保留度
        preservation = self._estimate_preservation(vector, folded)
        
        # 生成折疊金鑰
        fold_key = self._generate_fold_key(original_dim, self.target_dim)
        
        return FoldedVector(
            vector=folded,
            original_dim=original_dim,
            folded_dim=len(folded),
            method=self.method,
            preservation_score=preservation,
            compression_ratio=original_dim / len(folded),
            fold_key=fold_key
        )
    
    def unfold(
        self,
        folded: FoldedVector,
        hint_vector: Optional[List[float]] = None
    ) -> List[float]:
        """
        反折疊（近似恢復）
        
        注意：這是有損操作，只能近似恢復
        
        Args:
            folded: 折疊後的向量
            hint_vector: 提示向量（可提高恢復品質）
        
        Returns:
            近似恢復的高維向量
        """
        if folded.original_dim == folded.folded_dim:
            return folded.vector.copy()
        
        # 使用轉置投影矩陣進行反投影
        projection = self._get_projection_matrix(folded.original_dim)
        
        # 反投影
        restored = [0.0] * folded.original_dim
        for i in range(folded.original_dim):
            for j in range(folded.folded_dim):
                restored[i] += folded.vector[j] * projection[j][i]
        
        # 如果有提示向量，進行混合
        if hint_vector and len(hint_vector) == folded.original_dim:
            alpha = 0.3  # 提示權重
            restored = [
                (1 - alpha) * r + alpha * h
                for r, h in zip(restored, hint_vector)
            ]
        
        return self._normalize(restored)
    
    def compute_similarity(
        self,
        folded1: FoldedVector,
        folded2: FoldedVector
    ) -> float:
        """
        計算折疊向量的相似度
        
        這是語義折疊的核心保證：
        折疊後的相似度應該近似原始相似度
        """
        if len(folded1.vector) != len(folded2.vector):
            return 0.0
        
        return self._cosine_similarity(folded1.vector, folded2.vector)
    
    def fold_batch(
        self,
        vectors: List[List[float]],
        preserve_topology: bool = True
    ) -> Tuple[List[FoldedVector], SemanticManifold]:
        """
        批次折疊並計算語義流形
        
        Args:
            vectors: 向量列表
            preserve_topology: 是否保留拓撲
        
        Returns:
            (折疊向量列表, 語義流形)
        """
        if not vectors:
            return [], SemanticManifold(
                center=[], radius=0.0, density=0.0, concepts=[]
            )
        
        # 折疊所有向量
        folded_list = [self.fold(v, preserve_topology) for v in vectors]
        
        # 計算流形中心
        dim = len(folded_list[0].vector)
        center = [0.0] * dim
        for fv in folded_list:
            for i, val in enumerate(fv.vector):
                center[i] += val
        center = [c / len(folded_list) for c in center]
        
        # 計算半徑（最大距離）
        max_dist = 0.0
        for fv in folded_list:
            dist = sum((a - b) ** 2 for a, b in zip(fv.vector, center)) ** 0.5
            max_dist = max(max_dist, dist)
        
        # 計算密度
        density = len(folded_list) / max(max_dist ** 2, 0.01)
        
        manifold = SemanticManifold(
            center=center,
            radius=max_dist,
            density=min(density * self.S_STAR, 10.0),  # 使用 S★ 常數
            concepts=[]
        )
        
        return folded_list, manifold
    
    def align_across_models(
        self,
        vectors_a: List[List[float]],
        vectors_b: List[List[float]],
        anchor_pairs: List[Tuple[int, int]]
    ) -> Tuple[List[FoldedVector], List[FoldedVector]]:
        """
        跨模型語義對齊
        
        使用錨點對來對齊不同模型的語義空間
        
        Args:
            vectors_a: 模型 A 的向量
            vectors_b: 模型 B 的向量
            anchor_pairs: 已知對應的索引對
        
        Returns:
            對齊後的折疊向量
        """
        # 先各自折疊
        folded_a = [self.fold(v) for v in vectors_a]
        folded_b = [self.fold(v) for v in vectors_b]
        
        if not anchor_pairs:
            return folded_a, folded_b
        
        # 計算對齊變換
        # 簡化版：計算錨點的平均偏移
        offset = [0.0] * self.target_dim
        for idx_a, idx_b in anchor_pairs:
            if idx_a < len(folded_a) and idx_b < len(folded_b):
                for i in range(self.target_dim):
                    offset[i] += folded_a[idx_a].vector[i] - folded_b[idx_b].vector[i]
        
        if anchor_pairs:
            offset = [o / len(anchor_pairs) for o in offset]
        
        # 對齊 B 到 A 的空間
        for fv in folded_b:
            fv.vector = [v + o for v, o in zip(fv.vector, offset)]
        
        return folded_a, folded_b
    
    # ========== 內部方法 ==========
    
    def _random_projection(self, vector: List[float]) -> List[float]:
        """隨機投影降維"""
        projection = self._get_projection_matrix(len(vector))
        
        result = []
        for row in projection:
            val = sum(v * p for v, p in zip(vector, row))
            result.append(val)
        
        return result
    
    def _pca_like_fold(self, vector: List[float]) -> List[float]:
        """類 PCA 折疊（簡化版）"""
        # 將向量分成塊，每塊取加權和
        original_dim = len(vector)
        chunk_size = original_dim // self.target_dim
        
        result = []
        for i in range(self.target_dim):
            start = i * chunk_size
            end = start + chunk_size if i < self.target_dim - 1 else original_dim
            
            # 加權和，中間權重更高
            chunk = vector[start:end]
            weights = [1.0 + 0.5 * math.sin(math.pi * j / len(chunk)) for j in range(len(chunk))]
            val = sum(v * w for v, w in zip(chunk, weights)) / sum(weights)
            result.append(val)
        
        return result
    
    def _lsh_fold(self, vector: List[float]) -> List[float]:
        """局部敏感雜湊折疊"""
        # 使用隨機超平面
        projection = self._get_projection_matrix(len(vector))
        
        result = []
        for row in projection:
            dot = sum(v * p for v, p in zip(vector, row))
            # 保留符號和幅度信息
            result.append(math.tanh(dot))
        
        return result
    
    def _semantic_hash_fold(self, vector: List[float]) -> List[float]:
        """語義雜湊折疊"""
        # 將向量轉為位元串，然後雜湊
        vec_str = ','.join(f"{v:.6f}" for v in vector)
        hash_bytes = hashlib.sha256(vec_str.encode()).digest()
        
        # 將雜湊轉為浮點向量
        result = []
        for i in range(self.target_dim):
            idx = i % len(hash_bytes)
            val = (hash_bytes[idx] - 128) / 128.0
            result.append(val)
        
        return result
    
    def _hybrid_fold(self, vector: List[float]) -> List[float]:
        """混合折疊（綜合多種方法）"""
        # 使用隨機投影作為基礎
        rp_result = self._random_projection(vector)
        
        # 加入 PCA-like 的塊信息
        pca_result = self._pca_like_fold(vector)
        
        # 混合
        alpha = 0.7
        result = [
            alpha * r + (1 - alpha) * p
            for r, p in zip(rp_result, pca_result)
        ]
        
        return result
    
    def _get_projection_matrix(self, original_dim: int) -> List[List[float]]:
        """取得或生成投影矩陣"""
        if original_dim in self._projection_cache:
            return self._projection_cache[original_dim]
        
        # 生成高斯隨機投影矩陣
        self.random.seed(self.seed)
        matrix = []
        for _ in range(self.target_dim):
            row = [self.random.gauss(0, 1) / math.sqrt(self.target_dim) for _ in range(original_dim)]
            matrix.append(row)
        
        self._projection_cache[original_dim] = matrix
        return matrix
    
    def _normalize(self, vector: List[float]) -> List[float]:
        """L2 正規化"""
        norm = sum(v * v for v in vector) ** 0.5
        if norm < 1e-10:
            return vector
        return [v / norm for v in vector]
    
    def _cosine_similarity(self, v1: List[float], v2: List[float]) -> float:
        """餘弦相似度"""
        dot = sum(a * b for a, b in zip(v1, v2))
        norm1 = sum(a * a for a in v1) ** 0.5
        norm2 = sum(b * b for b in v2) ** 0.5
        
        if norm1 < 1e-10 or norm2 < 1e-10:
            return 0.0
        
        return dot / (norm1 * norm2)
    
    def _estimate_preservation(self, original: List[float], folded: List[float]) -> float:
        """估算語義保留度"""
        # 使用能量保留作為指標
        original_energy = sum(v * v for v in original)
        folded_energy = sum(v * v for v in folded)
        
        if original_energy < 1e-10:
            return 1.0
        
        # 能量比例
        energy_ratio = folded_energy / original_energy
        
        # 保留度 = 能量比例的平方根（因為正規化的影響）
        return min(1.0, energy_ratio ** 0.5)
    
    def _generate_fold_key(self, original_dim: int, target_dim: int) -> str:
        """生成折疊金鑰"""
        key_data = f"{original_dim}:{target_dim}:{self.seed}:{self.method.value}"
        return hashlib.md5(key_data.encode()).hexdigest()[:16]


# ========== 測試 ==========

if __name__ == "__main__":
    print("=== 語義折疊測試 ===\n")
    
    folder = SemanticFolder(target_dim=64, method=FoldingMethod.HYBRID)
    
    # 生成測試向量（模擬 1536 維 embedding）
    random.seed(42)
    
    def generate_vector(dim: int, bias: float = 0.0) -> List[float]:
        return [random.gauss(bias, 1.0) for _ in range(dim)]
    
    # 測試 1: 基本折疊
    print("--- 測試 1: 基本折疊 ---")
    original = generate_vector(1536)
    folded = folder.fold(original)
    
    print(f"原始維度: {folded.original_dim}")
    print(f"折疊維度: {folded.folded_dim}")
    print(f"壓縮比: {folded.compression_ratio:.1f}x")
    print(f"保留度: {folded.preservation_score:.2%}")
    
    # 測試 2: 相似度保留
    print("\n--- 測試 2: 相似度保留 ---")
    
    # 生成相似向量（加上小擾動）
    similar = [v + random.gauss(0, 0.1) for v in original]
    # 生成不相似向量
    different = generate_vector(1536, bias=5.0)
    
    folded_similar = folder.fold(similar)
    folded_different = folder.fold(different)
    
    sim_original_similar = folder._cosine_similarity(original, similar)
    sim_original_different = folder._cosine_similarity(original, different)
    
    sim_folded_similar = folder.compute_similarity(folded, folded_similar)
    sim_folded_different = folder.compute_similarity(folded, folded_different)
    
    print(f"原始空間:")
    print(f"  相似向量相似度: {sim_original_similar:.3f}")
    print(f"  不相似向量相似度: {sim_original_different:.3f}")
    print(f"折疊空間:")
    print(f"  相似向量相似度: {sim_folded_similar:.3f}")
    print(f"  不相似向量相似度: {sim_folded_different:.3f}")
    
    # 測試 3: 批次折疊與語義流形
    print("\n--- 測試 3: 批次折疊與語義流形 ---")
    
    vectors = [generate_vector(1536, bias=i * 0.5) for i in range(10)]
    folded_list, manifold = folder.fold_batch(vectors)
    
    print(f"向量數量: {len(folded_list)}")
    print(f"流形半徑: {manifold.radius:.3f}")
    print(f"語義密度: {manifold.density:.3f}")
    
    # 測試 4: 反折疊
    print("\n--- 測試 4: 反折疊 ---")
    
    restored = folder.unfold(folded)
    restoration_sim = folder._cosine_similarity(original, restored)
    print(f"反折疊相似度: {restoration_sim:.3f}")
    
    print("\n✅ 語義折疊測試完成")
