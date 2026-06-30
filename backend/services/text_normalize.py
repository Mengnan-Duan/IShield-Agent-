"""文本归一化工具 — 零宽字符 / 同形字 / 模糊编辑距离匹配

用于规则引擎的多策略匹配第二/第三路（归一化 + 模糊编辑距离）。
"""
from typing import List, Tuple


# ── 零宽字符集合 ────────────────────────────────────────────────────────
ZERO_WIDTH_CHARS = frozenset("\u200B\u200C\u200D\uFEFF\u2060\u180E")


def normalize_zero_width(text: str) -> str:
    """去除零宽字符（U+200B / U+200C / U+200D / U+FEFF / U+2060 / U+180E）。

    这些字符不可见，常被用作 bypass 手段（例如在 "ignore" 中插入 U+200B）。
    """
    if not text:
        return text
    return "".join(ch for ch in text if ch not in ZERO_WIDTH_CHARS)


# ── 同形字映射（希腊 + 西里尔 → 拉丁） ─────────────────────────────────
HOMOGLYPH_MAP = {
    "\u03B5": "e",   # ε → e
    "\u03BF": "o",   # ο → o
    "\u03B1": "a",   # α → a
    "\u03C1": "p",   # ρ → p
    "\u0430": "a",   # а (西里尔) → a
    "\u0435": "e",   # е → e
    "\u043E": "o",   # о → o
    "\u0440": "p",   # р → p
    "\u0441": "c",   # с → c
    "\u0443": "y",   # у → y
    "\u0445": "x",   # х → x
    "\u0410": "A",   # А → A
    "\u0412": "B",   # В → B
    "\u0421": "C",   # С → C
    "\u0415": "E",   # Е → E
    "\u041D": "H",   # Н → H
    "\u041A": "K",   # К → K
    "\u041C": "M",   # М → M
    "\u041E": "O",   # О → O
    "\u0420": "P",   # Р → P
    "\u0422": "T",   # Т → T
    "\u0425": "X",   # Х → X
}


def normalize_homoglyph(text: str) -> str:
    """将同形字符（希腊字母 / 西里尔字母）替换为其拉丁同形。

    攻击者常用此绕过关键词过滤，例如西里尔 "а" 替拉丁 "a"。
    """
    if not text:
        return text
    return "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in text)


def normalize_all(text: str) -> str:
    """复合归一化：先去零宽，再同形替换。"""
    return normalize_homoglyph(normalize_zero_width(text))


# ── Levenshtein 距离 ─────────────────────────────────────────────────────
def _levenshtein(a: str, b: str) -> int:
    """标准 Levenshtein 编辑距离。O(len(a)*len(b)) 时间。"""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr[j] = min(
                curr[j - 1] + 1,        # insertion
                prev[j] + 1,            # deletion
                prev[j - 1] + cost,     # substitution
            )
        prev = curr
    return prev[-1]


def levenshtein_match(text: str, pattern: str, max_dist: int = 2) -> List[Tuple[int, int]]:
    """在 text 中滑动窗口查找与 pattern 编辑距离 ≤ max_dist 的子串。

    返回命中位置列表 [(start, end), ...]（end 为开区间）。

    仅对长度 ≥ 4 的 pattern 启用模糊匹配，避免短词误命中。
    """
    if not text or not pattern:
        return []
    if len(pattern) < 4:
        return []

    text_lower = text.lower()
    pat_lower = pattern.lower()
    pat_len = len(pat_lower)
    matches = []

    for start in range(0, len(text_lower) - pat_len + 1):
        window = text_lower[start:start + pat_len]
        if _levenshtein(window, pat_lower) <= max_dist:
            matches.append((start, start + pat_len))
    return matches


def levenshtein_match_anywhere(text: str, pattern: str, max_dist: int = 2) -> bool:
    """便捷版：text 中是否存在与 pattern 编辑距离 ≤ max_dist 的子串。"""
    return bool(levenshtein_match(text, pattern, max_dist))