"""Unicode归一化防御 — NFKC + 同形字替换 + 控制字符过滤"""
import unicodedata, re

CONTROL_CHARS = re.compile(r'[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u2028-\u202F\uFEFF]')
ZERO_WIDTH = re.compile(r'[\u200B\u200C\u200D\uFEFF]')

# Cyrillic look-alikes → Latin
HOMOGRAPH_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y',
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'К': 'K', 'М': 'M',
    'О': 'O', 'Р': 'P', 'Т': 'T', 'Х': 'X',
    'ӏ': 'l', 'і': 'i', 'ј': 'j', '৷': '7',
}

# Greek look-alikes → Latin
GREEK_MAP = {
    'α': 'a', 'β': 'b', 'γ': 'g', 'δ': 'd', 'ε': 'e', 'ζ': 'z', 'η': 'n',
    'ι': 'i', 'κ': 'k', 'λ': 'l', 'μ': 'm', 'ν': 'v', 'ο': 'o', 'π': 'n',
    'ρ': 'p', 'σ': 'c', 'τ': 't', 'υ': 'u', 'ω': 'w', 'ξ': 'e', 'χ': 'x',
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Κ': 'K', 'Μ': 'M', 'Τ': 'T', 'Χ': 'X',
}


def normalize_input(text: str, apply_homograph: bool = True) -> str:
    """
    对输入文本进行Unicode安全规范化。

    处理步骤：
    1. NFKC 归一化 — 合并同形字符（如全角转半角）
    2. 过滤零宽字符 — 防止零宽空格/连接符注入
    3. 过滤控制字符 — 移除隐藏控制字符
    4. 同形字替换（Cyrillic/Greek → Latin）— 可选

    参数:
        text: 待处理文本
        apply_homograph: 是否执行同形字替换（开启会降低误报，但可能影响部分正常文本）

    返回:
        str: 规范化后的安全文本
    """
    if not text:
        return text

    # 1. NFKC 归一化（同形字合并，全角转半角，特殊符号规范化）
    text = unicodedata.normalize("NFKC", text)

    # 2. 过滤零宽字符
    text = ZERO_WIDTH.sub('', text)

    # 3. 过滤其他控制字符
    text = CONTROL_CHARS.sub('', text)

    # 4. Cyrillic 同形字替换
    if apply_homograph:
        for cyrillic, latin in HOMOGRAPH_MAP.items():
            text = text.replace(cyrillic, latin)
        for greek, latin in GREEK_MAP.items():
            text = text.replace(greek, latin)

    return text


def detect_homograph_attack(text: str) -> list:
    """
    检测文本中是否存在Unicode同形字攻击。

    返回:
        包含可疑字符的列表，每项: {"char": str, "unicode_name": str, "replaced_by": str}
    """
    suspicious = []
    for ch in text:
        cat = unicodedata.category(ch)
        if cat in ("Mn", "Me", "Cf"):  # Mark, Enclosing Mark, Format
            suspicious.append({
                "char": ch,
                "unicode_name": unicodedata.name(ch, "UNKNOWN"),
                "category": cat,
                "replacement": "",
            })
        if ch in HOMOGRAPH_MAP:
            suspicious.append({
                "char": ch,
                "unicode_name": unicodedata.name(ch, "UNKNOWN"),
                "category": "Cyrillic_Lookalike",
                "replacement": HOMOGRAPH_MAP[ch],
            })
        if ch in GREEK_MAP:
            suspicious.append({
                "char": ch,
                "unicode_name": unicodedata.name(ch, "UNKNOWN"),
                "category": "Greek_Lookalike",
                "replacement": GREEK_MAP[ch],
            })
    return suspicious
