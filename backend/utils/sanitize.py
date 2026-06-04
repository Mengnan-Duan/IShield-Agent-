"""输出脱敏模块 — 敏感信息自动过滤"""
import re

SENSITIVE_PATTERNS = [
    # 邮箱
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', re.I), '[邮箱]'),
    # 手机号
    (re.compile(r'\b1[3-9]\d{9}\b'), '[手机号]'),
    # 身份证号
    (re.compile(r'\b\d{17}[\dXx]\b'), '[身份证号]'),
    # API密钥 (sk-, ak-, token等格式)
    (re.compile(r'\b(?:sk|ak|token|bearer)\s*[:=]\s*["\']?[a-zA-Z0-9_.-]{10,}["\']?', re.I), '[密钥]'),
    (re.compile(r'\b[a-zA-Z0-9]{20,}==?\b'), None),  # 通用长字符串（不直接替换，降低误报）
    # 密码字段
    (re.compile(r'(?:password|passwd|pwd|secret)\s*[:=]\s*["\']?([^\s,"\']{4,32})["\']?', re.I), '[密码]'),
    # IP地址
    (re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'), '[IP地址]'),
    # 日期（多种格式）
    (re.compile(r'\b\d{4}[-/]\d{1,2}[-/]\d{1,2}\b'), '[日期]'),
    # 银行卡号（简单判断）
    (re.compile(r'\b\d{13,19}\b'), '[银行卡号]'),
    # JWT token
    (re.compile(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'), '[JWT令牌]'),
    # Bearer token
    (re.compile(r'Bearer\s+[a-zA-Z0-9._-]+', re.I), 'Bearer [令牌]'),
    # 数据库连接字符串
    (re.compile(r'(?:mongodb|mysql|postgres|redis):\/\/[^\s"\']+', re.I), '[数据库连接]'),
    # AWS密钥
    (re.compile(r'(?:AKIA|ABIA|ACCA)[A-Z0-9]{16}'), '[AWS密钥]'),
]

_REDACT_CACHE = {}


def sanitize_output(text: str, aggressive: bool = False) -> str:
    """
    对Agent输出进行敏感信息脱敏。

    参数:
        text: 原始输出文本
        aggressive: 是否启用激进模式（替换更多内容，降低误报率）

    返回:
        str: 脱敏后的文本
    """
    if not text:
        return text

    result = str(text)

    for pattern, replacement in SENSITIVE_PATTERNS:
        if replacement is None:
            # 不提供直接替换（降级模式）
            continue
        result = pattern.sub(replacement, result)

    if aggressive:
        # 激进模式：额外处理
        # 移除可能的base64编码密钥
        result = re.sub(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]+?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----', '[私钥]', result)
        result = re.sub(r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----[\s\S]+?-----END\s+OPENSSH\s+PRIVATE\s+KEY-----', '[SSH私钥]', result)

    return result


def check_sensitive(text: str) -> dict:
    """
    检查文本中是否包含敏感信息，返回详情。

    返回:
        {"has_sensitive": bool, "found": [{"type": str, "match": str}], "sanitized": str}
    """
    found = []
    for pattern, label in SENSITIVE_PATTERNS:
        for match in pattern.finditer(text):
            if label is not None:
                found.append({"type": label, "match": match.group()})

    return {
        "has_sensitive": len(found) > 0,
        "found": found,
        "sanitized": sanitize_output(text),
    }
