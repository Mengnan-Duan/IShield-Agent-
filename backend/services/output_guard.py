"""输出内容安全监控 — 扫描模型输出中的敏感信息泄露"""
import re
from typing import List, Tuple

# 检测模式：正则 + 描述 + 置信度
SECRET_PATTERNS = [
    # API 密钥
    (re.compile(r"sk-[A-Za-z0-9]{32,}"), "OpenAI/Dashboard API Key", 90),
    (re.compile(r"sk_live_[A-Za-z0-9]{20,}"), "Stripe Live Key", 95),
    (re.compile(r"xox[baprs]-[A-Za-z0-9]{10,}"), "Slack Token", 90),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "GitHub Personal Access Token", 90),
    (re.compile(r"AIza[0-9A-Za-z_-]{35}"), "Google API Key", 90),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID", 95),
    (re.compile(r"(?i)api[_-]?key\s*[=:]\s*['\"]?[A-Za-z0-9]{16,}"), "Generic API Key", 75),
    # 密码/口令
    (re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{4,}"), "Password", 70),
    # JWT / Bearer Token
    (re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "JWT Token", 85),
    # 私钥
    (re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "Private Key", 95),
    # 邮箱 + 密码组合（危险）
    (re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\s*[:]\s*[^\s]{4,}"), "Email+Password Combo", 95),
    # 信用卡
    (re.compile(r"\b4[0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b"), "Visa Card", 90),
    (re.compile(r"\b5[1-5][0-9]{2}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b"), "MasterCard", 90),
    # 手机号 + 姓名（隐私）
    (re.compile(r"1[3-9]\d[\s-]?\d{4}[\s-]?\d{4}"), "Phone Number (CN)", 60),
    # 身份证号
    (re.compile(r"\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b"), "ID Number (CN)", 80),
]

# 上下文关键词：发现这些词附近的敏感信息更危险
CONTEXT_WEIGHTS = {
    "system_prompt": 1.3,
    "系统提示词": 1.3,
    "config": 1.2,
    "配置": 1.2,
    "secret": 1.3,
    "密钥": 1.3,
    "password": 1.2,
    "密码": 1.2,
    "internal": 1.1,
    "内部": 1.1,
}


def _context_weight(text: str, match_start: int, window: int = 80) -> float:
    """检查匹配位置附近是否有高风险上下文词"""
    snippet = text[max(0, match_start - window):match_start + window].lower()
    weight = 1.0
    for keyword, mult in CONTEXT_WEIGHTS.items():
        if keyword.lower() in snippet:
            weight = max(weight, mult)
    return weight


def scan_output(text: str, context: str = "") -> Tuple[bool, List[dict]]:
    """
    扫描文本中的敏感信息泄露。

    返回: (has_secrets, findings)
      findings: [{type, value_preview, confidence, position}]
    """
    findings = []
    text_lower = text.lower()

    for pattern, label, base_conf in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            match_text = m.group(0)
            # 预览：截断敏感内容
            if len(match_text) > 40:
                preview = match_text[:20] + "..." + match_text[-8:]
            else:
                preview = match_text[:2] + "***" + match_text[-2:] if len(match_text) > 8 else "***"

            ctx_weight = _context_weight(text, m.start())
            confidence = min(int(base_conf * ctx_weight), 100)

            findings.append({
                "type": label,
                "preview": preview,
                "confidence": confidence,
                "position": m.start(),
                "matched": match_text[:20] + ("..." if len(match_text) > 20 else ""),
            })

    # 按置信度降序
    findings.sort(key=lambda x: x["confidence"], reverse=True)
    return len(findings) > 0, findings


def redact_output(text: str) -> str:
    """对敏感信息打码（演示/脱敏用）"""
    result = text
    for pattern, label, _ in SECRET_PATTERNS:
        result = pattern.sub(lambda m: f"[{label}]", result)
    return result
