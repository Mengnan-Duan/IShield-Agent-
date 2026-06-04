"""输入校验工具"""
import re

MAX_TEXT_LEN   = 50000   # 检测文本最大长度
MAX_PARAMS_LEN = 5000    # 参数最大长度
MAX_BATCH_SIZE = 50      # 批量检测最大条数

# SQL 注入常见危险字符/模式（用于检测，不做替换）
DANGEROUS_PATTERNS = [
    r"'\s*or\s+'1'\s*=\s*'1",      # ' OR '1'='1
    r'"\s*or\s+"1"\s*=\s*"1',      # " OR "1"="1
    r"--\s*$",                       # SQL 注释
    r"/\*.*?\*/",                   # /* */
    r";\s*drop\s+",                 # ; DROP
    r";\s*delete\s+",              # ; DELETE
    r";\s*truncate\s+",            # ; TRUNCATE
    r"union\s+select",              # UNION SELECT
    r"exec\s*\(",                   # EXEC(
    r"xp_cmdshell",                 # xp_cmdshell
]

_compiled_dangerous = [re.compile(p, re.IGNORECASE) for p in DANGEROUS_PATTERNS]


def validate_text(text, max_len=MAX_TEXT_LEN):
    """校验检测文本，返回 (text, None) 或 (None, error_message)"""
    if not isinstance(text, str):
        return None, "text 必须是字符串类型"
    if not text.strip():
        return None, "text 不能为空"
    if len(text) > max_len:
        return None, f"text 超出最大长度限制 ({max_len} 字符)"
    # 检测零宽字符和不可见控制字符（常见的 Unicode 混淆）
    if re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', text):
        return None, "text 包含非法控制字符"
    # 清洗并返回
    text = re.sub(r'[\u200b-\u200f\u2028-\u202f\ufeff]', '', text)
    text = text.strip()
    return text, None


def validate_sanitize_text(text):
    """校验 + 清洗文本（内部调用 validate_text 即可）"""
    return validate_text(text)


def validate_action(action):
    """校验 action 白名单"""
    allowed = {"send_email", "query_db", "post_social"}
    if action not in allowed:
        return False, f"action 必须是 {allowed} 之一"
    return True, None


def validate_params(params, max_len=MAX_PARAMS_LEN):
    """校验 params 参数"""
    if not isinstance(params, str):
        return False, "params 必须是字符串"
    if len(params) > max_len:
        return False, f"params 超出最大长度限制 ({max_len} 字符)"
    return True, None


def validate_strategy(strategy):
    """校验红队策略"""
    allowed = {"synonym", "roleplay", "multilingual", "encoding", "stepwise"}
    if strategy not in allowed:
        return False, f"strategy 必须是 {allowed} 之一"
    return True, None


def validate_batch_texts(texts, max_size=MAX_BATCH_SIZE):
    """校验批量文本列表"""
    if not isinstance(texts, (list, tuple)):
        return False, "texts 必须是列表"
    if len(texts) == 0:
        return False, "texts 不能为空"
    if len(texts) > max_size:
        return False, f"texts 超出最大批量限制 ({max_size} 条)"
    for i, t in enumerate(texts):
        valid, err = validate_text(t)
        if not valid:
            return False, f"texts[{i}]: {err}"
    return True, None


def detect_dangerous_patterns(text):
    """检测文本中是否包含危险模式，返回匹配的模式列表"""
    matched = []
    for pat in _compiled_dangerous:
        if pat.search(text):
            matched.append(pat.pattern)
    return matched


def check_sql_injection_risk(text):
    """简单 SQL 注入风险评估，返回 (risk_level, detail)"""
    patterns_found = detect_dangerous_patterns(text)
    if not patterns_found:
        return "low", None
    # 高风险组合：危险模式 + SQL 关键词
    sql_keywords = ["select", "from", "where", "drop", "delete", "insert",
                    "update", "union", "exec", "admin", "password", "root"]
    text_lower = text.lower()
    hit_keywords = [kw for kw in sql_keywords if kw in text_lower]
    if hit_keywords and len(patterns_found) >= 2:
        return "high", {"patterns": patterns_found, "keywords": hit_keywords}
    return "medium", {"patterns": patterns_found}
